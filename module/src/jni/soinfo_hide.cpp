#include "soinfo_hide.h"

#include <dlfcn.h>
#include <dobby.h>
#include <link.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "log.h"
#include "xdl.h"

namespace {

// ─── Hide list ──────────────────────────────────────────────────────────────
// Path substrings whose modules we want gone from any enumeration channel.
// "jit-cache.so" is our staged payload (see inject.cpp::stage_gadget). The
// rest are defense-in-depth covers in case frida-server style injection
// happens alongside us.
const char *const kHideTokens[] = {
    "jit-cache.so",
    "frida-agent-32.so",
    "frida-agent-64.so",
    "memfd:frida-agent",
    "memfd:frida",
    "libgadget",
    "libfrida",
    "re.frida",
};
const size_t kHideTokensCount = sizeof(kHideTokens) / sizeof(kHideTokens[0]);

// ─── dl_iterate_phdr filter ─────────────────────────────────────────────────
//
// libc's dl_iterate_phdr walks the linker's solist and invokes a user
// callback per entry. We swap the callback for a thin wrapper that drops
// hidden entries before they reach the caller.
using dl_iter_cb_t = int (*)(struct dl_phdr_info *, size_t, void *);
using dl_iter_phdr_t = int (*)(dl_iter_cb_t, void *);

dl_iter_phdr_t orig_dl_iterate_phdr = nullptr;

struct cb_ctx {
    dl_iter_cb_t inner;
    void *data;
};

int filter_cb(struct dl_phdr_info *info, size_t size, void *data) {
    auto *ctx = static_cast<cb_ctx *>(data);
    if (info != nullptr && soinfo_hide_path_matches(info->dlpi_name)) {
        return 0;
    }
    return ctx->inner(info, size, ctx->data);
}

int hooked_dl_iterate_phdr(dl_iter_cb_t cb, void *data) {
    cb_ctx ctx{cb, data};
    return orig_dl_iterate_phdr(filter_cb, &ctx);
}

void install_dl_iterate_phdr_hook() {
    void *sym = dlsym(RTLD_DEFAULT, "dl_iterate_phdr");
    if (sym == nullptr) sym = dlsym(RTLD_NEXT, "dl_iterate_phdr");
    if (sym == nullptr) {
        LOGW("[soinfo_hide] dl_iterate_phdr unresolved");
        return;
    }
    int rc = DobbyHook(
        sym, reinterpret_cast<void *>(&hooked_dl_iterate_phdr),
        reinterpret_cast<void **>(&orig_dl_iterate_phdr));
    if (rc != 0) {
        LOGW("[soinfo_hide] DobbyHook(dl_iterate_phdr) rc=%d", rc);
        return;
    }
    LOGD("[soinfo_hide] dl_iterate_phdr filter active");
}

// ─── Bionic linker private symbols ──────────────────────────────────────────
//
// Mangled per the Itanium ABI; xdl_dsym matches "name" or "name.<suffix>"
// so .cfi / .llvm.<hash> variants resolve transparently.
//
// AOSP references (Apache-2.0):
//   bionic/linker/linker.cpp        - somain, solinker, solist_get_*
//   bionic/linker/linker_soinfo.h   - soinfo struct shape (private)
//
// The soinfo struct layout is not stable across Android versions, so the
// three fields we mutate (next, size_, constructors_called_) have their
// offsets discovered at run time by pattern-matching memory.

using opaque_so_t = void;
using fn_get_realpath_t = const char *(*)(opaque_so_t *);
using fn_soinfo_unload_t = void (*)(opaque_so_t *);
using fn_solist_head_t = opaque_so_t *(*)();
using fn_pdg_t = void (*)();

struct linker_syms {
    fn_solist_head_t solist_head;
    fn_solist_head_t solist_vdso;
    fn_get_realpath_t get_realpath;
    fn_soinfo_unload_t soinfo_unload;
    fn_pdg_t pdg_unprotect;
    fn_pdg_t pdg_reprotect;
    opaque_so_t *somain;
    opaque_so_t *solinker;
    size_t *load_counter;
    size_t *unload_counter;
};

bool resolve_linker_syms(linker_syms *out) {
    *out = linker_syms{};
    const char *path = (sizeof(void *) == 8) ? "/linker64" : "/linker";
    void *h = xdl_open(path, XDL_TRY_FORCE_LOAD);
    if (h == nullptr) {
        LOGW("[soinfo_hide] xdl_open(%s) failed", path);
        return false;
    }

    out->solist_head = reinterpret_cast<fn_solist_head_t>(
        xdl_dsym(h, "__dl__Z15solist_get_headv", nullptr));
    out->solist_vdso = reinterpret_cast<fn_solist_head_t>(
        xdl_dsym(h, "__dl__Z15solist_get_vdsov", nullptr));
    out->get_realpath = reinterpret_cast<fn_get_realpath_t>(
        xdl_dsym(h, "__dl__ZNK6soinfo12get_realpathEv", nullptr));
    out->soinfo_unload = reinterpret_cast<fn_soinfo_unload_t>(
        xdl_dsym(h, "__dl__ZL13soinfo_unloadP6soinfo", nullptr));
    out->pdg_unprotect = reinterpret_cast<fn_pdg_t>(
        xdl_dsym(h, "__dl__ZN18ProtectedDataGuardC2Ev", nullptr));
    out->pdg_reprotect = reinterpret_cast<fn_pdg_t>(
        xdl_dsym(h, "__dl__ZN18ProtectedDataGuardD2Ev", nullptr));

    void *somain_var = xdl_dsym(h, "__dl__ZL6somain", nullptr);
    void *solinker_var = xdl_dsym(h, "__dl__ZL8solinker", nullptr);
    out->somain = somain_var
                      ? *static_cast<opaque_so_t **>(somain_var)
                      : nullptr;
    out->solinker = solinker_var
                        ? *static_cast<opaque_so_t **>(solinker_var)
                        : nullptr;

    out->load_counter = static_cast<size_t *>(
        xdl_dsym(h, "__dl__ZL21g_module_load_counter", nullptr));
    out->unload_counter = static_cast<size_t *>(
        xdl_dsym(h, "__dl__ZL23g_module_unload_counter", nullptr));

    xdl_close(h);

    if (out->solist_head == nullptr || out->get_realpath == nullptr ||
        out->soinfo_unload == nullptr || out->pdg_unprotect == nullptr ||
        out->pdg_reprotect == nullptr || out->somain == nullptr ||
        out->solinker == nullptr) {
        LOGW("[soinfo_hide] one or more linker symbols missing");
        return false;
    }
    return true;
}

constexpr size_t kOffNotFound = SIZE_MAX;

// Pattern-discover the offsets of the soinfo fields we need to mutate.
// Returns true iff all three were located within the 1 KiB window.
bool discover_offsets(const linker_syms &s,
                      size_t *off_next,
                      size_t *off_size,
                      size_t *off_cc) {
    *off_next = kOffNotFound;
    *off_size = kOffNotFound;
    *off_cc = kOffNotFound;

    opaque_so_t *head = s.solist_head();
    opaque_so_t *vdso = (s.solist_vdso != nullptr) ? s.solist_vdso() : nullptr;
    if (head == nullptr) return false;

    const char *solinker_realpath = s.get_realpath(s.solinker);

    constexpr size_t kScanWords = 1024 / sizeof(void *);
    constexpr size_t kStep = sizeof(void *);
    constexpr size_t kLmWords =
        (sizeof(struct link_map) + sizeof(void *) - 1) / sizeof(void *);

    for (size_t i = 0; i < kScanWords; i++) {
        const size_t off = i * kStep;

        if (*off_next == kOffNotFound) {
            // 'next' on the head soinfo points at one of the second-loaded
            // soinfos: somain, solinker, or vdso.
            opaque_so_t *cand = *reinterpret_cast<opaque_so_t **>(
                reinterpret_cast<uintptr_t>(head) + off);
            if (cand == s.somain || cand == s.solinker || cand == vdso) {
                *off_next = off;
            }
        }

        if (*off_size == kOffNotFound) {
            // 'size_' on somain holds the total LOAD-segment span: a value
            // in a plausible mapped-image range.
            size_t cand = *reinterpret_cast<size_t *>(
                reinterpret_cast<uintptr_t>(s.somain) + off);
            if (cand > 0x100u && cand < 0x100000u) {
                *off_size = off;
            }
        }

        if (*off_cc == kOffNotFound) {
            // The link_map sub-struct embedded in soinfo carries
            // l_name = realpath(); the byte right after it (rounded up to
            // pointer alignment) is the constructors_called_ flag.
            uintptr_t lm_addr = reinterpret_cast<uintptr_t>(s.solinker) + off;
            const auto *lm = reinterpret_cast<const struct link_map *>(lm_addr);
            uintptr_t cc_addr = lm_addr + kLmWords * sizeof(void *);
            const auto *cc = reinterpret_cast<const bool *>(cc_addr);
            if (lm->l_name == solinker_realpath && *cc) {
                *off_cc = off + kLmWords * sizeof(void *);
            }
        }

        if (*off_next != kOffNotFound && *off_size != kOffNotFound &&
            *off_cc != kOffNotFound) {
            return true;
        }
    }

    return false;
}

bool unlist_via_solist(const linker_syms &s,
                       size_t off_next,
                       size_t off_size,
                       size_t off_cc) {
    bool any = false;

    for (opaque_so_t *so = s.solist_head(); so != nullptr;) {
        opaque_so_t *next = *reinterpret_cast<opaque_so_t **>(
            reinterpret_cast<uintptr_t>(so) + off_next);
        const char *rp = s.get_realpath(so);

        if (rp != nullptr && soinfo_hide_path_matches(rp)) {
            LOGI("[soinfo_hide] unlisting %p (%s)", so, rp);
            s.pdg_unprotect();
            // size_=0 makes soinfo_unload's munmap path a no-op so Frida's
            // running code pages survive.
            *reinterpret_cast<size_t *>(
                reinterpret_cast<uintptr_t>(so) + off_size) = 0;
            // Skip fini_array; gadget destructors would touch state we
            // are about to remove.
            *reinterpret_cast<bool *>(
                reinterpret_cast<uintptr_t>(so) + off_cc) = false;
            s.soinfo_unload(so);
            s.pdg_reprotect();
            if (s.load_counter != nullptr) (*s.load_counter)--;
            if (s.unload_counter != nullptr) (*s.unload_counter)--;
            any = true;
        }
        so = next;
    }
    return any;
}

// ─── PHH-GSI env scrub ──────────────────────────────────────────────────────
const char *const kEnvPrefixesToScrub[] = {
    "PHH_",
};

void scrub_environment() {
    if (environ == nullptr) return;
    int dropped = 0;
    int safety_budget = 256;
    for (size_t i = 0; environ[i] != nullptr && safety_budget > 0; /* manual */) {
        const char *e = environ[i];
        bool match = false;
        for (auto pref : kEnvPrefixesToScrub) {
            size_t plen = strlen(pref);
            if (strncmp(e, pref, plen) == 0) {
                match = true;
                break;
            }
        }
        if (!match) {
            i++;
            continue;
        }
        const char *eq = strchr(e, '=');
        if (eq == nullptr) {
            i++;
            continue;
        }
        size_t name_len = static_cast<size_t>(eq - e);
        char name[64];
        if (name_len + 1 >= sizeof(name)) {
            i++;
            continue;
        }
        memcpy(name, e, name_len);
        name[name_len] = '\0';

        const char *before = environ[i];
        unsetenv(name);
        dropped++;
        safety_budget--;
        // unsetenv usually shifts the array in-place; if it didn't (failure
        // or already-removed), advance i to avoid spinning.
        if (environ[i] == before) i++;
    }
    if (dropped > 0) {
        LOGI("[soinfo_hide] scrubbed %d env entries", dropped);
    }
}

std::atomic<bool> g_installed{false};

}  // namespace

bool soinfo_hide_path_matches(const char *path) {
    if (path == nullptr) return false;
    for (size_t i = 0; i < kHideTokensCount; i++) {
        if (strstr(path, kHideTokens[i]) != nullptr) return true;
    }
    return false;
}

void install_soinfo_hide() {
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true)) return;

    LOGI("[soinfo_hide] post-load enumeration scrub starting");

    // Best-effort: try to remove our payload from the linker's private
    // solist. If anything fails (symbol resolution, offsets, or unlist)
    // we still benefit from the dl_iterate_phdr filter installed below.
    linker_syms s{};
    if (resolve_linker_syms(&s)) {
        size_t off_next = 0, off_size = 0, off_cc = 0;
        if (discover_offsets(s, &off_next, &off_size, &off_cc)) {
            LOGD("[soinfo_hide] offsets next=%zu size=%zu cc=%zu",
                 off_next, off_size, off_cc);
            unlist_via_solist(s, off_next, off_size, off_cc);
        } else {
            LOGW("[soinfo_hide] soinfo offset discovery failed");
        }
    }

    install_dl_iterate_phdr_hook();
    scrub_environment();

    LOGI("[soinfo_hide] post-load scrub complete");
}
