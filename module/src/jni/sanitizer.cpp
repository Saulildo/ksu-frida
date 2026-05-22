#include "sanitizer.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

#include <dobby.h>

#include "log.h"

// memfd_create() is exposed in NDK headers only from API 30+, but the
// underlying syscall is available since Linux 3.17 (Android 5.0+ / API 21).
// Provide robust fallbacks that work across the four NDK target ABIs.
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef SYS_memfd_create
#if defined(__aarch64__)
#define SYS_memfd_create 279
#elif defined(__arm__)
#define SYS_memfd_create 385
#elif defined(__x86_64__)
#define SYS_memfd_create 319
#elif defined(__i386__)
#define SYS_memfd_create 356
#endif
#endif

namespace {

// ─── Thread-name sanitizer ──────────────────────────────────────────────────

// Pool of thread names that show up in vanilla AOSP processes; we map
// suspicious names to one of these so the result blends with the noise of
// /proc/<tid>/comm without picking a single distinctive replacement.
const char *const kGenericThreadNames[] = {
    "Binder:0_1",
    "Profile Saver",
    "HeapTaskDaemon",
    "RenderThread",
    "FinalizerDaemon",
    "ReferenceQueueD",
    "pool-1-thread-1",
    "GCDaemon",
};
const size_t kGenericThreadNamesCount =
    sizeof(kGenericThreadNames) / sizeof(kGenericThreadNames[0]);

// Cheap stable hash so the same input always maps to the same replacement.
uint32_t fnv1a(const char *s, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= static_cast<uint8_t>(s[i]);
        h *= 16777619u;
    }
    return h;
}

bool looks_frida_thread_name(const char *name) {
    if (name == nullptr) return false;
    // Substrings that show up in Frida / GLib / GUM / GDBus thread names.
    static const char *const kSuspectSubstrings[] = {
        "frida", "gum-", "gum_", "gmain", "gdbus", "gjs",
        "g-io-", "g-vfs-", "g-main",
    };
    for (auto p : kSuspectSubstrings) {
        if (strstr(name, p) != nullptr) return true;
    }
    return false;
}

const char *sanitize_thread_name(const char *name) {
    if (!looks_frida_thread_name(name)) return name;
    uint32_t h = fnv1a(name, strlen(name));
    return kGenericThreadNames[h % kGenericThreadNamesCount];
}

using pthread_setname_np_t = int (*)(pthread_t, const char *);
pthread_setname_np_t orig_pthread_setname_np = nullptr;

int hooked_pthread_setname_np(pthread_t t, const char *name) {
    const char *sanitized = sanitize_thread_name(name);
    if (sanitized != name) {
        LOGD("[sanitizer] pthread_setname_np '%s' -> '%s'", name, sanitized);
        return orig_pthread_setname_np(t, sanitized);
    }
    return orig_pthread_setname_np(t, name);
}

// prctl is variadic in Bionic but always reads 5 args from the va_list, so
// we hook with a fixed 5-arg shape (matches the AArch64 / ARM / x86 ABIs).
using prctl_5_t = int (*)(int, unsigned long, unsigned long,  // NOLINT(runtime/int)
                          unsigned long, unsigned long);      // NOLINT(runtime/int)
prctl_5_t orig_prctl = nullptr;

int hooked_prctl(int option,
                 unsigned long a2,                    // NOLINT(runtime/int)
                 unsigned long a3,                    // NOLINT(runtime/int)
                 unsigned long a4,                    // NOLINT(runtime/int)
                 unsigned long a5) {                  // NOLINT(runtime/int)
    if (option == PR_SET_NAME && a2 != 0) {
        const char *name = reinterpret_cast<const char *>(a2);
        const char *sanitized = sanitize_thread_name(name);
        if (sanitized != name) {
            LOGD("[sanitizer] prctl(PR_SET_NAME) '%s' -> '%s'",
                 name, sanitized);
            return orig_prctl(option,
                              reinterpret_cast<unsigned long>(sanitized),
                              a3, a4, a5);
        }
    }
    return orig_prctl(option, a2, a3, a4, a5);
}

// ─── Abstract-socket sanitizer ──────────────────────────────────────────────

bool buffer_contains_frida(const char *p, size_t n) {
    if (n < 5 || p == nullptr) return false;
    for (size_t i = 0; i + 5 <= n; i++) {
        if (p[i] == 'f' && p[i + 1] == 'r' && p[i + 2] == 'i' &&
            p[i + 3] == 'd' && p[i + 4] == 'a') {
            return true;
        }
    }
    return false;
}

// Build a sanitized abstract-namespace sockaddr_un. Returns true if a rewrite
// was applied. We keep the same length and the same non-alphanumeric structure
// (so dots / dashes are preserved) and replace alphanumerics with a stable
// hash-derived stream. This guarantees that any later connect() to the same
// original name produces the same translated name, so in-process IPC keeps
// working even though the visible name no longer mentions frida.
bool rewrite_abstract_unix_addr(const struct sockaddr *in, socklen_t in_len,
                                struct sockaddr_un *out, socklen_t *out_len) {
    if (in == nullptr || in->sa_family != AF_UNIX) return false;

    socklen_t hdr = static_cast<socklen_t>(offsetof(struct sockaddr_un, sun_path));
    if (in_len <= hdr + 1) return false;

    const struct sockaddr_un *in_un = reinterpret_cast<const struct sockaddr_un *>(in);
    if (in_un->sun_path[0] != '\0') return false;  // not abstract namespace

    size_t name_len = static_cast<size_t>(in_len) - hdr - 1;
    if (name_len == 0 || name_len + 1 >= sizeof(out->sun_path)) return false;

    const char *name = in_un->sun_path + 1;
    if (!buffer_contains_frida(name, name_len)) return false;

    memset(out, 0, sizeof(*out));
    out->sun_family = AF_UNIX;
    out->sun_path[0] = '\0';

    static const char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    const size_t kAlphabetLen = sizeof(kAlphabet) - 1;
    uint32_t base = fnv1a(name, name_len);

    for (size_t i = 0; i < name_len; i++) {
        char c = name[i];
        bool is_alpha_lower = (c >= 'a' && c <= 'z');
        bool is_alpha_upper = (c >= 'A' && c <= 'Z');
        bool is_digit = (c >= '0' && c <= '9');
        if (is_alpha_lower || is_alpha_upper || is_digit) {
            uint32_t v = base ^ static_cast<uint32_t>(i * 2654435761u);
            out->sun_path[i + 1] = kAlphabet[v % kAlphabetLen];
        } else {
            out->sun_path[i + 1] = c;
        }
    }

    *out_len = static_cast<socklen_t>(hdr + 1 + name_len);
    return true;
}

using bind_t = int (*)(int, const struct sockaddr *, socklen_t);
bind_t orig_bind = nullptr;
bind_t orig_connect = nullptr;

int hooked_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    struct sockaddr_un rewritten = {};
    socklen_t rewritten_len = 0;
    if (rewrite_abstract_unix_addr(addr, len, &rewritten, &rewritten_len)) {
        LOGD("[sanitizer] bind() abstract socket rewritten");
        return orig_bind(fd,
                         reinterpret_cast<const struct sockaddr *>(&rewritten),
                         rewritten_len);
    }
    return orig_bind(fd, addr, len);
}

int hooked_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    struct sockaddr_un rewritten = {};
    socklen_t rewritten_len = 0;
    if (rewrite_abstract_unix_addr(addr, len, &rewritten, &rewritten_len)) {
        return orig_connect(
            fd, reinterpret_cast<const struct sockaddr *>(&rewritten),
            rewritten_len);
    }
    return orig_connect(fd, addr, len);
}

// ─── /proc/self/maps filter (rwxp + maps-scan defense) ─────────────────────
//
// Apps detect Frida's GUM Stalker by scanning `/proc/self/maps` for any
// mapping with rwxp permissions: vanilla Android processes essentially
// never have read+write+execute pages, so even one rwxp line is a hard
// tell. Apps also grep the same file for substrings such as "frida",
// "gum-", "/libgadget" or "re.frida.*".
//
// Rather than trying to reprotect Stalker's JIT pool (which would break
// hooking) we lie about it: open() / openat() on /proc/self/maps return a
// memfd containing a sanitized copy where rwxp -> r-xp and lines whose
// path field mentions a known Frida-family token are removed entirely.
// The staged "jit-cache.so" basename is intentionally kept visible so the
// view stays consistent and looks like an ART JIT artifact.

bool path_is_self_maps(const char *path) {
    if (path == nullptr) return false;
    if (strcmp(path, "/proc/self/maps") == 0) return true;
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "/proc/%d/maps", getpid());
    if (n > 0 && static_cast<size_t>(n) < sizeof(buf) && strcmp(path, buf) == 0) {
        return true;
    }
    return false;
}

bool maps_line_should_drop(const char *line, size_t len) {
    static const char *const kDropTokens[] = {
        "frida",
        "gum-",
        "gum_",
        "/libgadget",
        "/libfrida",
        "/re.frida",
    };
    for (auto t : kDropTokens) {
        size_t tlen = strlen(t);
        if (len < tlen) continue;
        for (size_t i = 0; i + tlen <= len; i++) {
            if (memcmp(line + i, t, tlen) == 0) return true;
        }
    }
    return false;
}

void downgrade_rwxp_inplace(char *line, size_t len) {
    // The perms field appears at most once per maps line.
    for (size_t i = 0; i + 4 <= len; i++) {
        if (line[i] == 'r' && line[i + 1] == 'w' &&
            line[i + 2] == 'x' && line[i + 3] == 'p') {
            line[i + 1] = '-';
            return;
        }
    }
}

using open_3_t = int (*)(const char *, int, mode_t);
open_3_t orig_open = nullptr;

using openat_4_t = int (*)(int, const char *, int, mode_t);
openat_4_t orig_openat = nullptr;

int build_filtered_maps_fd() {
#ifndef SYS_memfd_create
    return -1;
#else
    int real_fd = orig_open != nullptr
                      ? orig_open("/proc/self/maps", O_RDONLY | O_CLOEXEC, 0)
                      : open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (real_fd < 0) return -1;

    std::string raw;
    raw.reserve(8192);
    char buf[8192];
    ssize_t n;
    while ((n = read(real_fd, buf, sizeof(buf))) > 0) {
        raw.append(buf, static_cast<size_t>(n));
    }
    close(real_fd);

    std::string out;
    out.reserve(raw.size());

    size_t pos = 0;
    while (pos < raw.size()) {
        size_t nl = raw.find('\n', pos);
        size_t end = (nl == std::string::npos) ? raw.size() : nl;
        size_t line_len = end - pos;

        if (line_len > 0 && !maps_line_should_drop(raw.data() + pos, line_len)) {
            size_t before = out.size();
            out.append(raw, pos, line_len);
            downgrade_rwxp_inplace(out.data() + before, line_len);
            out.push_back('\n');
        }

        if (nl == std::string::npos) break;
        pos = nl + 1;
    }

    int memfd = static_cast<int>(syscall(SYS_memfd_create, "jit-cache", MFD_CLOEXEC));
    if (memfd < 0) return -1;

    const char *p = out.data();
    size_t left = out.size();
    while (left > 0) {
        ssize_t w = write(memfd, p, left);
        if (w <= 0) {
            close(memfd);
            return -1;
        }
        p += w;
        left -= static_cast<size_t>(w);
    }
    lseek(memfd, 0, SEEK_SET);
    return memfd;
#endif
}

int hooked_open(const char *path, int flags, mode_t mode) {
    if (path_is_self_maps(path)) {
        int fd = build_filtered_maps_fd();
        if (fd >= 0) {
            LOGD("[sanitizer] open(%s) -> filtered memfd %d", path, fd);
            return fd;
        }
    }
    return orig_open(path, flags, mode);
}

int hooked_openat(int dirfd, const char *path, int flags, mode_t mode) {
    if (path_is_self_maps(path)) {
        int fd = build_filtered_maps_fd();
        if (fd >= 0) {
            LOGD("[sanitizer] openat(%s) -> filtered memfd %d", path, fd);
            return fd;
        }
    }
    return orig_openat(dirfd, path, flags, mode);
}

// ─── Hook installation ──────────────────────────────────────────────────────

void *resolve_libc_symbol(const char *name) {
    void *sym = dlsym(RTLD_DEFAULT, name);
    if (sym == nullptr) sym = dlsym(RTLD_NEXT, name);
    return sym;
}

void install_one(const char *name, void *replacement, void **orig) {
    void *sym = resolve_libc_symbol(name);
    if (sym == nullptr) {
        LOGW("[sanitizer] symbol %s not found, skipping", name);
        return;
    }
    int rc = DobbyHook(sym, replacement, orig);
    if (rc != 0) {
        LOGW("[sanitizer] DobbyHook(%s) failed: rc=%d", name, rc);
        return;
    }
    LOGD("[sanitizer] hook installed: %s @ %p", name, sym);
}

std::atomic<bool> g_installed{false};

}  // namespace

void install_runtime_sanitizer() {
    bool expected = false;
    if (!g_installed.compare_exchange_strong(expected, true)) {
        return;
    }
    LOGI("[sanitizer] installing runtime fingerprint sanitizers");

    install_one("pthread_setname_np",
                reinterpret_cast<void *>(&hooked_pthread_setname_np),
                reinterpret_cast<void **>(&orig_pthread_setname_np));

    install_one("prctl",
                reinterpret_cast<void *>(&hooked_prctl),
                reinterpret_cast<void **>(&orig_prctl));

    install_one("bind",
                reinterpret_cast<void *>(&hooked_bind),
                reinterpret_cast<void **>(&orig_bind));

    install_one("connect",
                reinterpret_cast<void *>(&hooked_connect),
                reinterpret_cast<void **>(&orig_connect));

    install_one("open",
                reinterpret_cast<void *>(&hooked_open),
                reinterpret_cast<void **>(&orig_open));

    install_one("openat",
                reinterpret_cast<void *>(&hooked_openat),
                reinterpret_cast<void **>(&orig_openat));
}
