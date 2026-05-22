#include "sanitizer.h"

#include <dlfcn.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <dobby.h>

#include "log.h"

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
}
