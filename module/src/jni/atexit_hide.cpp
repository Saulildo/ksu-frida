#include "atexit_hide.h"

#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "log.h"
#include "soinfo_hide.h"
#include "xdl.h"

namespace {

// Bionic AtexitArray + AtexitEntry layout from
// bionic/libc/bionic/atexit.cpp (AOSP, Apache-2.0).
//
// The first two fields of AtexitArray (array_ pointer + size_ count) are
// stable across all Android versions we target (7.1+), even though
// later fields churn (extracted_count_ added in Q, total_appends_ in R,
// pthread_mutex_t added later). We only read the first two, so layout
// drift downstream is tolerated.
struct AtexitArrayHead {
    void *array_ptr;  // AtexitEntry *
    size_t size;
};

// AtexitEntry has been stable since bionic was first shipped.
struct AtexitEntry {
    void (*fn)(void *);
    void *arg;
    void *dso;
};

void noop_handler(void * /*arg*/) {}

void *resolve_g_array() {
    static const char *const kCandidatePaths[] = {
        "libc.so",
        "/system/lib64/libc.so",
        "/system/lib/libc.so",
        "/apex/com.android.runtime/lib64/bionic/libc.so",
        "/apex/com.android.runtime/lib/bionic/libc.so",
    };
    void *libc = nullptr;
    for (auto p : kCandidatePaths) {
        libc = xdl_open(p, XDL_TRY_FORCE_LOAD);
        if (libc != nullptr) break;
    }
    if (libc == nullptr) {
        LOGW("[atexit_hide] cannot xdl_open libc");
        return nullptr;
    }

    // First try the file-scope static mangling, then the anonymous-
    // namespace one (some bionic versions wrap g_array in `namespace {}`).
    void *sym = xdl_dsym(libc, "_ZL7g_array", nullptr);
    if (sym == nullptr) {
        sym = xdl_dsym(libc, "_ZN12_GLOBAL__N_17g_arrayE", nullptr);
    }
    xdl_close(libc);
    return sym;
}

bool make_writable(void *addr, size_t len) {
    auto page = sysconf(_SC_PAGESIZE);
    if (page <= 0) page = 4096;
    auto pmask = static_cast<uintptr_t>(page) - 1;
    uintptr_t start = reinterpret_cast<uintptr_t>(addr) & ~pmask;
    uintptr_t end = (reinterpret_cast<uintptr_t>(addr) + len + pmask) & ~pmask;
    return mprotect(reinterpret_cast<void *>(start), end - start,
                    PROT_READ | PROT_WRITE) == 0;
}

bool entry_belongs_to_hidden_module(const AtexitEntry &e) {
    if (e.fn == nullptr) return false;

    Dl_info info{};
    int rc = dladdr(reinterpret_cast<void *>(e.fn), &info);
    // dladdr returns 0 on failure. After install_soinfo_hide() ran
    // successfully, fn pointers into our unlisted soinfo no longer
    // resolve - that is our orphaned-entry signal.
    if (rc == 0 || info.dli_fname == nullptr) return true;
    return soinfo_hide_path_matches(info.dli_fname);
}

std::atomic<bool> g_done{false};

}  // namespace

void scrub_payload_atexit_handlers() {
    bool expected = false;
    if (!g_done.compare_exchange_strong(expected, true)) return;

    void *raw = resolve_g_array();
    if (raw == nullptr) {
        LOGW("[atexit_hide] _ZL7g_array unresolved; skipping");
        return;
    }

    auto *head = static_cast<AtexitArrayHead *>(raw);
    auto *entries = static_cast<AtexitEntry *>(head->array_ptr);
    size_t count = head->size;
    if (entries == nullptr || count == 0) {
        LOGD("[atexit_hide] empty atexit array");
        return;
    }

    if (!make_writable(entries, count * sizeof(AtexitEntry))) {
        LOGW("[atexit_hide] mprotect on atexit array failed");
        return;
    }

    int patched = 0;
    for (size_t i = 0; i < count; i++) {
        if (entry_belongs_to_hidden_module(entries[i])) {
            entries[i].fn = &noop_handler;
            entries[i].arg = nullptr;
            patched++;
        }
    }

    if (patched > 0) {
        LOGI("[atexit_hide] patched %d atexit entries", patched);
    } else {
        LOGD("[atexit_hide] no atexit entries needed patching");
    }
}
