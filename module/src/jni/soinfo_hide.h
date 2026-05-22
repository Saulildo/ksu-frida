#ifndef ZYGISKFRIDA_SOINFO_HIDE_H
#define ZYGISKFRIDA_SOINFO_HIDE_H

// Post-load anti-enumeration scrub:
//
//   1. Best-effort unlinks the staged payload (and any frida-family
//      soinfo loaded alongside) from the Bionic linker's private solist
//      so private linker walkers stop seeing them. Memory mappings are
//      preserved (size_=0 trick) so worker threads keep executing.
//   2. Hooks dl_iterate_phdr() as a fallback / defense in depth: any
//      caller iterating the soinfo list via the libc public API skips
//      our hidden modules.
//   3. Scrubs PHH-GSI environment variables that would otherwise tell a
//      detection app that the device is on a non-stock GSI.
//
// Idempotent. Call after the payload has fully initialised.
//
// Technique inspiration: PerformanC/Treat-Wheel-Zygisk (AGPLv3), used as
// reference material only. This is an independent clean-room
// reimplementation backed by xDL's existing .symtab lookup helper and
// AOSP linker.cpp / atexit.cpp documentation. No code is copied.
void install_soinfo_hide();

// Substring-matches the supplied path against the shared hide list
// (jit-cache.so, frida-agent-*, libgadget, libfrida, re.frida, ...).
// Exposed so other components (atexit_hide) can reuse the same policy.
bool soinfo_hide_path_matches(const char *path);

#endif  // ZYGISKFRIDA_SOINFO_HIDE_H
