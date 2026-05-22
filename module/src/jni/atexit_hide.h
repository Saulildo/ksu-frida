#ifndef ZYGISKFRIDA_ATEXIT_HIDE_H
#define ZYGISKFRIDA_ATEXIT_HIDE_H

// Walk libc's static atexit registry (Bionic AtexitArray g_array) and
// replace any handler whose fn pointer either:
//   (a) no longer dladdr-resolves to a visible shared object - i.e. it
//       points into a soinfo we just unlisted; or
//   (b) resolves to a path on the soinfo_hide hide list - i.e. it
//       belongs to a frida-family module we want to disown.
//
// Replacement is a no-op handler in our loader (which stays loaded for
// target apps), so __cxa_finalize at process exit cannot crash dancing
// over a freed soinfo's destructors.
//
// Idempotent. Must be called after install_soinfo_hide() so the
// dladdr-failure path correctly identifies orphaned entries.
//
// Technique inspiration: PerformanC/Treat-Wheel-Zygisk's do_atexit_hiding
// (AGPLv3); independent clean-room reimplementation backed by AOSP
// bionic/libc/bionic/atexit.cpp documentation. No code is copied.
void scrub_payload_atexit_handlers();

#endif  // ZYGISKFRIDA_ATEXIT_HIDE_H
