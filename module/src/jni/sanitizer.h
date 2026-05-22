#ifndef ZYGISKFRIDA_SANITIZER_H
#define ZYGISKFRIDA_SANITIZER_H

// Installs runtime hooks that scrub well-known Frida fingerprints from
// the target process before the gadget is loaded.
//
// Currently filters:
//   - pthread_setname_np / prctl(PR_SET_NAME) thread renames matching
//     gum-*, gmain, gdbus*, frida-*, etc. (visible via /proc/<tid>/comm).
//   - bind() / connect() on AF_UNIX abstract-namespace addresses whose
//     payload contains "frida" (visible via /proc/net/unix).
//
// Idempotent: subsequent calls are no-ops.
void install_runtime_sanitizer();

#endif  // ZYGISKFRIDA_SANITIZER_H
