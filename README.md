# VoidWalker

> Walk the shadows of the kernel, remain undetected by the Watch.

VoidWalker is a Zygisk module that injects a Frida gadget (or any other
`.so`) into the address space of selected Android applications, while actively
hiding the loader's fingerprints from in-app detection.

> [Frida](https://frida.re) is a dynamic instrumentation toolkit for developers,
> reverse-engineers, and security researchers.\
> [Zygisk](https://github.com/topjohnwu/Magisk) is the part of Magisk (and
> Rezygisk / Zygisk-Next) that allows code to run inside every Android
> application's process.

## What's different vs running frida-server

- The gadget is **not** embedded into the APK itself, so APK signature /
  integrity checks still pass.
- The target process is **not** ptraced like it is with `frida-server`,
  avoiding the entire ptrace-based detection family.
- Control over the timing of the injection (configurable per-app start-up
  delay) so apps that scan at launch can be stepped past.
- Allows loading multiple arbitrary libraries into the process.
- Compatible with [Rezygisk](docs/rezygisk.md) and the Rezygisk CSO loader -
  no source changes required.

## Anti-detection layer

Beyond the gadget itself (sourced from
[`appknox/knox-frida-patcher`](https://github.com/appknox/knox-frida-patcher)
which renames Frida's compile-time identifiers), VoidWalker scrubs additional
runtime fingerprints:

| Detection vector                                            | How VoidWalker hides it |
|-------------------------------------------------------------|--------------------------|
| `frida-server` process name in `/proc/*/cmdline`            | Not used (loader runs in-process) |
| `libfrida-agent.so` / `libgadget.so` in `/proc/self/maps`   | Staging copy renamed to `jit-cache.so`; original mapping anonymised by `remap_lib` after dlopen; `/proc/self/maps` is also returned via a memfd-filtered view |
| `gum-js-loop` / `gmain` / `gdbus*` in `/proc/<tid>/comm`    | Runtime hooks on `pthread_setname_np` and `prctl(PR_SET_NAME)` rewrite suspicious names to vanilla Android thread labels |
| `frida-agent-64.so` in `/proc/self/fd/*` readlinks          | Staged file basename is `jit-cache.so`, so any memfd-style readlink shows the JIT artifact name |
| `frida_agent_main` symbol via `dlsym` / memory scan         | Rebranded gadget from `knox-frida-patcher` (no upstream symbol) |
| `frida_file` SELinux label                                  | Rebranded gadget                |
| Default port `27042`                                        | Default config ships in `script` mode (no listener); listen-mode users set `port` in `libsecmon.config.so` |
| `re.frida.server` D-Bus name                                | Rebranded gadget                |
| Abstract Unix sockets containing `frida`                    | Runtime hooks on `bind()` and `connect()` rewrite the abstract-namespace name with a stable hash so in-process IPC keeps working |
| `.frida` / `frida-` temp paths                              | Staging directory is `/data/data/<pkg>/.cache/`; bundled gadget is at `/data/local/tmp/libsec/` |
| `rwxp` JIT pages in `/proc/self/maps`                       | `open` / `openat` hook downgrades `rwxp` to `r-xp` in the filtered maps view returned to the caller |
| Module enumeration via `dl_iterate_phdr`                    | After Frida finishes initialising, the loader unlinks the gadget from the linker's private `solist` (mappings preserved via `size_=0` trick); a `dl_iterate_phdr` filter hook serves as fallback |
| Direct linker `solist` walking                              | Same `solist` unlink covers private linker walkers (resolves Bionic linker internals via xDL `.symtab` lookup) |
| Dangling atexit handlers pointing into hidden modules       | Walks Bionic's `_ZL7g_array` and replaces orphaned entries with a no-op so `__cxa_finalize` doesn't crash and so handler enumeration cannot use them as a tell |
| `PHH_*` GSI environment variables                           | Cleared from `environ` during the post-load scrub |
| Library remapping (Fridagisk-style)                         | `remapper.cpp` copies each segment to a fresh anon mmap and `mremap`s it over the original to strip path/inode |

## How to use the module

### Prerequisites
- Rooted device / emulator
- Zygisk available and enabled (Magisk, Rezygisk, Zygisk-Next, or KernelSU's built-in Zygisk)

### Quick start
- Download the latest release from the [Release Page](https://github.com/Saulildo/ksu-frida/releases).
- Transfer the zip to your device and install it via Magisk (or KernelSU /
  APatch).
- Reboot after install.
- Create the config file and adjust the package name to your target app
  (replace `your.target.application` in the commands):
```shell
adb shell 'su -c cp /data/local/tmp/libsec/config.json.example /data/local/tmp/libsec/config.json'
adb shell 'su -c sed -i s/com.example.package/your.target.application/ /data/local/tmp/libsec/config.json'
```
- Launch your app. It will pause at start-up allowing you to attach,
  e.g. `frida -U -N your.target.application` or `frida -U -n Gadget`.

This assumes you don't have any other Frida server running. You can still run
it together with `frida-server` but you would have to configure the gadget to
use a different port.

### Library Remapper

VoidWalker has an advanced system to hide library loading inside the
`/proc/self/maps` view of the target. This is called the library *remapper*.
On a successful injection of a library, the remapper attempts to copy the data
from the procfs-backed mapping and reallocate it into a separate anonymous
memory location for the target library. This prevents detection / scanning
attempts which might be used by the target application to check for suspicious
injection or shared libraries.
Implementation lives in
[`module/src/jni/remapper.cpp`](module/src/jni/remapper.cpp).

### Runtime sanitizer

Even with a renamed gadget, Frida's runtime can still leak a few hardcoded
identifiers (thread names from GUM / GLib, abstract Unix sockets in some
configurations, `rwxp` JIT pages, lingering atexit registrations).
VoidWalker installs Dobby-based inline hooks on `pthread_setname_np`,
`prctl(PR_SET_NAME)`, `bind()`, `connect()`, `open()` and `openat()` *before*
the payload is loaded and rewrites any frida-/gum-/gmain-/gdbus-flavoured
strings on the fly.

After the gadget finishes initialising the loader runs a post-load scrub
that unlinks the staged payload from the Bionic linker's private `solist`
(memory mappings preserved so worker threads keep executing), filters
`dl_iterate_phdr` as a fallback, neutralises orphaned `atexit` handlers,
and clears PHH-GSI environment variables. See
[`module/src/jni/sanitizer.cpp`](module/src/jni/sanitizer.cpp),
[`module/src/jni/soinfo_hide.cpp`](module/src/jni/soinfo_hide.cpp) and
[`module/src/jni/atexit_hide.cpp`](module/src/jni/atexit_hide.cpp).

The `solist` unlink and atexit scrub techniques were inspired by
[PerformanC/Treat-Wheel-Zygisk](https://github.com/PerformanC/Treat-Wheel-Zygisk)
(AGPLv3); they are reimplemented here as independent clean-room code that
references AOSP `bionic/linker/linker.cpp` and `bionic/libc/bionic/atexit.cpp`
as primary sources and reuses the in-tree xDL `.symtab` resolver instead of
porting the AGPLv3 ELF parser.

### Configuration

This module also supports adding a start up delay that can delay injection of
the payload to avoid checks run at startup time, loading arbitrary libraries
and child gating.

Please take a look at the [advanced configuration guide](docs/advanced_config.md)
for this. The legacy [simple config](docs/simple_config.md) is still supported.

For Rezygisk-specific notes, see [docs/rezygisk.md](docs/rezygisk.md).

## How to build

- Checkout the project.
- Run `./gradlew :module:assembleRelease`.
- The built Magisk module will be in the `out` directory:
  - `out/voidwalker-vX.Y.Z-release.zip`

You can also build and install the module to your device directly with
`./gradlew :module:flashAndRebootRelease`.

CI builds the module on every push to `main` / `voidwalker` and uploads the
zip as a workflow artifact; see
[.github/workflows/ci.yml](.github/workflows/ci.yml).

## Caveats

- For emulators this will start the gadget in native realm. This means you
  will be able to hook Java but not native functions.

## Credits

- Inspired by https://github.com/Perfare/Zygisk-Il2CppDumper
- https://github.com/lico-n/ZygiskFrida (upstream)
- https://github.com/electrondefuser/fridagisk (remapper implementation)
- https://github.com/hexhacking/xDL
- https://github.com/jmpews/Dobby
- https://github.com/appknox/knox-frida-patcher (rebranded gadget builds)
