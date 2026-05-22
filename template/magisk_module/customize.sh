# VoidWalker module installer.
#
# We do NOT set SKIPUNZIP=1: Magisk auto-extracts the zip to $MODPATH so
# module.prop / zygisk/<abi>.so / webroot/ / config.json.example all land
# in their final locations without any manual "extract" plumbing. This
# script only handles the bits Magisk can't: unpacking the bundled gadget
# .xz files into /data/local/tmp/libsec/ and dropping a sane default
# gadget config.

MODULE_ID=@MODULE_ID@
TMP_MODULE_DIR=/data/local/tmp/libsec

if [ "$ARCH" != "arm" ] && [ "$ARCH" != "arm64" ] && [ "$ARCH" != "x86" ] && [ "$ARCH" != "x64" ]; then
  abort "! Unsupported platform: $ARCH"
fi
ui_print "- Device platform: $ARCH"

BUSYBOX_BIN=/data/adb/magisk/busybox
[ -f $BUSYBOX_BIN ] || BUSYBOX_BIN=/data/adb/ksu/bin/busybox
[ -f $BUSYBOX_BIN ] || BUSYBOX_BIN=/data/adb/ap/bin/busybox
[ -f $BUSYBOX_BIN ] || abort "! unable to locate busybox"
ui_print "- Using busybox: $BUSYBOX_BIN"

mkdir -p "$TMP_MODULE_DIR"
ui_print "- Payload directory: $TMP_MODULE_DIR"

# Map device $ARCH to the gadget arch directory we shipped (downloaded
# by gradle's downloadFrida task, currently arm and arm64 only).
case "$ARCH" in
  arm)   PRIMARY_GADGET=arm    ; SECONDARY_GADGET= ;;
  arm64) PRIMARY_GADGET=arm64  ; SECONDARY_GADGET=arm ;;
  x86)   PRIMARY_GADGET=x86    ; SECONDARY_GADGET= ;;
  x64)   PRIMARY_GADGET=x86_64 ; SECONDARY_GADGET=x86 ;;
esac

install_gadget() {
  src_arch=$1
  dst_name=$2
  src="$MODPATH/gadget/libgadget-$src_arch.so.xz"
  if [ -f "$src" ]; then
    ui_print "- Installing gadget ($src_arch -> $dst_name)"
    cp -f "$src" "$TMP_MODULE_DIR/$dst_name.xz"
    $BUSYBOX_BIN unxz -f "$TMP_MODULE_DIR/$dst_name.xz"
  else
    ui_print "- Skipping gadget for $src_arch (not bundled in this build)"
  fi
}

install_gadget "$PRIMARY_GADGET" "libsecmon.so"
[ -n "$SECONDARY_GADGET" ] && [ "$IS64BIT" = true ] && install_gadget "$SECONDARY_GADGET" "libsecmon32.so"

# The bundled .xz files have served their purpose; remove them from the
# installed module so we don't waste space on disk.
rm -rf "$MODPATH/gadget"

# Surface the example config alongside the runtime config path so users
# can `cp config.json.example config.json` without copying out of /data/adb.
[ -f "$MODPATH/config.json.example" ] && cp -f "$MODPATH/config.json.example" "$TMP_MODULE_DIR/config.json.example"

ui_print "- Writing default gadget config (script mode)"
echo '{"interaction":{"type":"script","path":"/data/local/tmp/libsec/script.js"}}' > "$TMP_MODULE_DIR/libsecmon.config.so"

set_perm_recursive "$TMP_MODULE_DIR" 0 0 0755 0644
set_perm_recursive "$MODPATH" 0 0 0755 0644
