#!/bin/sh
# Cross-compile the benign PE test samples (corpus/pe/sample.c) without a
# Windows SDK: clang emits COFF objects, lld-link (rust-lld from the Rust
# toolchain, or a system lld-link) creates import libraries from .def files
# and links. Outputs: <out>/pe-<arch>-{hard,weak}.exe
#   usage: corpus/build-pe.sh [out-dir]     (default: corpus/out)
# Exit status 2 means a required tool is missing (callers skip).
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/out}
mkdir -p "$out"
command -v clang >/dev/null 2>&1 || { echo "clang not found" >&2; exit 2; }
LLD=""
if command -v lld-link >/dev/null 2>&1; then
  LLD="lld-link"
elif command -v rustc >/dev/null 2>&1; then
  host=$(rustc -vV | sed -n 's/^host: //p')
  cand="$(rustc --print sysroot)/lib/rustlib/$host/bin/rust-lld"
  [ -x "$cand" ] && LLD="$cand -flavor link"
fi
[ -n "$LLD" ] || { echo "lld-link / rust-lld not found" >&2; exit 2; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

alt=""
def() { # name machine stdcall-decorated(x86) exports...
  lib=$1; m=$2; dec=$3; shift 3
  {
    echo "LIBRARY $(echo "$lib" | tr a-z A-Z).dll"
    echo "EXPORTS"
    for e in "$@"; do
      echo "  ${e%@*}"
      # x86 __stdcall call sites reference _Name@N; bind them to the plain
      # export so the hint/name table says "Name", as with the real DLLs.
      [ "$dec" = 1 ] && alt="$alt /alternatename:__imp__$e=__imp__${e%@*}"
    done
  } > "$tmp/$lib-$m.def"
  $LLD /lib /nologo /def:"$tmp/$lib-$m.def" /machine:"$m" /out:"$tmp/$lib-$m.lib" >/dev/null
}

for arch in x86_64 aarch64 i686; do
  alt=""
  case $arch in
    x86_64) m=x64; dec=0; tag=x86_64 ;;
    aarch64) m=arm64; dec=0; tag=arm64 ;;
    i686) m=x86; dec=1; tag=x86 ;;
  esac
  def kernel32 $m $dec ExitProcess@4 GetModuleHandleA@4 GetProcAddress@8 VirtualProtect@16 IsDebuggerPresent@0
  def user32 $m $dec MessageBoxA@16
  def advapi32 $m $dec RegOpenKeyExA@20 RegSetValueExA@24
  clang -target $arch-pc-windows-msvc -O2 -fstack-protector-strong -c "$here/pe/sample.c" -o "$tmp/s-$m.obj"
  libs="$tmp/kernel32-$m.lib $tmp/user32-$m.lib $tmp/advapi32-$m.lib"
  common="/nologo /nodefaultlib /entry:mainCRTStartup /subsystem:console /safeseh:no"
  [ $m = x86 ] || common="/nologo /nodefaultlib /entry:mainCRTStartup /subsystem:console"
  # Hardened: ASLR (+high entropy on 64-bit), DEP, CFG, /GS cookie in load config.
  hard="/dynamicbase /nxcompat /guard:cf"
  [ $m = x86 ] || hard="$hard /highentropyva"
  $LLD $common $hard $alt /out:"$out/pe-$tag-hard.exe" "$tmp/s-$m.obj" $libs
  # Weak: fixed base, no DEP/CFG (ARM64 Windows requires ASLR, so x86 only).
  if [ $m != arm64 ]; then
    weak="/dynamicbase:no /nxcompat:no /fixed"
    [ $m = x86 ] || weak="$weak /highentropyva:no"
    $LLD $common $weak $alt /out:"$out/pe-$tag-weak.exe" "$tmp/s-$m.obj" $libs
  fi
done
