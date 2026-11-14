#!/bin/sh
# Build the benign test corpus (spec §9.2). Outputs go to corpus/out (not committed).
set -e
cd "$(dirname "$0")"
mkdir -p out
for src in src/*.c; do
  n=$(basename "$src" .c)
  for opt in O0 O1 O2 O3 Os; do
    for arch in arm64 x86_64; do
      clang -$opt -g -arch $arch -o "out/$n-$arch-$opt" "$src" 2>/dev/null || continue
      cp "out/$n-$arch-$opt" "out/$n-$arch-$opt.stripped" && strip "out/$n-$arch-$opt.stripped"
    done
  done
done
ls out | wc -l
