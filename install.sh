#!/bin/sh
set -eu
prefix="${PREFIX:-/usr/local}"
dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cc_bin="${CC:-cc}"
"$cc_bin" ${CFLAGS:--O2 -std=c99} -o "$dir/nettop" "$dir/nettop.c"
mkdir -p "$prefix/bin"
cp "$dir/nettop" "$prefix/bin/nettop"
chmod 755 "$prefix/bin/nettop"
printf 'Installed nettop to %s\n' "$prefix/bin/nettop"
