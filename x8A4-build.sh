#!/bin/sh
# Builds the bundled x8A4 CLI (vendored from Cryptiiiic/x8A4 99a79f7 + NonceSetX changes, see README.md) as one arm64 binary.
# libkrw is found in <jbroot>/usr/lib from <jbroot>/Applications/NonceSetX.app on both rootless and roothide.
set -e
cd "$(dirname "$0")/x8A4"
OUT="${1:-../.theos/x8A4}"
mkdir -p "$(dirname "$OUT")"

xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=15.0 -std=gnu17 -O2 -Wall \
	-IInclude -IInclude/choma \
	-DVERSION_COMMIT_COUNT='"11"' -DVERSION_COMMIT_SHA='"99a79f7-noncesetx"' -DSOVERSION=1 -DRELEASE='"1"' \
	x8A4_CLI.c x8A4.c Logger/logger.c Kernel/*.c Services/services.c Registry/registry.c \
	Lib/libchoma.a Lib/libxpf.a Lib/libkrw.tbd \
	-framework CoreFoundation -framework IOKit -lcompression -lz \
	-Wl,-rpath,@executable_path/../../usr/lib \
	-o "$OUT"

ldid -Stfp0.plist "$OUT"
