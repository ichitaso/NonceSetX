#!/bin/sh
# Builds nsx26 (iOS 26 helper, see nsx26/nsx26.c). libjailbreak is Dopamine's <jbroot>/basebin/libjailbreak.dylib.
set -e
cd "$(dirname "$0")/nsx26"
OUT="${1:-../.theos/nsx26}"
mkdir -p "$(dirname "$OUT")"

xcrun -sdk iphoneos clang -arch arm64 -miphoneos-version-min=15.0 -O2 -Wall \
	nsx26.c libjailbreak.tbd -framework CoreFoundation -framework IOKit \
	-Wl,-rpath,@executable_path/../../basebin \
	-o "$OUT"

ldid -Sent.plist "$OUT"
