#!/bin/bash

# DON'T USE THIS IF YOU DON'T KNOW WHAT IT DOES

THIS_DIR="$( cd "$( /usr/bin/dirname "${BASH_SOURCE[0]}" )" && /bin/pwd )"
OPENWRT_DIR=$THIS_DIR/openwrt

pushd $OPENWRT_DIR
make package/dreamcatcher/clean
make package/dreamcatcher/compile V=s
popd

echo "If you see build errors, fix them and try again."
echo "If the build worked, you can get the dreamcatcher binary at"
echo "$OPENWRT_DIR/build_dir/target-mips_34kc_musl-1.1.14/dreamcatcher/dreamcatcher"
