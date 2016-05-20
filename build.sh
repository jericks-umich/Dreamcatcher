#!/bin/bash

THIS_DIR="$( cd "$( /usr/bin/dirname "${BASH_SOURCE[0]}" )" && /bin/pwd )"

# get latest openwrt
git submodule update --init --recursive


