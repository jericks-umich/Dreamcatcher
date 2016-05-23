# wrt
The quest for a secure home network.

# Build Target (Pre-installation)
Right now, we are using the TP-Link WDR4300, and so this build process is designed for it.
Before you can flash our image, you may need to unlock your device.
Start by flashing `factory-to-ddwrt-us.bin`, then revert to a previous version of the 
TP-Link firmware with `tl-wdr4300v1-webrevert.bin`, then you can flash OpenWRT builds.
These files can be found in `unlock/`.

This link can be handy: [https://wiki.openwrt.org/toh/tp-link/tl-wdr4300](https://wiki.openwrt.org/toh/tp-link/tl-wdr4300)

# Installation
Simply run the build script. It will initialize the OpenWRT submodule, link
the configuration files and patches into place, and run `make`.
    Usage: ./build.sh [-h] [-s] [-i]
    -h  print usage statement
    -s  skip intro updates (useful when rebuilding)
    -i  install required dependencies (apt-get based only) 

