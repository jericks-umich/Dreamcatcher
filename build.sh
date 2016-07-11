#!/bin/bash

USAGE="Usage: $0 [-h] [-s] [-i]
-h  print usage statement
-s  skip intro updates (useful when rebuilding)
-i  install required dependencies (apt-get based only)
"

THIS_DIR="$( cd "$( /usr/bin/dirname "${BASH_SOURCE[0]}" )" && /bin/pwd )"
OPENWRT_DIR=$THIS_DIR/openwrt
CONFIG_DIR=$THIS_DIR/config
PATCH_DIR=$THIS_DIR/patches
DREAMCATCHER_DIR=$THIS_DIR/dreamcatcher
LUCI_APP_DREAMCATCHER_DIR=$THIS_DIR/luci-app-dreamcatcher
DEPS="git-core build-essential libssl-dev libncurses5-dev unzip gawk"

for arg in "$@"; do
	case $arg in
		-s)
			SKIP=1
			;;
		-i)
			INSTALL=1
			;;
		*)
			printf '%s' "$USAGE"
			exit
			;;
	esac
done

# do installation of dependencies, but only if -i IS present
if [ "$INSTALL" == "1" ] ; then
	echo "Installing dependencies. Need your sudo password."
	sudo apt-get install $DEPS
fi


# do one-time setup stuff here, and allow it to be skipped in the future
if [ "$SKIP" != "1" ] ; then
	# get latest openwrt
	echo "Retrieving and updating OpenWRT repository."
	git submodule update --init --recursive

	# update feeds (packages, etc.)
	echo "Updating OpenWRT modules"
	pushd $OPENWRT_DIR
	./scripts/feeds update -a
	./scripts/feeds install -a
	popd
fi

# from here, run every time build.sh is called

#### PACKAGES ####
# add dreamcatcher package
rm $OPENWRT_DIR/package/network/utils/dreamcatcher 2>/dev/null
ln -s $DREAMCATCHER_DIR $OPENWRT_DIR/package/network/utils/dreamcatcher

# add luci-app-dreamcatcher package
# don't build while still under development
#rm $OPENWRT_DIR/package/feeds/luci/luci-app-dreamcatcher 2>/dev/null
#ln -s $LUCI_APP_DREAMCATCHER_DIR $OPENWRT_DIR/package/feeds/luci/luci-app-dreamcatcher

#### CONFIG ####
# use our config file diff with everything we need in it
# (Note: you can manually edit this configuration by cd'ing to the openwrt/
#  directory and running 'make menuconfig')
echo "Updating OpenWRT build config file..."
rm $OPENWRT_DIR/.config 2>/dev/null
pushd $OPENWRT_DIR
make defconfig
cat $CONFIG_DIR/development.diff >> $OPENWRT_DIR/.config
#cat $CONFIG_DIR/dreamcatcher.diff >> $OPENWRT_DIR/.config
make defconfig
popd

#### PATCHES ####
# add patches to openwrt
echo "Linking patches to openwrt build..."
# hostapd - add additional bridge naming scheme
rm $OPENWRT_DIR/package/network/services/hostapd/patches/701-static_bridge_vlan_naming.patch 2>/dev/null
ln -s $PATCH_DIR/701-static_bridge_vlan_naming.patch $OPENWRT_DIR/package/network/services/hostapd/patches/
# firewall3 - add additional dreamcatcher firewall chain
mkdir -p $OPENWRT_DIR/package/network/config/firewall/patches
rm $OPENWRT_DIR/package/network/config/firewall/patches/701-dreamcatcher-chain.patch 2>/dev/null
ln -s $PATCH_DIR/701-dreamcatcher-chain.patch $OPENWRT_DIR/package/network/config/firewall/patches/701-dreamcatcher-chain.patch
# firewall3 - allow reloading of dreamcatcher firewall chain
# don't build while still under development
#rm $OPENWRT_DIR/package/network/config/firewall/patches/702-dreamcatcher-firewall-reload.patch 2>/dev/null
#ln -s $PATCH_DIR/702-dreamcatcher-firewall-reload.patch $OPENWRT_DIR/package/network/config/firewall/patches/702-dreamcatcher-firewall-reload.patch

#### MAKE ####
# make openwrt
echo "Building openwrt. This may take a while."
pushd $OPENWRT_DIR
make # making with multiple threads often causes build to fail
#make -j$(nproc)
_status=$?
popd

#### MESSAGES FOR USER ####
if [ "$_status" == "0" ] ; then
	image_path=$OPENWRT_DIR/openwrt/bin/ar71xx/openwrt-ar71xx-generic-tl-wdr4300-v1-squashfs-factory.bin
	echo "Build complete. You can find your image at $image_path."
	echo "After flashing, put CA at /root/CA/ and freeradius2 at /etc/freeradius2/ ."
fi


