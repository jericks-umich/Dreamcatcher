#!/bin/bash

USAGE="Usage: $0 [-h] [-s] [-i] [-vm] [-j]
-h  print usage statement
-s  setup intro updates -- must be done originally before building the first time
-i  install required dependencies (apt-get based only)
-vm	build x86 VM for testing
"

THIS_DIR="$( cd "$( /usr/bin/dirname "${BASH_SOURCE[0]}" )" && /bin/pwd )"
OPENWRT_DIR=$THIS_DIR/openwrt
CONFIG_DIR=$THIS_DIR/config
PATCH_DIR=$THIS_DIR/patches
DREAMCATCHER_DIR=$THIS_DIR/dreamcatcher
WARDEN_DIR=$THIS_DIR/warden
LUCI_APP_DREAMCATCHER_DIR=$THIS_DIR/luci-app-dreamcatcher
DEPS="git-core build-essential libssl-dev libncurses5-dev unzip gawk subversion quilt zlib1g-dev"
XTABLES_DEPS="pkg-config libxtables-dev libxtables12 xtables-addons-common xtables-addons-dkms xtables-addons-source"

for arg in "$@"; do
	case $arg in
		-s)
			SETUP=1
			;;
		-i)
			INSTALL=1
			;;
		-vm)
			VM=1
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
	sudo apt-get update
	sudo apt-get install $DEPS $XTABLES_DEPS
fi


# do one-time setup stuff here, and allow it to be skipped in the future
if [ "$SETUP" == "1" ] ; then
	# get latest openwrt
	echo "Retrieving and updating OpenWRT repository."
	git submodule update --init --recursive

	# update feeds (packages, etc.)
	echo "Updating OpenWRT modules"
	#pushd $OPENWRT_DIR
	#./scripts/feeds update -a
	#./scripts/feeds install -a
	#popd

	# openwrt's feeds script will pull down the latest versions of the feeds
	# we want feeds from a particular snapshot in time (aug 31, 2016)

	# remove old feeds
	pushd $OPENWRT_DIR
	rm -rf ./feeds
	mkdir ./feeds
	popd

	# clone all the feeds
	pushd $OPENWRT_DIR/feeds/
	git clone https://github.com/openwrt/packages.git
	git clone https://github.com/openwrt/luci.git
	git clone https://github.com/openwrt-routing/packages.git routing
	git clone https://github.com/openwrt/telephony.git
	git clone https://github.com/openwrt-management/packages.git management
	git clone https://github.com/openwrt/targets.git
	popd

	# check out specific revisions
	pushd $OPENWRT_DIR/feeds/packages
	git checkout 4944d6e1b55b3e321f559ae0779f00213a246d6f
	popd
	pushd $OPENWRT_DIR/feeds/luci
	git checkout d5f8c9b0280ac17eaa8ea87a893204dfeeea7d68
	popd
	pushd $OPENWRT_DIR/feeds/routing
	git checkout 96d00199991eac7d6c29e8d08458e12750489e82
	popd
	pushd $OPENWRT_DIR/feeds/telephony
	git checkout 1f0fb2538ba6fc306198fe2a9a4b976d63adb304
	popd
	pushd $OPENWRT_DIR/feeds/management
	git checkout 3a3acd14c77156f8f67cf491263a027a2d483bfd
	popd
	pushd $OPENWRT_DIR/feeds/targets
	git checkout a977f6ab0f2f1cbdc8ee6bdca08ebc86980e4350
	popd
fi


#### PACKAGES ####
# add dreamcatcher package
rm $OPENWRT_DIR/package/network/utils/dreamcatcher 2>/dev/null
ln -s $DREAMCATCHER_DIR $OPENWRT_DIR/package/network/utils/dreamcatcher

# add warden package
rm $OPENWRT_DIR/package/network/utils/warden 2>/dev/null
ln -s $WARDEN_DIR $OPENWRT_DIR/package/network/utils/warden

# build feed indices (this was stolen and modified from scripts/feeds)
pushd $OPENWRT_DIR/
for feed in packages luci routing telephony management targets; do
	mkdir -p "./feeds/$feed.tmp"
	mkdir -p "./feeds/$feed.tmp/info"

	export TOPDIR=$OPENWRT_DIR
	make -s prepare-mk OPENWRT_BUILD= TMP_DIR="$OPENWRT_DIR/feeds/$feed.tmp"
	make -s -f include/scan.mk IS_TTY=1 SCAN_TARGET="packageinfo" SCAN_DIR="feeds/$feed" SCAN_NAME="package" SCAN_DEPS="$OPENWRT_DIR/include/package*.mk" SCAN_DEPTH=5 SCAN_EXTRA="" TMP_DIR="$OPENWRT_DIR/feeds/$feed.tmp"
	make -s -f include/scan.mk IS_TTY=1 SCAN_TARGET="targetinfo" SCAN_DIR="feeds/$feed" SCAN_NAME="target" SCAN_DEPS="profiles/*.mk $OPENWRT_DIR/include/target.mk" SCAN_DEPTH=5 SCAN_EXTRA="" SCAN_MAKEOPTS="TARGET_BUILD=1" TMP_DIR="$OPENWRT_DIR/feeds/$feed.tmp"
	ln -sf $feed.tmp/.packageinfo ./feeds/$feed.index
	ln -sf $feed.tmp/.targetinfo ./feeds/$feed.targetindex
done
popd

# install feeds
pushd $OPENWRT_DIR
./scripts/feeds install -a
popd

# add luci-app-dreamcatcher package
rm $OPENWRT_DIR/package/feeds/luci/luci-app-dreamcatcher 2>/dev/null
ln -s $LUCI_APP_DREAMCATCHER_DIR $OPENWRT_DIR/package/feeds/luci/luci-app-dreamcatcher


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
rm $OPENWRT_DIR/package/network/config/firewall/patches/702-dreamcatcher-firewall-reload.patch 2>/dev/null
ln -s $PATCH_DIR/702-dreamcatcher-firewall-reload.patch $OPENWRT_DIR/package/network/config/firewall/patches/702-dreamcatcher-firewall-reload.patch
# firewall3 - automatically create NFQUEUE target default rule to send packets to dreamcatcher
rm $OPENWRT_DIR/package/network/config/firewall/patches/703-dreamcatcher-nfqueue-rule.patch 2>/dev/null
ln -s $PATCH_DIR/703-dreamcatcher-nfqueue-rule.patch $OPENWRT_DIR/package/network/config/firewall/patches/703-dreamcatcher-nfqueue-rule.patch
# firewall3 - adjust default dreamcatcher iptables rules to send mdns packets to dreamcatcher before hitting rules
rm $OPENWRT_DIR/package/network/config/firewall/patches/704-dreamcatcher-mdns-rule.patch 2>/dev/null
ln -s $PATCH_DIR/704-dreamcatcher-mdns-rule.patch $OPENWRT_DIR/package/network/config/firewall/patches/704-dreamcatcher-mdns-rule.patch
# firewall3 - update to prioritize unicast rules over broadcast rules
rm $OPENWRT_DIR/package/network/config/firewall/patches/705-dreamcatcher-unicast-broadcast-priority.patch 2>/dev/null
ln -s $PATCH_DIR/705-dreamcatcher-unicast-broadcast-priority.patch $OPENWRT_DIR/package/network/config/firewall/patches/705-dreamcatcher-unicast-broadcast-priority.patch
# xtables-addons - add support for native iptables mdns module
rm $OPENWRT_DIR/package/network/utils/iptables/patches/706-dreamcatcher-iptables-mdns.patch 2>/dev/null
ln -s $PATCH_DIR/706-dreamcatcher-iptables-mdns.patch $OPENWRT_DIR/package/network/utils/iptables/patches/706-dreamcatcher-iptables-mdns.patch
rm $OPENWRT_DIR/package/network/utils/xtables-addons/patches/706-dreamcatcher-xtables-mdns.patch 2>/dev/null
ln -s $PATCH_DIR/706-dreamcatcher-xtables-mdns.patch $OPENWRT_DIR/package/network/utils/xtables-addons/patches/706-dreamcatcher-xtables-mdns.patch
rm $OPENWRT_DIR/target/linux/generic/patches-4.1/706-dreamcatcher-xtables-mdns-kernel.patch 2>/dev/null
ln -s $PATCH_DIR/706-dreamcatcher-xtables-mdns-kernel.patch $OPENWRT_DIR/target/linux/generic/patches-4.1/706-dreamcatcher-xtables-mdns-kernel.patch

# compatibility patches
rm $OPENWRT_DIR/tools/mkimage/patches/210-openssl-1.1.x-compat.patch 2>/dev/null
ln -s $PATCH_DIR/210-openssl-1.1.x-compat.patch $OPENWRT_DIR/tools/mkimage/patches/210-openssl-1.1.x-compat.patch
rm $OPENWRT_DIR/package/feeds/packages/freeradius2/patches/707-dreamcatcher-freeradius2-fix-openssl-1.1.x-update.patch 2>/dev/null
ln -s $PATCH_DIR/707-dreamcatcher-freeradius2-fix-openssl-1.1.x-update.patch $OPENWRT_DIR/package/feeds/packages/freeradius2/patches/707-dreamcatcher-freeradius2-fix-openssl-1.1.x-update.patch

# patch the iptables/xtables makefiles so it builds and includes the mdns module
pushd $OPENWRT_DIR
git apply $PATCH_DIR/mdns_makefiles.patch
popd

# weird download error -- can't find a particular version of the ca-certificates package on any mirror? Weird.
# patch the Makefile to retrieve a ~5 day older version
pushd $OPENWRT_DIR
git apply $PATCH_DIR/ca-certificates_old_version.patch
#cp $CONFIG_DIR/ca-certificates_updated.Makefile $OPENWRT_DIR/package/system/ca-certificates/
popd



#### CONFIG ####
# use our config file diff with everything we need in it
# (Note: you can manually edit this configuration by cd'ing to the openwrt/
#  directory and running 'make menuconfig')
echo "Updating OpenWRT build config file..."
rm $OPENWRT_DIR/.config 2>/dev/null
pushd $OPENWRT_DIR
make defconfig
if [ "$VM" != "1" ] ; then
	cat $CONFIG_DIR/development.diff >> $OPENWRT_DIR/.config
else
	cat $CONFIG_DIR/x86_vm.diff >> $OPENWRT_DIR/.config
fi
#cat $CONFIG_DIR/dreamcatcher.diff >> $OPENWRT_DIR/.config
make defconfig
popd



#### MAKE ####
# make openwrt
echo "Building openwrt. This may take a while."
pushd $OPENWRT_DIR
#make # making with multiple threads often causes build to fail
make -j$(nproc)
_status=$?
popd

#### MESSAGES FOR USER ####
if [ "$_status" == "0" ] ; then
	image_path=$OPENWRT_DIR/bin/ar71xx/openwrt-ar71xx-generic-tl-wdr4300-v1-squashfs-factory.bin
	echo "Build complete. You can find your image at $image_path."
	sum=`md5sum $image_path | cut -f 1 -d " "`
	echo "The md5sum of your image is $sum."
	echo "After flashing, put CA at /root/CA/ and freeradius2 at /etc/freeradius2/"
	echo "and follow the other directions in the README file"
fi


