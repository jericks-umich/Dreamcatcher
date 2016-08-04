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

# Post-installation
You will need to copy over some configuration files to set up the freeradius2
RADIUS server, certificates, etc.
Use scp to copy freeradius2/ to /etc/freeradius2/ on the router, and CA/ to
/root/CA/ on the router.
Then, restart the RADIUS server with `/etc/init.d/radiusd restart`.

You will need to enable iptables to use the physdev module by changing
'net.bridge.bridge-nf-call-iptables=0' to '=1' in /etc/sysctl.conf.

You will need to edit /etc/config/firewall and add
'option DREAMCATCHER 1'
to the 'lan' zone to enable dreamcatcher support on your LAN.

You will need to configure the wireless networks. We have provided a sample
configuration at config/wireless that should be copied to /etc/config/wireless
on the router. This creates a test network named "TEST NETWORK DO NOT USE"
that connects to the radius server configured in /etc/freeradius2/.

You will need to put the Google Cloud Messaging Auth token and registration
id into /etc/config/gcm\_auth\_key and /etc/config/gcm\_reg\_id, respectively, for
push notifications to work.

In a future commit, we will want to automate this configuration and generate
new certificates, etc. during the install.


