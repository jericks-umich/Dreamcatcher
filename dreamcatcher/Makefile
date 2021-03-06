include $(TOPDIR)/rules.mk

PKG_NAME:=dreamcatcher
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

# debugging
TARGET_CFLAGS += -ggdb3

include $(INCLUDE_DIR)/package.mk

define Package/dreamcatcher
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Firewall
	TITLE:=Dreamcatcher intra-network filter
	DEPENDS:=+wpad +libnetfilter-queue +iptables-mod-nfqueue +kmod-ipt-nfqueue +iptables-mod-extra +kmod_ipt-extra +kmod-nfnetlink +kmod-nfnetlink-queue +libuci +freeradius2 +FREERADIUS_OPENSSL +freeradius2-common +freeradius2-mod-chap +freeradius2-mod-detail +freeradius2-mod-eap +freeradius2-mod-eap-mschapv2 +freeradius2-mod-eap-peap +freeradius2-mod-eap-tls +freeradius2-mod-eap-ttls +freeradius2-mod-exec +freeradius2-mod-files +freeradius2-mod-mschap +freeradius2-mod-pap +freeradius2-mod-passwd +freeradius2-mod-preprocess +freeradius2-mod-radutmp +freeradius2-utils +libopenssl +libcurl +libxtables +kmod-ipt-compat-xtables
endef

define Package/bridge/description
	Dreamcatcher utility for filtering bad packets on the local network.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

LDFLAGS += -Wl,-rpath-link=$(STAGING_DIR)/usr/lib -lnetfilter_queue -luci -lnfnetlink -lpthread -lssl -lcrypto -lcurl

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(LDFLAGS) -I$(PKG_BUILD_DIR) -o $(PKG_BUILD_DIR)/dreamcatcher \
		$(PKG_BUILD_DIR)/main.c \
		$(PKG_BUILD_DIR)/config.c \
		$(PKG_BUILD_DIR)/logger.c \
		$(PKG_BUILD_DIR)/protocols.c
endef

define Package/dreamcatcher/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/checkpoint.sh $(1)/usr/sbin/checkpoint
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/dreamcatcher.init $(1)/etc/init.d/dreamcatcher
	$(INSTALL_BIN) ./files/checkpoint.init $(1)/etc/init.d/checkpoint
	# HACK -- need to make the CA files persistent, and don't feel like modifying the freeradius package (too much work)
	# so we're going to do it here
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	$(INSTALL_BIN) ./files/freeradius2.keep $(1)/lib/upgrade/keep.d/freeradius2
endef

$(eval $(call BuildPackage,dreamcatcher))
