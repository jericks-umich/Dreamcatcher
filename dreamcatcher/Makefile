include $(TOPDIR)/rules.mk

PKG_NAME:=dreamcatcher
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/dreamcatcher
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Firewall
	TITLE:=Dreamcatcher intra-network filter
	DEPENDS:=+libnetfilter-queue +iptables-mod-nfqueue +kmod-ipt-nfqueue +kmod-nfnetlink-queue +libuci
endef

define Package/bridge/description
	Dreamcatcher utility for filtering bad packets on the local network.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

LDFLAGS += -Wl,-rpath-link=$(STAGING_DIR)/usr/lib -lnetfilter_queue -luci

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(LDFLAGS) -I$(PKG_BUILD_DIR) -o $(PKG_BUILD_DIR)/dreamcatcher \
		$(PKG_BUILD_DIR)/main.c \
		$(PKG_BUILD_DIR)/config.c \
		$(PKG_BUILD_DIR)/logger.c
endef

define Package/dreamcatcher/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,dreamcatcher))
