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
endef

define Package/bridge/description
	Dreamcatcher utility for filtering bad packets on the local network.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/dreamcatcher $(PKG_BUILD_DIR)/dreamcatcher.c
endef

define Package/dreamcatcher/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/$(PKG_NAME) $(1)/usr/sbin/
endef

$(eval $(call BuildPackage,dreamcatcher))