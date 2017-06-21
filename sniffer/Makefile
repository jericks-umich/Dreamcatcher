include $(TOPDIR)/rules.mk

PKG_NAME:=sniffer
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

# debugging
TARGET_CFLAGS += -ggdb3

include $(INCLUDE_DIR)/package.mk

define Package/sniffer
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Firewall
	TITLE:=Sniffer machine-learning firewall
	DEPENDS:=+libnetfilter-queue +iptables-mod-nfqueue +kmod-ipt-nfqueue +iptables-mod-extra +kmod_ipt-extra +kmod-nfnetlink +kmod-nfnetlink-queue +python +python-pip
endef

define Package/bridge/description
	Sniffer tool for machine-learning and network defense
endef

define Package/sniffer/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./src/sniffer.py $(1)/usr/sbin/sniffer.py
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/sniffer.init $(1)/etc/init.d/sniffer
endef

$(eval $(call BuildPackage,sniffer))
