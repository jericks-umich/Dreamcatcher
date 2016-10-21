#ifndef _LINUX_NETFILTER_XT_MDNS_H
#define _LINUX_NETFILTER_XT_MDNS_H

enum {
  XT_MDNS_TYPE_DISCOVERY,
  XT_MDNS_TYPE_ADVERTISEMENT,
};

// TODO: find if there are actual numbers for this in the mDNS spec
// maximum number of mDNS names that can be associated with a device
#define XT_MDNS_MAX_NAMES 16
// maximum number of characters that can be used for a name
#define XT_MDNS_MAX_NAME_SIZE 64

struct xt_mdns_mtinfo {
  __u8 type;
  char names[XT_MDNS_MAX_NAMES][XT_MDNS_MAX_NAME_SIZE];
};

#endif // _LINUX_NETFILTER_XT_MDNS_H 
