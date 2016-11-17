#ifndef _LINUX_NETFILTER_XT_MDNS_H
#define _LINUX_NETFILTER_XT_MDNS_H

#include "dns.h"

#define DEVICE_NAME_SIZE 128

enum {
  XT_MDNS_TYPE_DISCOVERY,
  XT_MDNS_TYPE_ADVERTISEMENT,
};

// maximum number of mDNS names that can be associated with a device
#define XT_MDNS_MAX_NAMES 16
// maximum number of characters that can be used for a name
#define XT_MDNS_MAX_NAME_SIZE 256

struct xt_mdns_mtinfo {
  __u8 type;
  char names[XT_MDNS_MAX_NAMES][XT_MDNS_MAX_NAME_SIZE];
};

bool device_name_approved(const struct xt_mdns_mtinfo* info, char* device_name);
bool advertisement_match(const struct xt_mdns_mtinfo* info, const struct dns_header* dns, unsigned char* dns_raw);
unsigned int read_dns_name(unsigned char* payload, unsigned char* start, char* buf);
unsigned char* skip_question(unsigned char* p);

#endif // _LINUX_NETFILTER_XT_MDNS_H 
