#ifndef DREAMCATCHER_CONFIG_H
#define DREAMCATCHER_CONFIG_H

#include <fcntl.h>

#include <uci.h>

#include <protocols.h>


typedef enum {
  ACCEPT,
  DROP,
  REJECT,
} verdict;

/* EXAMPLE RULE
 config rule
   option title 0
   option src_vlan 10
   option dst_vlan 11
   option proto tcp
   option src_ip 192.168.1.2
   option dst_ip 192.168.1.3
   option src_port 46264
   option dst_port 80
   option verdict ACCEPT
   option approved 0
*/

/*
0.
"%s wants to communicate with %s" % (src_vlan, dst_vlan)

1.
"%s wants to discover devices on your network" % (src_vlan)

2.
"%s wants to tell other devices on your network about itself" % (src_vlan)

3.
"%s wants to broadcast to your network" % (src_vlan)
*/
typedef enum {
  DIRECT,
  DISCOVER,
  ADVERTISE,
  BROADCAST,
} message_type;

typedef struct rule {
  char hash[33]; // 32 hex chars plus '\0'
  char message[128];
  message_type title;
  unsigned int src_vlan;
  unsigned int dst_vlan;
  protocol proto;
  char src_ip[16];
  char dst_ip[16];
  unsigned int src_port;
  unsigned int dst_port;
  verdict target;
  // rule will also have a default 'option approved 0' appended, 
  // meaning the rule has not been approved by the user yet
} rule;

void set_message(rule* r);
char* get_verdict_string(verdict v);
void hash_rule(rule* r);
void print_uci_ptr(struct uci_ptr* p);
int write_rule(rule* r);
void clean_config();
int lock_open_config();
int unlock_close_config();
void add_new_named_rule_section(struct uci_context *ctx, const char* hash);
void rule_uci_set_int(struct uci_context *ctx, const char* hash, const char* option, const unsigned int value);
void rule_uci_set_str(struct uci_context *ctx, const char* hash, const char* option, const char* value);


#endif // DREAMCATCHER_CONFIG_H
