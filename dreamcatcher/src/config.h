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
 config temp_rule
   option src 11
   option dst 10
   option proto tcp
   option dst_port 80
   option verdict REJECT
*/
typedef struct temp_rule {
  unsigned int src_vlan;
  unsigned int dst_vlan;
  protocol proto;
  char src_ip[16];
  char dst_ip[16];
  unsigned int src_port;
  unsigned int dst_port;
  verdict target;
} temp_rule;

char* get_verdict_string(verdict v);
void print_uci_ptr(struct uci_ptr* p);
int write_rule(temp_rule rule);
void clean_config();
int lock_open_config();
int unlock_close_config();
void rule_uci_set_int(struct uci_context *ctx, const char* option, const unsigned int value);
void rule_uci_set_str(struct uci_context *ctx, const char* option, const char* value);


#endif // DREAMCATCHER_CONFIG_H
