#ifndef DREAMCATCHER_CONFIG_H
#define DREAMCATCHER_CONFIG_H

#include <fcntl.h>
#include <pthread.h>

#include <uci.h>

#include <main.h>
#include <protocols.h>


typedef enum {
  UNSPEC,
  ACCEPT,
  DROP,
  REJECT,
} verdict;

/* EXAMPLE RULE
 config rule
   option type 0
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
"%s wants to send messages to %s" % (src_vlan, dst_vlan)
1.
"%s wants to broadcast messages to your network" % (src_vlan)
2. 
"%s wants to look for a device named %s" % (src_vlan, mdns_device)
3.
"%s wants to advertise itself on your network as %s" % (src_vlan, mdns_device)
4.
"%s wants to advertise itself to %s as %s" % (src_vlan, dst_vlan, mdns_device)
*/

typedef enum {
  UNICAST,
  BROADCAST,
  DISCOVER,
  ADVERTISE,
} message_type;

#define DEVICE_NAME_SIZE 128
#define IP_ADDR_LEN 16

typedef struct rule {
  char hash[33]; // 32 hex chars plus '\0'
  char message[128]; // not in use anymore
  message_type type;
  unsigned int src_vlan;
  unsigned int dst_vlan;
  protocol proto;
  char src_ip[IP_ADDR_LEN];
  char dst_ip[IP_ADDR_LEN];
  unsigned int src_port;
  unsigned int dst_port;
  verdict target;
  // mDNS params
  char device_name[DEVICE_NAME_SIZE];
  // rule will also have a default 'option approved 0' appended, 
  // meaning the rule has not been approved by the user yet
  
} rule;

#define RULE_QUEUE_SIZE 128
rule* rule_queue;
pthread_mutex_t* lock;
rule* start; // point to places in rule_queue
rule* end; // point to places in rule_queue

void set_message(rule* r);
char* get_verdict_string(verdict v);
void hash_rule(rule* r);
void print_uci_ptr(struct uci_ptr* p);
void print_sections(struct uci_package* pkg);
int write_rule(rule* r);

int rule_exists(struct uci_context* ctx, const char* hash);
void add_new_named_rule_section(struct uci_context* ctx, const char* hash, int dpi_rule);
void rule_uci_set_int(struct uci_context* ctx, const char* hash, const char* option, const unsigned int value);
void rule_uci_set_str(struct uci_context* ctx, const char* hash, const char* option, const char* value);

void get_dns_question_name(unsigned char* payload, char* buf);
int check_dpi_rule(rule* r, dns_header* dns, unsigned char* payload, u_int32_t* verdict);
int dpi_rule_exists(struct uci_context* ctx, const char* hash, u_int32_t* verdict);

int lock_open_config();
int unlock_close_config(int fd);

#endif // DREAMCATCHER_CONFIG_H
