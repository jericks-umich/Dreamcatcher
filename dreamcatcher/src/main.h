#ifndef DREAMCATCHER_H
#define DREAMCATCHER_H

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <protocols.h>

#define QUEUE_NUM 4670

// creating my own struct for the dns header because I can't find a good standard one
// http://www.networksorcery.com/enp/protocol/dns.htm
typedef struct dns_header {
  u_int16_t id;
  // flags
  //u_int16_t flags;
  u_int16_t qr:1,     // Query/Response (0 is query, 1 response)
            opcode:4, // Opcode
            aa:1,     // Authoritative Answer
            tc:1,     // Truncated
            rd:1,     // Recursion Desired
            ra:1,     // Recursion Available
            z:1,      //  ... my reference didn't specify what this was for
            ad:1,     // Authenticated Data
            cd:1,     // Checking Disabled
            rcode:4;  // Return Code
  u_int16_t questions;
  u_int16_t answer_rr;
  u_int16_t authority_rr;
  u_int16_t additional_rr;
} dns_header;

void orig_print_pkt (struct nfq_data *tb);
void ip_to_bytes(unsigned char* buf, __be32 addr);
void print_ipv4(struct ip* i);
void print_ipv6(struct ip6_hdr* i);
unsigned int get_src_vlan(struct nfq_data *tb);
unsigned int get_dst_vlan(struct nfq_data *tb);
void print_dns(dns_header* d);
int add_rule(struct nfq_data *tb, u_int32_t* verdict);
void print_pkt (struct nfq_data *tb);
void reload_firewall();
void print_tcp(struct tcphdr* t);
void print_udp(struct udphdr* u);
void print_icmp(struct icmphdr* i);
void alert_user();
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
int main(int argc, char **argv);


#endif // DREAMCATCHER_H
