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

#define QUEUE_NUM 4671

unsigned int get_src_vlan(struct nfq_data *tb);
void handle_packet(struct nfq_data *tb);
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
int main(int argc, char **argv);


#endif // DREAMCATCHER_H
