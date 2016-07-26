#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <main.h>
#include <protocols.h>
#include <config.h>
#include <logger.h>
#include <conductor.h>

#define TAG "MAIN"

/* returns packet id */
void orig_print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;
  struct nlif_handle* h;
  char ifname_buf[16];
#define BUF_SIZE 1024
  char buf[BUF_SIZE];
  buf[0] = '\0';

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "%02x:", hwph->hw_addr[i]);
		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "indev=%u ", ifi);

  h = nlif_open();
  if (h == NULL) {
    LOGE("nlif_open");
    exit(1);
  }
  nlif_query(h);
	nfq_get_physindev_name(h, tb, ifname_buf);
  nlif_close(h);
  LOGV("indev name: %s", ifname_buf);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		snprintf(buf+strlen(buf), BUF_SIZE-strlen(buf), "payload_len=%d ", ret);

  LOGV(buf);

	return;
}

// TODO: this function is apparently unused now, delete?
void ip_to_bytes(unsigned char* buf, __be32 addr)
{
	buf[0] = addr && 0xff;
	buf[1] = (addr>>8) && 0xff;
	buf[2] = (addr>>16) && 0xff;
	buf[3] = (addr>>24) && 0xff;
}

// Input: ip* data structure to print
void print_ipv4(struct ip* i)
{
	// print out ip header info
	LOGV("~~~ IPv4 HEADER: ~~~");
	LOGV("version:         %hhu", i->ip_v);
	LOGV("Header length:   %hhu", i->ip_hl);
	LOGV("TOS:             %hhu", i->ip_tos);
	LOGV("Total Length:    %hu", i->ip_len);
	LOGV("ID:              %hu", i->ip_id);

	LOGV("Fragment Offset: %hu", i->ip_off);
	LOGV("Time-to-Live:    %hhu", i->ip_ttl);
	LOGV("Protocol:        %hhu", i->ip_p);
	LOGV("Checksum:        %hu", i->ip_sum);
	LOGV("Source Address:  %s", inet_ntoa(i->ip_src));
	LOGV("Dest Address:    %s", inet_ntoa(i->ip_dst));

	// Do any Option header checking here
}

// Input: ip6_hdr* data structure to print
void print_ipv6(struct ip6_hdr* i)
{
	LOGV("IPv6 is not implemented yet (what else is new, lol)");
}

unsigned int get_src_vlan(struct nfq_data *tb) {
  struct nlif_handle* h;
  char ifname_buf[16]; // IFNAMSIZ from linux kernel is 16
  char* vlan_ptr;
  h = nlif_open();
  if (h == NULL) {
    LOGW("nlif_open failed.");
    return (unsigned int) -1;
  }
  nlif_query(h);
	nfq_get_physindev_name(h, tb, ifname_buf);
  nlif_close(h);
  LOGV("indev name: %s", ifname_buf);
  strtok(ifname_buf, "."); // throw away the first pointer pointing to "wlanX" or another network prefix
  vlan_ptr = strtok(NULL, "."); // vlan_ptr points to the vlan id now
  LOGV("Attempting to convert string \"%s\" to integer", vlan_ptr);
  return (unsigned int) strtol(vlan_ptr, NULL, 10); // returns 0 if unable to convert to integer
}

unsigned int get_dst_vlan(struct nfq_data *tb) {
  struct nlif_handle* h;
  char ifname_buf[16]; // IFNAMSIZ from linux kernel is 16
  char* vlan_ptr;
  h = nlif_open();
  if (h == NULL) {
    LOGW("nlif_open failed.");
    return (unsigned int) -1;
  }
  nlif_query(h);
	nfq_get_physoutdev_name(h, tb, ifname_buf);
  nlif_close(h);
  LOGV("outdev name: %s", ifname_buf);
  strtok(ifname_buf, "."); // throw away the first pointer pointing to "wlanX" or another network prefix
  vlan_ptr = strtok(NULL, "."); // vlan_ptr points to the vlan id now
  LOGV("Attempting to convert string \"%s\" to integer", vlan_ptr);
  return (unsigned int) strtol(vlan_ptr, NULL, 10); // returns 0 if unable to convert to integer
}

void add_rule(struct nfq_data *tb) {
	int ret;
	protocol proto = 0;
	unsigned char *data;
	struct ip* ip;
	struct ip6_hdr* ipv6;
	struct tcphdr* tcp;
	struct udphdr* udp;
	struct icmphdr* icmp;
  
  rule new_rule;
  memset(&new_rule, 0, sizeof(new_rule)); // zero out all fields

  /////////////
  // Layer 2 //
  /////////////
  
  new_rule.src_vlan = get_src_vlan(tb);
  new_rule.dst_vlan = get_dst_vlan(tb);

	/////////////
	// Layer 3 //
	/////////////
	ret = nfq_get_payload(tb, &data);
	if (ret < 0) {
		LOGD("empty packet. nothing to do here...");
		return;
	}
	ip = (struct ip*) data;
	// check if ipv4 or ipv6
	switch (ip->ip_v) { // ip version
		case 4:
			proto = ip->ip_p; // get protocol from ipv4 header
			data = data + (4 * ip->ip_hl); // increment data pointer to next header
			//print_ipv4(ip);
			break;
		case 6:
			ipv6 = (struct ip6_hdr*) data;
			proto = -1; // TODO: find protocol in ipv6 header
			data = data + (4 * 0); // TODO: find end of ipv6 header and advance data to next header
			//print_ipv6(ipv6); // side-effect, increments data to layer 4
			break;
		default:
			LOGD("Unknown Layer 3 protocol: %hhu. Not handled.",ip->ip_v);
	}
	/////////////
	// Layer 4 //
	/////////////
	switch (proto) {
		case TCP :
			tcp = (struct tcphdr*) data;
      new_rule.proto = TCP;
      //new_rule.src_port = (unsigned int) tcp->th_sport;
      new_rule.dst_port = (unsigned int) tcp->th_dport;
			break;
		case UDP :
			udp = (struct udphdr*) data;
      new_rule.proto = UDP;
      //if (ip->ip_v == 4) {
      //  strncpy(new_rule.src_ip, inet_ntoa(ip->ip_src), sizeof(new_rule.src_ip));
      //}
      //new_rule.src_port = (unsigned int) udp->uh_sport;
      new_rule.dst_port = (unsigned int) udp->uh_dport;
			break;
		case ICMP : 
			icmp = (struct icmphdr*) data;
      new_rule.proto = ICMP;
			break;
			//case SCTP : // not implemented (yet?)
		default :
			LOGD("Unknown protocol %hhu. Not handled.", proto);
	}
  new_rule.target = REJECT;

  // logic to determine type of packet and how we want to handle it
  // TODO
  // default title type = 0
  new_rule.title = 0; // %s wants to communicate with %s
  set_message(&new_rule);

  // write the rule to the config file
  write_rule(&new_rule);

  // pass the new rule to conductor
  LOGD("Pushing the rule to the conductor's queue.");
  push_rule_to_queue(&new_rule);

	return;
}

void print_pkt (struct nfq_data *tb)
{
	int ret;
	protocol proto = 0;
	unsigned char *data;
	struct ip* ip;
	struct ip6_hdr* ipv6;
	struct tcphdr* tcp;
	struct udphdr* udp;
	struct icmphdr* icmp;

	orig_print_pkt(tb); // print the original packet information

	/////////////
	// Layer 3 //
	/////////////
	ret = nfq_get_payload(tb, &data);
	if (ret < 0) {
		LOGD("empty packet. nothing to do here...");
		return;
	}
	ip = (struct ip*) data;
	// check if ipv4 or ipv6
	switch (ip->ip_v) { // ip version
		case 4:
			proto = ip->ip_p; // get protocol from ipv4 header
			data = data + (4 * ip->ip_hl); // increment data pointer to next header
			print_ipv4(ip);
			break;
		case 6:
			ipv6 = (struct ip6_hdr*) data;
			proto = -1; // TODO: find protocol in ipv6 header
			data = data + (4 * 0); // TODO: find end of ipv6 header and advance data to next header
			print_ipv6(ipv6); // side-effect, increments data to layer 4
			break;
		default:
			LOGD("Unknown Layer 3 protocol: %hhu. Not handled.",ip->ip_v);
	}

	/////////////
	// Layer 4 //
	/////////////
	switch (proto) {
		case TCP :
			tcp = (struct tcphdr*) data;
			print_tcp(tcp);
			break;
		case UDP :
			udp = (struct udphdr*) data;
			print_udp(udp);
			break;
		case ICMP : 
			icmp = (struct icmphdr*) data;
			print_icmp(icmp);
			break;
			//case SCTP : // not implemented (yet?)
		default :
			LOGD("Unknown protocol %hhu. Not handled.", proto);
	}

	return;
}

void print_tcp(struct tcphdr* t) {
	char flags[24]; // flags string
	flags[0] = '\0';
	// print out tcp header
	LOGV("~~~ TCP HEADER: ~~~");
	LOGV("Source Port:     %hu", t->th_sport);
	LOGV("Dest Port:       %hu", t->th_dport);
	LOGV("Sequence num:    %u", t->th_seq);
	LOGV("Acknowledge num: %u", t->th_ack);
	LOGV("Data offset:     %hhu", t->th_off);
	LOGV("Reserved:        %hhu", t->th_x2);
	if (t->th_flags & TH_URG)  { strcat(flags, "URG "); } else { strcat(flags, " -  "); }
	if (t->th_flags & TH_ACK)  { strcat(flags, "ACK "); } else { strcat(flags, " -  "); }
	if (t->th_flags & TH_PUSH) { strcat(flags, "PSH "); } else { strcat(flags, " -  "); }
	if (t->th_flags & TH_RST)  { strcat(flags, "RST "); } else { strcat(flags, " -  "); }
	if (t->th_flags & TH_SYN)  { strcat(flags, "SYN "); } else { strcat(flags, " -  "); }
	if (t->th_flags & TH_FIN)  { strcat(flags, "FIN" ); } else { strcat(flags, " - "); }
	LOGV("Flags:           %s", flags);
	LOGV("Window size:     %hu", t->th_win);
	LOGV("Checksum         %hu", t->th_sum);
	LOGV("Urgent pointer   0x%hx", t->th_urp);

	// Do any Option header checking here

	return;
}

void print_udp(struct udphdr* u) {
	LOGV("~~~ UDP HEADER: ~~~");
	LOGV("Source Port:     %hu", u->uh_sport);
	LOGV("Dest Port:       %hu", u->uh_dport);
	LOGV("Length:          %hu", u->uh_ulen);
	LOGV("Checksum:        %hu", u->uh_sum);
}

void print_icmp(struct icmphdr* i) {
	LOGV("~~~ ICMP HEADER: ~~~");
	LOGV("Message type:    %hhu", i->type);
	LOGV("Message code:    %hhu", i->code);
	LOGV("Checksum:        %hhu", i->checksum);
	LOGV("Rest of header:  0x%x", (unsigned int)i->un.gateway); // just grabbing any union field
}

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
  LOGV("Got callback!");
  int ret;
  int id;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
  } else {
    LOGW("Cannot parse packet. Not sure what to do!");
  }
  ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
  LOGD("Set DROP verdict. Return value: %d", ret);
  print_pkt(nfa);
  add_rule(nfa);
  reload_firewall();
  return ret;
}

void reload_firewall() {
  int ret;
  printf("Reloading the firewall.\n");
  ret = system("/sbin/fw3 reload-dreamcatcher");
  if (ret != 0) {
    printf("Error in reloading the firewall: %d", ret);
  }
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
  pthread_t conductor_thread;

  // clear out any previous temporary rules -- we don't have state for them anymore -- need to recreate them if we want them again
  //clean_config();
  // reload firewall
  //reload_firewall();

  // initialize rule_queue
  initialize_rule_queue();
  // create new thread for conducting new rules to google/client application
  rv = pthread_create(&conductor_thread, NULL, &conduct, NULL);

  // create handle to nfqueue and watch for new packets to handle
	LOGV("opening library handle");
	h = nfq_open();
	if (!h) {
		LOGE("error during nfq_open()");
		exit(1);
	}
	LOGV("unbinding existing nf_queue handler for AF_INET (if any)");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		LOGE("error during nfq_unbind_pf()");
		exit(1);
	}
	LOGV("binding nfnetlink_queue as nf_queue handler for AF_INET");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		LOGE("error during nfq_bind_pf()");
		exit(1);
	}
	LOGV("binding this socket to queue '%d'", QUEUE_NUM);
	qh = nfq_create_queue(h, QUEUE_NUM, &cb, NULL);
	if (!qh) {
		LOGE("error during nfq_create_queue()");
		exit(1);
	}
	LOGV("setting copy_packet mode");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		LOGE("can't set packet_copy mode");
		exit(1);
	}
	fd = nfq_fd(h);
	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		LOGV("pkt received");
		nfq_handle_packet(h, buf, rv);
	}
  LOGD("Quitting because we received %d: %s", rv, strerror(errno));
	LOGV("unbinding from queue %d", QUEUE_NUM);
	nfq_destroy_queue(qh);
	LOGV("closing library handle");
	nfq_close(h);

  // TODO: do some signal handling to detect early close
  pthread_cancel(conductor_thread);
  free(rule_queue);

	exit(0);
}
