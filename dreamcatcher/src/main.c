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

void print_dns(dns_header* d) {
  LOGV("Printing dns packet.");
  LOGV("id: %u", d->id);
  //LOGV("qr: %u", (d->flags & (1 << 15)) >> 15);
  //LOGV("opcode: %u", (d->flags & (15 << 11)) >> 11);
  //LOGV("aa: %u", (d->flags & (1 << 10)) >> 10);
  //LOGV("tc: %u", (d->flags & (1 << 9)) >> 9);
  //LOGV("rd: %u", (d->flags & (1 << 8)) >> 8);
  //LOGV("ra: %u", (d->flags & (1 << 7)) >> 7);
  //LOGV("z: %u", (d->flags & (1 << 6)) >> 6);
  //LOGV("ad: %u", (d->flags & (1 << 5)) >> 5);
  //LOGV("cd: %u", (d->flags & (1 << 4)) >> 4);
  //LOGV("rcode: %u", d->flags & 16);
  LOGV("qr: %u", d->qr);
  LOGV("opcode: %u", d->opcode);
  LOGV("aa: %u", d->aa);
  LOGV("tc: %u", d->tc);
  LOGV("rd: %u", d->rd);
  LOGV("ra: %u", d->ra);
  LOGV("z: %u", d->z);
  LOGV("ad: %u", d->ad);
  LOGV("cd: %u", d->cd);
  LOGV("rcode: %u", d->rcode);
  LOGV("questions: %u", d->questions);
  LOGV("answer_rr: %u", d->answer_rr);
  LOGV("authority_rr: %u", d->authority_rr);
  LOGV("additional_rr: %u", d->additional_rr);
}

// returns 0 on new (non-dpi_)rule added, -1 if new rule not added, (and 1 if a dpi_rule was added)
int add_rule(struct nfq_data *tb, u_int32_t* verdict) {
	int ret;
  int dpi_rule_exists;
	protocol proto = 0;
	unsigned char *data;
	struct ip* ip;
	struct ip6_hdr* ipv6;
	struct tcphdr* tcp;
	struct udphdr* udp;
	struct icmphdr* icmp;
  dns_header* dns;
  
  rule new_rule;
  memset(&new_rule, 0, sizeof(new_rule)); // zero out all fields

  // logic to determine type of packet and how we want to handle it
  // default type = UNICAST
  // this will get reassigned to another type if the packet meets certain conditions
  new_rule.type = UNICAST; // %s wants to communicate with %s

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
		return -1;
	}
	ip = (struct ip*) data;
	// check if ipv4 or ipv6
	switch (ip->ip_v) { // ip version
		case 4:
			proto = ip->ip_p; // get protocol from ipv4 header
			data = data + (4 * ip->ip_hl); // increment data pointer to layer 4 header
			//print_ipv4(ip);
			break;
		case 6:
      // ipv6 is disabled in the build, so this should never happen
			ipv6 = (struct ip6_hdr*) data;
			proto = -1; // TODO: find protocol in ipv6 header
			data = data + (4 * 0); // TODO: find end of ipv6 header and advance data to next header
			//print_ipv6(ipv6); // side-effect, increments data to layer 4
			break;
		default:
			LOGD("Unknown Layer 3 protocol: %hhu. Not handled.",ip->ip_v);
	}

  // Check if BROADCAST traffic
  // TODO: make this flexible so it works if network is not a /24
  if ((ip->ip_dst.s_addr & 255) == 255) { // if last octet is .255
    new_rule.type = BROADCAST; // set type to broadcast
    strncpy(new_rule.dst_ip, inet_ntoa(ip->ip_dst), sizeof(new_rule.dst_ip)); // add filter based on ip address
    new_rule.dst_vlan = 0; // unset dst_vlan so that one rule manages packets that can be allowed/blocked from any device
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
      data = data + sizeof(*udp); // UDP header is always 8 bytes
      new_rule.proto = UDP;
      //if (ip->ip_v == 4) {
      //  strncpy(new_rule.src_ip, inet_ntoa(ip->ip_src), sizeof(new_rule.src_ip));
      //}
      //new_rule.src_port = (unsigned int) udp->uh_sport;
      new_rule.dst_port = (unsigned int) udp->uh_dport;
      
      // Check if mDNS/link-local traffic
      if ((new_rule.dst_port == 5353)) {
        new_rule.dst_vlan = 0; // remove dst_vlan since we allow link-local traffic to be multicast or unicast the same way
        dns = (dns_header*) data;
        data = data + sizeof(*dns); // data now points at the start of questions variable-length field
        print_dns(dns);
        // check if DISCOVER or ADVERTISE traffic (Query/Response bit is first bit of 3rd byte in payload)
        if (dns->qr == 0) { // DISCOVER
          new_rule.type = DISCOVER;
        } else { // ADVERTISE
          new_rule.type = ADVERTISE;
        }
        // check against existing dpi_rule set for ALLOW/BLOCK verdict
        dpi_rule_exists = check_dpi_rule(&new_rule, dns, data, verdict);
        // if dpi_rule already exists
          // verdict already set above in check_dpi_rule()
          // return early without creating a new rule
        if (dpi_rule_exists) {
          return -1; // no new rule added
        }
        // else
          // proceed to create new rule (do nothing)
      }
			break;
		case ICMP : 
			icmp = (struct icmphdr*) data;
      new_rule.proto = ICMP;
			break;
			//case SCTP : // not implemented (yet?)
		default :
			LOGD("Unknown protocol %hhu. Not handled.", proto);
      return -1; // don't add a new rule, but still block this packet
	}

  // set new_rule.target to REJECT by default if we're making a new rule
  new_rule.target = REJECT;

  // we're not setting the message anymore
  //set_message(&new_rule);

  // write the rule to the config file
  ret = write_rule(&new_rule);
  if (ret == 0) { // if success
    // pass the new rule to conductor
    LOGD("Pushing the rule to the conductor's queue.");
    push_rule_to_queue(&new_rule);
  } else {
    LOGD("Could not write rule to the config file.");
  }
  
  if (ret == 0 && new_rule.type >= DISCOVER) { // if this is a dpi_rule, 
    ret = 1; // don't reload firewall rules, since iptables doesn't handle dpi rules
  }

	return ret;
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
  u_int32_t verdict = NF_DROP;
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
  } else {
    LOGW("Cannot parse packet. Not sure what to do!");
  }
  print_pkt(nfa);
  ret = add_rule(nfa, &verdict); // may change verdict to NF_ACCEPT in some cases, otherwise default NF_DROP
  if (ret == 0) { // if there is a new (non-dpi_)rule added
    reload_firewall();
  }
  ret = nfq_set_verdict(qh, id, verdict, 0, NULL);
  LOGD("Set %d verdict(%d is ACCEPT, %d is DROP). Return value: %d", verdict, NF_ACCEPT, NF_DROP, ret);
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
  int ret;
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
		ret = nfq_handle_packet(h, buf, rv);
    LOGV("nfq_handle_packet returns %d", ret);
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
