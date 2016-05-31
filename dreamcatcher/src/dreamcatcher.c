#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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
#include <dreamcatcher.h>

/* returns packet id */
u_int32_t orig_print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}

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
	printf("~~~ IPv4 HEADER: ~~~\n");
	printf("version:         %hhu\n", i->ip_v);
	printf("Header length:   %hhu\n", i->ip_hl);
	printf("TOS:             %hhu\n", i->ip_tos);
	printf("Total Length:    %hu\n", i->ip_len);
	printf("ID:              %hu\n", i->ip_id);

	printf("Fragment Offset: %hu\n", i->ip_off);
	printf("Time-to-Live:    %hhu\n", i->ip_ttl);
	printf("Protocol:        %hhu\n", i->ip_p);
	printf("Checksum:        %hu\n", i->ip_sum);
	printf("Source Address:  %s\n", inet_ntoa(i->ip_src));
	printf("Dest Address:    %s\n", inet_ntoa(i->ip_dst));

	// Do any Option header checking here
}

// Input: ip6_hdr* data structure to print
void print_ipv6(struct ip6_hdr* i)
{
	printf("IPv6 is not implemented yet (what else is new, lol)\n");
}

u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	int ret;
	u_int8_t proto = 0;
	unsigned char *data;
	struct ip* ip;
	struct ip6_hdr* ipv6;
	struct tcphdr* tcp;
	struct udphdr* udp;
	struct icmphdr* icmp;

	id = orig_print_pkt(tb); // print the original packet information

	/////////////
	// Layer 3 //
	/////////////
	ret = nfq_get_payload(tb, &data);
	if (ret < 0) {
		printf("empty packet. nothing to do here...\n");
		return id;
	}
	ip = (struct ip*) data;
	// check if ipv4 or ipv6
	switch (ip->ip_v) { // ip version
		case 4:
			//printf("IPv4 !\n");
			proto = ip->ip_p; // get protocol from ipv4 header
			data = data + (4 * ip->ip_hl); // increment data pointer to next header
			print_ipv4(ip);
			break;
		case 6:
			//printf("IPv6 !\n");
			ipv6 = (struct ip6_hdr*) data;
			proto = -1; // TODO: find protocol in ipv6 header
			data = data + (4 * 0); // TODO: find end of ipv6 header and advance data to next header
			print_ipv6(ipv6); // side-effect, increments data to layer 4
			break;
		default:
			printf("Unknown Layer 3 protocol: %hhu. Not handled.\n",ip->ip_v);
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
			printf("Unknown protocol %hhu. Not handled.\n", proto);
	}

	return id;
}

void print_tcp(struct tcphdr* t) {
	char flags[24]; // flags string
	flags[0] = '\0';
	// print out tcp header
	printf("~~~ TCP HEADER: ~~~\n");
	printf("Source Port:     %hu\n", t->th_sport);
	printf("Dest Port:       %hu\n", t->th_dport);
	printf("Sequence num:    %u\n", t->th_seq);
	printf("Acknowledge num: %u\n", t->th_ack);
	printf("Data offset:     %hhu\n", t->th_off);
	printf("Reserved:        %hhu\n", t->th_x2);
	if (t->th_flags & TH_URG)
		strcat(flags, "URG ");
	else
		strcat(flags, " -  ");
	if (t->th_flags & TH_ACK)
		strcat(flags, "ACK ");
	else
		strcat(flags, " -  ");
	if (t->th_flags & TH_PUSH)
		strcat(flags, "PSH ");
	else
		strcat(flags, " -  ");
	if (t->th_flags & TH_RST)
		strcat(flags, "RST ");
	else
		strcat(flags, " -  ");
	if (t->th_flags & TH_SYN)
		strcat(flags, "SYN ");
	else
		strcat(flags, " -  ");
	if (t->th_flags & TH_FIN)
		strcat(flags, "FIN");
	else
		strcat(flags, " - ");
	printf("Flags:           %s\n", flags);
	printf("Window size:     %hu\n", t->th_win);
	printf("Checksum         %hu\n", t->th_sum);
	printf("Urgent pointer   0x%hx\n", t->th_urp);

	// Do any Option header checking here

	return;
}

void print_udp(struct udphdr* u) {
	printf("~~~ UDP HEADER: ~~~\n");
	printf("Source Port:     %hu\n", u->uh_sport);
	printf("Dest Port:       %hu\n", u->uh_dport);
	printf("Length:          %hu\n", u->uh_ulen);
	printf("Checksum:        %hu\n", u->uh_sum);
}

void print_icmp(struct icmphdr* i) {
	printf("~~~ ICMP HEADER: ~~~\n");
	printf("Message type:    %hhu\n", i->type);
	printf("Message code:    %hhu\n", i->code);
	printf("Checksum:        %hhu\n", i->checksum);
	printf("Rest of header:  0x%x\n", (unsigned int)i->un.gateway); // just grabbing any union field
}

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	char response;
	u_int32_t id = print_pkt(nfa);
	printf("ACCEPT (Yy) or REJECT (Nn) this packet [Y/n]: ");
	fflush(stdout);
	scanf("%c", &response);
	if (response == 'n' || response == 'N') {
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '%d'\n", QUEUE_NUM);
	qh = nfq_create_queue(h, QUEUE_NUM, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
		printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue %d\n", QUEUE_NUM);
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
