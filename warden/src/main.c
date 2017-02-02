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
#include <curl/curl.h>

#include <main.h>
#include <logger.h>

#define TAG "MAIN"

//From Dreamcatcher
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

//Queue 1 VLAN Processing
void handle_packet(struct nfq_data *tb) {
    
    unsigned int vlan = get_src_vlan(tb);
    char vlan_s[5];
    
    FILE * fp;
    while(fp = fopen("/var/run/warden.vlan", "r")){
        fclose(fp);
        sleep(1);
    }
    fp = fopen("/var/run/warden.vlan", "w");
    
    snprintf(vlan_s, 5, "%d", vlan);
    fputs(vlan_s, fp);
    
    fclose(fp);
    
    return;
}

//Queue 2 VLAN Processing
void handle_packet2(struct nfq_data *tb) {
    
    unsigned int vlan = get_src_vlan(tb);
    char vlan_s[5];
    
    FILE * fp;
    while(fp = fopen("/var/run/warden.vlan2", "r")){
        fclose(fp);
        sleep(1);
    }
    fp = fopen("/var/run/warden.vlan2", "w");
    
    snprintf(vlan_s, 5, "%d", vlan);
    fputs(vlan_s, fp);
    
    fclose(fp);
    
    return;
}

//Queue 1 Callback
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    LOGV("Got callback!");
    int ret;
    int id;
    u_int32_t verdict = NF_ACCEPT;
    
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    } else {
        LOGW("Cannot parse packet. Not sure what to do!");
    }
    
    handle_packet(nfa);
    
    ret = nfq_set_verdict(qh, id, verdict, 0, NULL);
    return ret;
}

//Queue 2 Callback
int cb2(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    LOGV("Got callback 2!");
    int ret;
    int id;
    u_int32_t verdict = NF_ACCEPT;
    
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    } else {
        LOGW("Cannot parse packet. Not sure what to do!");
    }
    
    handle_packet(nfa);
    
    ret = nfq_set_verdict(qh, id, verdict, 0, NULL);
    return ret;
}

void * parentFunc(void *arg){

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    int ret;
    char buf[4096] __attribute__ ((aligned));
    
    
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

}

void *parentFunc2(void * arg){

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    int ret;
    char buf[4096] __attribute__ ((aligned));
    
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
    LOGV("binding this socket to queue '%d'", QUEUE_NUM2);
    qh = nfq_create_queue(h, QUEUE_NUM2, &cb2, NULL);
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
    LOGV("unbinding from queue %d", QUEUE_NUM2);
    nfq_destroy_queue(qh);
    LOGV("closing library handle");
    nfq_close(h);

}


int main(int argc, char **argv)
{

    pthread_t th1, th2;
    pthread_create(&th1, NULL, parentFunc, "");
    pthread_create(&th2, NULL, parentFunc2, "");

    pthread_join(th1, NULL);
    pthread_join(th2, NULL);
    
    exit(0);
}
