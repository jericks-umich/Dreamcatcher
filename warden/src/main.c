#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>

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
#include <json-c/json.h>

#include <main.h>
#include <logger.h>

#define TAG "MAIN"

int NUM_QUEUES;
int QUEUES[MAX_QUEUES];
const char * FILENAMES[MAX_QUEUES];
pthread_t thread_arr[MAX_QUEUES];
unsigned int last_vlan[MAX_QUEUES] = {0};

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

//VLAN Processing
void handle_packet(struct nfq_data *tb, char * filename, int index) {

	//Grab source vlan to store in file
	unsigned int vlan = get_src_vlan(tb);
	char vlan_s[5];
	
	FILE * fp;

	//If file exists
	if(fp = fopen(filename, "r")){
		fclose(fp);

		//If vlan matches, let packet through
		if(vlan == last_vlan[index]){
			return;
		}

		//If vlan doesn't match, wait and create new file
		else{
			//Busy wait while file exists
			int timer = 0;
			while(fp = fopen(filename, "r")){
			//if(fp = fopen(filename, "r")){
				fclose(fp);
				sleep(1);
				timer = timer + 1;
				if (timer > 3){
					remove(filename);
					break;
				}
			}

			//Once file has been deleted, recreate it
			sleep(1);
			fp = fopen(filename, "w");

			//Store source vlan in new file
			snprintf(vlan_s, 5, "%d", vlan);
			fputs(vlan_s, fp);

			//Close file
			fclose(fp);

			last_vlan[index] = vlan;
			return;
		}
	}
	//If file doesn't exist
	else{
		//If vlan doesn't match, sleep a second
		if(vlan != last_vlan[index]){
			sleep(1);
		}

		//Create file
		fp = fopen(filename, "w");

		//Store source vlan in a new file
		snprintf(vlan_s, 5, "%d", vlan);
		fputs(vlan_s, fp);

		//Close file
		fclose(fp);

		last_vlan[index] = vlan;
		return;

	}


}


//Callback
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	LOGV("Got callback!");
	int ret;
	int id;
	u_int32_t verdict = NF_ACCEPT;	
	char * filename;

	//Get queue_num from mark
	int queue_num = nfq_get_nfmark(nfa);
	
	//Search through QUEUES array to find index
	int index = -1;
	for (int i = 0; i < NUM_QUEUES; ++i){
		if(QUEUES[i] == queue_num){
			index = i;
			break;
		}
	}
	//Make sure matching entry was found
	if (index == -1){
		LOGW("Invalid queue num");
	}

	//Use index to find associated filename
	filename = FILENAMES[index];

	struct nfqnl_msg_packet_hdr * ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
		id = ntohl(ph->packet_id);
	} else {
		LOGW("Cannot parse packet. Not sure what to do!");
	}

	handle_packet(nfa, filename, index);

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
	int queue_num = (int)arg;

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
	LOGV("binding this socket to queue '%d'", queue_num);
	qh = nfq_create_queue(h, queue_num, &cb, NULL);
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
	LOGV("unbinding from queue %d", queue_num);
	nfq_destroy_queue(qh);
	LOGV("closing library handle");
	nfq_close(h);

}


int main(int argc, char **argv)
{
	//Read from initialization file
	static const char filename [] = "test.txt";
	FILE * fp;
	fp = fopen("test.txt", "r");
	char line[256];

	//Get NUM_QUEUES
	fgets(line, sizeof(line), fp);
	char * num_queues_string = strtok(line, " ");
	num_queues_string = strtok(NULL, " ");
	NUM_QUEUES = atoi(num_queues_string);

	//Read queue + filename pairs from file
	int index = 0;
	while(fgets(line, sizeof(line), fp)){ 
		
		char * read_string = strtok(line, " " );
		char * to_store = "";

		//Handle queue_num
		if(!strcmp(read_string, "queue_num:")){
			read_string = strtok(NULL, " " );
			QUEUES[index] = atoi(read_string);
		}

		//Handle filename
		else if(!strcmp(read_string, "filename:")){

			read_string = strtok(NULL, " ");

			//Needed to remove garbage characters at end
			read_string[strlen(read_string)-1] = '\0';

			FILENAMES[index] = (char*) malloc(100);
			strcpy(FILENAMES[index], read_string);

			//queue_num + filename pair done
			++index;
		}
	}

	//Threads aren't created until after array initialization 
	//to avoid race conditions
	for(int i = 0; i < NUM_QUEUES; ++i){ 
		pthread_t th;
		thread_arr[i] = th;
		pthread_create(&thread_arr[i], NULL, parentFunc, QUEUES[i]);
	}

	//Join child threads to parent thread
	for (int i = 0; i < NUM_QUEUES; ++i){
		pthread_join(thread_arr[i], NULL);
	}

	//Close file
	fclose(fp);
	
	//Free dynamically allocated memory
	for (int i = 0; i < NUM_QUEUES; ++i){
		free(FILENAMES[i]);
	}

	exit(0);
}
