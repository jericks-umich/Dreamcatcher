#include <conductor.h>

void* conduct(void* arg) {
  // TODO: 
  // Loop
    // Poll the config file for changes
      // If config file changes, for each change, send client a new message through GCM
    // Listen to Google Cloud Messaging service for updates
      // If GCM sends status update, update config file
    // sleep for ~ 5 seconds?

  //rule r;
  //pop_rule_from_queue(&r);
}

#include <conductor.h>
#include <config.h>
#include <protocols.h>
#include <curl/curl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void* conduct(void* arg) {
  // TODO: 
  // Loop
    // Poll the config file for changes
      // If config file changes, for each change, send client a new message through GCM
    // Listen to Google Cloud Messaging service for updates
      // If GCM sends status update, update config file
    // sleep for ~ 5 seconds?
  while(true){
  	send_message();
    sleep(5);
  }
}

void* send_message(){
	// TODO:
	// Get sender id and registration id from config file.
	rule r;
	if (pop_rule_from_queue(&r) != -1){
		char* hash = r.hash;
		char* message = r.message;
		protocol proto = r.proto;
		char* proto_string = get_protocol_string(proto);
		char* src_ip = r.src_ip;
		char* dst_ip = r.dst_ip;
		unsigned int src_port = r.src_port;
		unsigned int dst_port = r.dst_port;
		
		struct curl_slist *headers = NULL;
		char* key_header;
		key_header = malloc(100);
		char * auth_key = "AIzaSyCkzLOzVdzLj_FLh2Y2X2k4cKfRt0L8TsQ";
		char * target = "fv_V70tXDUo:APA91bHyOVeAW9FWMQjoU9ui1HELYuO5F1Eu1NDQrd8hNAZk0bXGQnZZxcU-riPNqskyySHdHRFK0h9-u5mVUqTRuhHByHo_stzngOXyPfH7DRIbpLix2A3hwHLPokPEAyYBkBOCoPUw";
		sprintf(key_header,"Authorization: key=%s",auth_key);
		headers = curl_slist_append(headers,"Accept: application/json");
		headers = curl_slist_append(headers,"Content-Type:application/json");
		headers = curl_slist_append(headers,key_header);

		char* jsonObj;
		jsonObj = malloc(1000);
		sprintf(jsonObj,
			"{\"data\": { \
				\"id\" : %s \
				\"message\" : %s, \
				\"proto\" : %s, \
				\"src_ip\" : %s, \
				\"dst_ip\" : %s, \
				\"src_port\" : %d, \
				\"dst_port\" : %d, \
				\"costom field\" : \"\" \
				\"token\" : \"\", \
				\"router_ip\" : \"\" \
			}, \
			\"to\" : \"%s\" \
		}", hash, message, proto_string, src_ip, dst_ip, src_port, dst_port, target);
		
		CURL *curl = curl_easy_init();
		curl_easy_setopt(curl,CURLOPT_URL,"https://gcm-http.googleapis.com/gcm/send");
		curl_easy_setopt(curl,CURLOPT_POSTFIELDS,jsonObj);
		curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		free(key_header);
		free(jsonObj);
	}
}
