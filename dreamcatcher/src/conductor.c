#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <curl/curl.h>

#include <logger.h>
#include <config.h>
#include <protocols.h>
#include <conductor.h>

#define TAG "CONDUCTOR"

void* conduct(void* arg) {
  rule r;
  while(true) {
    if (pop_rule_from_queue(&r) != -1) {
      LOGD("Popped rule, sending message.");
      send_message(&r);
    } else {
      sleep(5);
    }
  }
}

void send_message(rule* r){
  char* hash = r->hash;
  char* message = r->message;
  protocol proto = r->proto;
  char* proto_string = get_protocol_string(proto);
  char* src_ip = r->src_ip;
  char* dst_ip = r->dst_ip;
  unsigned int src_port = r->src_port;
  unsigned int dst_port = r->dst_port;

  struct curl_slist* headers = NULL;
  char* key_header = "Authorization: key=AIzaSyCkzLOzVdzLj_FLh2Y2X2k4cKfRt0L8TsQ";
  char* target = "fuNfN3w646k:APA91bF09PmuCnUwPYK29-DMNHNdEUa92slZbxV-l3VOxDmRSbUWuwhTWqI95O4h-glR51yRzLhgEttblcgzxa_M4stgp8XMJtZt3TYPOHdudd-gaH4hZ7nEgUnw_IHKB0z61jpqKb1P";

  headers = curl_slist_append(headers,"Accept: application/json");
  headers = curl_slist_append(headers,"Content-Type:application/json");
  headers = curl_slist_append(headers,key_header);

  char jsonObj[1024];
  //TODO: router_ip and token need filling
  snprintf(jsonObj, sizeof(jsonObj), "{ \"data\": { \"id\" : %s, \"message\" : %s, \"proto\" : %s, \"src_ip\" : %s, \"dst_ip\" : %s, \"src_port\" : %d, \"dst_port\" : %d, \"token\" : \"\", \"router_ip\" : \"\", }, \"to\" : \"%s\" }", hash, message, proto_string, src_ip, dst_ip, src_port, dst_port, target);

  LOGD("message: %s", jsonObj);
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl,CURLOPT_URL,"https://gcm-http.googleapis.com/gcm/send");
  curl_easy_setopt(curl,CURLOPT_POSTFIELDS,jsonObj);
  curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
  curl_easy_perform(curl);
  curl_easy_cleanup(curl);
}
