#include <stddef.h>
#include <protocols.h>
#include <logger.h>

#define TAG "PROTOCOLS"

char* get_protocol_string(protocol proto) {
  switch (proto) {
    case TCP:
      //LOGV("TCP");
      return "TCP";
    case UDP:
      //LOGV("UDP");
      return "UDP";
    case ICMP:
      //LOGV("ICMP");
      return "ICMP";
  } 
  return NULL;
}
