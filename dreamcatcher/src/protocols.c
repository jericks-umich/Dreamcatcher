#include <stddef.h>
#include <protocols.h>

char* get_protocol_string(protocol proto) {
  switch (proto) {
    case TCP:
      return "tcp";
    case UDP:
      return "udp";
    case ICMP:
      return "icmp";
  } 
  return NULL;
}
