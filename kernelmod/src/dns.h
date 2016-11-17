#ifndef DNS_H
#define DNS_H

// creating my own struct for the dns header because I can't find a good standard one
// http://www.networksorcery.com/enp/protocol/dns.htm
typedef struct dns_header {
  __u16 id;
  // flags
  //u_int16_t flags;
  __u16 qr:1,     // Query/Response (0 is query, 1 response)
        opcode:4, // Opcode
        aa:1,     // Authoritative Answer
        tc:1,     // Truncated
        rd:1,     // Recursion Desired
        ra:1,     // Recursion Available
        z:1,      //  ... my reference didn't specify what this was for
        ad:1,     // Authenticated Data
        cd:1,     // Checking Disabled
        rcode:4;  // Return Code
  __u16 questions;
  __u16 answer_rr;
  __u16 authority_rr;
  __u16 additional_rr;
} dns_header;

typedef enum {
  A = 1,
  PTR = 12,
  TXT = 16, 
  AAAA = 28,
  SRV = 33
} dns_type;

#endif // DNS_H
