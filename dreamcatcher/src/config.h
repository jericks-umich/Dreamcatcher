#ifndef DREAMCATCHER_CONFIG_H
#define DREAMCATCHER_CONFIG_H

#include <fcntl.h>

#include <protocols.h>

void clean_config();
int lock_open_config();
int unlock_close_config();

typedef enum {
  ACCEPT,
  DROP,
  REJECT,
} verdict;

/*
 config temp_rule
   option name "Block http from user 11 to user 10"
   option src 11
   option dst 10
   option proto tcp
   option dst_port 80
   option verdict REJECT
*/
typedef struct {
  unsigned int src_vlan;
  unsigned int dst_vlan;
  protocol proto;
  unsigned int src_port;
  unsigned int dst_port;
  verdict target;
} temp_rule;



#endif // DREAMCATCHER_CONFIG_H
