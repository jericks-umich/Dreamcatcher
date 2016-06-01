#ifndef DREAMCATCHER_CONFIG_H
#define DREAMCATCHER_CONFIG_H

#include <fcntl.h>

void clean_config();
void* monitor_config(void* threadid);

// global vars
int fd;
struct flock fl;

#endif // DREAMCATCHER_CONFIG_H
