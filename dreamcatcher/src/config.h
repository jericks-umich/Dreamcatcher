#ifndef DREAMCATCHER_CONFIG_H
#define DREAMCATCHER_CONFIG_H

#include <fcntl.h>

void clean_config();
int lock_open_config();
int lock_close_config();

// global vars
int fd;
struct flock fl;

#endif // DREAMCATCHER_CONFIG_H
