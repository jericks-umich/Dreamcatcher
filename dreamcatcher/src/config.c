#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <uci.h>

#include <main.h>

#define CONFIG_FILE "/etc/config/dreamcatcher"

void clean_config() {
  // lock the config file

  // read the config file
    // remove any temporary rules

}

// return fd if successful, -1 if failed
// block until we get a handle
int lock_open_config() {
  // open file to get file descriptor
  fd = open(CONFIG_FILE, O_RDWR);
  if (fd == -1){
    return -1;
  }

  // acquire file lock
  fl.l_type = F_WRLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  // set a lock on the file and wait if it's already locked
  if (fcntl(fd, F_SETLKW, &fl) == -1) { // if the lock fails
    close(fd);
    return -1;
  } 
  // if it succeeds and we have a write lock
  return fd;
  // leave fd and fl global variables set for subsequent unlock call
}

int unlock_close_config() {
  int ret_val = 0;

  // update file lock
  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  // unlock file
  if (fcntl(fd, F_SETLKW, &fl) == -1) {
    printf("Error unlocking file.\n");
    retval = -1;
  }

  // close file descriptor
  close(fd);

  return retval;
}








