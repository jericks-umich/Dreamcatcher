#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <uci.h>

#include <main.h>
#include <config.h>
#include <logger.h>

#define TAG "CONFIG"

#define CONFIG_FILE "/etc/config/dreamcatcher"

void clean_config() {
  int fd;

  // lock the config file
  //fd = lock_open_config();
  //if (fd == -1) { // uh oh
  //  LOGW("Can't lock the config file");
  //}


  // read the config file
    // remove any temporary rules

}

// return fd if successful, -1 if failed
// block until we get a handle
int lock_open_config() {
  int fd;
  // open file to get file descriptor
  fd = open(CONFIG_FILE, O_RDWR);
  if (fd == -1){
    LOGW("Can't open config file.");
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
    LOGW("Locking config file failed.");
    return -1;
  } 
  // if it succeeds and we have a write lock
  return fd;
  // TODO: fix below
  // leave fd and fl global variables set for subsequent unlock call
}

int unlock_close_config() {
  int retval = 0;

  // update file lock
  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  // unlock file
  if (fcntl(fd, F_SETLKW, &fl) == -1) {
    LOGW("Error unlocking file.");
    retval = -1;
  }

  // close file descriptor
  close(fd);

  return retval;
}








