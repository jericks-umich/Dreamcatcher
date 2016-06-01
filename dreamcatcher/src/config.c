#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <fcntl.h>

#include <uci.h>

#include <main.h>

#define CONFIG_FILE "/etc/config/dreamcatcher"

void clean_config() {
  // lock the config file

  // read the config file
    // remove any temporary rules

}

// monitor thread runs here
void* monitor_config(void* threadid) {
  int quit_val = 0;
  int ret;
  while (1) { // loop forever
    // check whether we should quit
    printf("monitor thread: checking whether we should exit\n");
    ret = pthread_mutex_trylock(&thread_quit_lock); // try to get lock
    if (ret == 0) { // if we acquire lock
      quit_val = thread_quit; // create local copy of value so we can release lock ASAP
      pthread_mutex_unlock(&thread_quit_lock); // release lock
      if (quit_val != 0) {
        printf("monitor thread: got exit signal. exiting.\n");
        pthread_exit(NULL);
      }
    }

    printf("monitor thread: checking the config file\n");
    // lock the config file

    // read the config file
      // look for permanent rules with IDs (these need to be updated (remove ID) and their packets released)

    // if change made, reload firewall

    sleep(1); // sleep so we aren't spinning ridiculously fast
  }
  pthread_exit(NULL);
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








