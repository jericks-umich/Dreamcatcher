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
  int ret;
  int fd;
  int tries = 0;
#define MAX_TRIES 3
  struct uci_context* ctx;
  struct uci_package* pkg;
  struct uci_section* temp_rule_section;
  struct uci_element* rule_ptr;
  unsigned int rule_count = 0;
  struct uci_ptr ptr;
  char* ptr_string;

  // lock the config file
  LOGV("Locking config file");
  fd = -1;
  for (tries = 0; fd == -1 && tries < MAX_TRIES; tries++) {
    fd = lock_open_config();
  }
  if (fd == -1) {
    LOGE("Could not open or lock config file.");
    exit(1);
  }

  LOGV("Prepping to read config file");
  // prep for reading config file
  ctx = uci_alloc_context();
  if (!ctx) {
    LOGW("Didn't properly initialize context");
  }
  ret = uci_load(ctx, "dreamcatcher", &pkg); // config file loaded into pkg
  if (ret != UCI_OK) {
    LOGW("Didn't properly load config file");
    uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  }
  // delete any and all temp_rule entries
  LOGV("Deleting temp_rule entries from config file");
  ptr_string = strdup("dreamcatcher.@temp_rule[-1]");
  uci_lookup_ptr(ctx, &ptr, ptr_string, true); // get first temp_rule
  while (ptr.s != NULL) {
    uci_delete(ctx, &ptr); // remove temp_rule
    free(ptr_string);
    ptr_string = strdup("dreamcatcher.@temp_rule[-1]");
    uci_lookup_ptr(ctx, &ptr, ptr_string, true); // get first temp_rule
  }
  free(ptr_string);
  // save and commit changes
  LOGV("Saving changes to config file");
  ret = uci_save(ctx, pkg);
  if (ret != UCI_OK) {
    LOGW("Didn't properly save config file.");
    uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  }
  LOGV("Committing changes to config file");
  ret = uci_commit(ctx, &pkg, false); // false should be true, library got it backwards
  if (ret != UCI_OK) {
    LOGW("Didn't properly commit config file.");
    uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  }
  LOGV("Done cleaning config file");

  // unlock the config file
  LOGV("Unlocking config file");
  fd = -1;
  for (tries = 0; fd == -1 && tries < MAX_TRIES; tries++) {
    fd = unlock_close_config();
  }
  if (fd == -1) {
    LOGE("Could not unlock or close config file.");
    exit(1);
  }
}

// return fd if successful, -1 if failed
// block until we get a handle
int lock_open_config() {
  int fd;
  struct flock fl;

  // open file to get file descriptor
  fd = open(CONFIG_FILE, O_RDWR);
  if (fd == -1){
    LOGW("Can't open config file %s.", CONFIG_FILE);
    return -1;
  }

  // prep file lock
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
}

int unlock_close_config(int fd) {
  struct flock fl;
  int retval = 0;

  // prep file unlock
  fl.l_type = F_UNLCK;
  fl.l_whence = SEEK_SET;
  fl.l_start = 0;
  fl.l_len = 0;

  // unlock file
  if (fcntl(fd, F_SETLKW, &fl) == -1) {
    LOGW("Error unlocking config file.");
    retval = -1;
  }

  // close file descriptor
  close(fd);

  return retval;
}








