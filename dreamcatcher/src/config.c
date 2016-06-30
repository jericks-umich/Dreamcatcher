#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <uci.h>

#include <main.h>
#include <config.h>
#include <logger.h>
#include <protocols.h>

#define TAG "CONFIG"

#define CONFIG_FILE "/etc/config/dreamcatcher"

#define MAX_TRIES 3

void print_uci_ptr(struct uci_ptr* p) {
  LOGV("uci_ptr package = %s",p->package);
  LOGV("uci_ptr section = %s",p->section);
  LOGV("uci_ptr option  = %s",p->option);
  LOGV("uci_ptr value   = %s",p->value);
  LOGV("uci_ptr.p       = %u",(unsigned int) p->p);
  LOGV("uci_ptr.s       = %u",(unsigned int) p->s);
  LOGV("uci_ptr.o       = %u",(unsigned int) p->o);
  LOGV("uci_ptr.last    = %u",(unsigned int) p->last);
}

char* get_verdict_string(verdict v) {
  switch (v) {
    case ACCEPT:
      return "ACCEPT";
    case DROP:
      return "DROP";
    case REJECT:
      return "REJECT";
  } 
  return NULL;
}

// input: the rule to be written to config file
// return: 0 on success, -1 on failure
int write_rule(rule r) {
  int fd;
  int ret;
  int tries = 0;

  struct uci_context* ctx;
  struct uci_package* pkg;
  struct uci_section* rule_section;

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

  // print out the rule to be written
  LOGV("New rule:");
  LOGV("src_vlan: %u", r.src_vlan);
  LOGV("dst_vlan: %u", r.dst_vlan);
  LOGV("protonum: %u", r.proto);
  LOGV("protocol: %s", get_protocol_string(r.proto));
  LOGV("src_ip:   %s", r.src_ip);
  LOGV("dst_ip:   %s", r.dst_ip);
  LOGV("src_port: %u", r.src_port);
  LOGV("dst_port: %u", r.dst_port);
  LOGV("target:   %d", r.target);

  // write the rule out to the config file
  // initialize
  LOGV("Initializing config file context");
  ctx = uci_alloc_context();
  if (!ctx) {
    LOGW("Didn't properly initialize context");
  }
  ret = uci_load(ctx, "dreamcatcher", &pkg); // config file loaded into pkg
  if (ret != UCI_OK) {
    LOGW("Didn't properly load config file");
    uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  }
  // create new entry/section
  ret = uci_add_section(ctx, pkg, "rule", &rule_section); // rule_section now points at the new rule
  if (ret != UCI_OK) {
    LOGW("Didn't properly add new section");
    uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  }
  // populate section
  if (r.src_vlan != 0) {
    rule_uci_set_int(ctx, "src", r.src_vlan);
  }
  if (r.dst_vlan != 0) {
    rule_uci_set_int(ctx, "dst", r.dst_vlan);
  }
  rule_uci_set_str(ctx, "proto", get_protocol_string(r.proto));
  if (strncmp(r.src_ip, "\0", sizeof(r.src_ip)) != 0) {
    rule_uci_set_str(ctx, "src_ip", r.src_ip);
  }
  if (strncmp(r.dst_ip, "\0", sizeof(r.dst_ip)) != 0) {
    rule_uci_set_str(ctx, "dst_ip", r.dst_ip);
  }
  if (r.src_port != 0) {
    rule_uci_set_int(ctx, "src_port", r.src_port);
  }
  if (r.dst_port != 0) {
    rule_uci_set_int(ctx, "dst_port", r.dst_port);
  }
  rule_uci_set_str(ctx, "verdict", get_verdict_string(r.target));

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
  LOGV("Done adding rule to config file");

  // unlock the config file
  LOGV("Unlocking config file");
  ret = -1;
  for (tries = 0; ret == -1 && tries < MAX_TRIES; tries++) {
    ret = unlock_close_config(fd);
  }
  if (ret == -1) {
    LOGE("Could not unlock or close config file.");
    exit(1);
  }
}

void rule_uci_set_int(struct uci_context *ctx, const char* option, const unsigned int value) {
  struct uci_ptr ptr;
  char* ptr_string;
  ptr_string = malloc(128);
  sprintf(ptr_string, "dreamcatcher.@rule[-1].%s=%d", option, value);
  uci_lookup_ptr(ctx, &ptr, ptr_string, true);
  uci_set(ctx, &ptr);
  free(ptr_string);
}

void rule_uci_set_str(struct uci_context *ctx, const char* option, const char* value) {
  struct uci_ptr ptr;
  char* ptr_string;
  ptr_string = malloc(128);
  sprintf(ptr_string, "dreamcatcher.@rule[-1].%s=%s", option, value);
  uci_lookup_ptr(ctx, &ptr, ptr_string, true);
  uci_set(ctx, &ptr);
  free(ptr_string);
}

void clean_config() {
  int ret;
  int fd;
  int tries = 0;
  struct uci_context* ctx;
  struct uci_package* pkg;
  struct uci_section* rule_section;
  struct uci_element* rule_ptr;
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
  // delete any and all rule entries
  LOGV("Deleting rule entries from config file");
  ptr_string = strdup("dreamcatcher.@rule[-1]");
  uci_lookup_ptr(ctx, &ptr, ptr_string, true); // get first rule
  while (ptr.s != NULL) {
    uci_delete(ctx, &ptr); // remove rule
    free(ptr_string);
    ptr_string = strdup("dreamcatcher.@rule[-1]");
    uci_lookup_ptr(ctx, &ptr, ptr_string, true); // get first rule
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
  ret = -1;
  for (tries = 0; ret == -1 && tries < MAX_TRIES; tries++) {
    ret = unlock_close_config();
  }
  if (ret == -1) {
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








