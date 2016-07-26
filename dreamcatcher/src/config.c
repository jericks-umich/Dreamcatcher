#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

#include <openssl/md5.h>

#include <uci.h>

#include <main.h>
#include <config.h>
#include <logger.h>
#include <protocols.h>

#define TAG "CONFIG"

#define CONFIG_FILE "/etc/config/dreamcatcher"

#define MAX_TRIES 3

void set_message(rule* r) {
  switch (r->title) {
    case (DIRECT):
      snprintf(r->message, sizeof(r->message), "%d wants to send messages to %d", r->src_vlan, r->dst_vlan);
      break;
    case (DISCOVER):
      snprintf(r->message, sizeof(r->message), "%d wants to discover devices on your network", r->src_vlan);
      break;
    case (ADVERTISE):
      snprintf(r->message, sizeof(r->message), "%d wants to tell other devices on your network about itself", r->src_vlan);
      break;
    case (BROADCAST):
      snprintf(r->message, sizeof(r->message), "%d wants to broadcast messages to your network", r->src_vlan);
      break;
    default:
      snprintf(r->message, sizeof(r->message), "Someone's trying to talk to someone. Please use advanced mode to view the specific details.");
      break;
  }
}

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

// takes as input a rule
// generates as output a hash, which is written to the pointer supplied as the first argument
void hash_rule(rule* r) {
  MD5_CTX c;
  unsigned char hash_bytes[MD5_DIGEST_LENGTH];
  char hash_string[512] = "\0";
  // create string to be hashed
  // required
  snprintf(hash_string, sizeof(hash_string)-1, "%stitle%d",    hash_string, r->title);
  if (r->src_vlan != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%ssrc_vlan%d", hash_string, r->src_vlan);
  }
  if (r->dst_vlan != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%sdst_vlan%d", hash_string, r->dst_vlan);
  }
  // required
  snprintf(hash_string, sizeof(hash_string)-1, "%sproto%s",    hash_string, get_protocol_string(r->proto));
  if (strncmp(r->src_ip, "\0", sizeof(r->src_ip)) != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%ssrc_ip%s",   hash_string, r->src_ip);
  }
  if (strncmp(r->dst_ip, "\0", sizeof(r->dst_ip)) != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%sdst_ip%s",   hash_string, r->dst_ip);
  }
  if (r->src_port != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%ssrc_port%d", hash_string, r->src_port);
  }
  if (r->dst_port != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%sdst_port%d", hash_string, r->dst_port);
  }
  // take MD5 hash
  MD5(hash_string, strlen(hash_string), hash_bytes);
  // convert hash_bytes into hex
  for (int i=0; i<sizeof(hash_bytes); i++) { // iterate over hash_bytes and append them in hex to r->hash
    snprintf(r->hash, sizeof(r->hash), "%s%02x", r->hash, hash_bytes[i]);
  }
}

void print_sections(struct uci_package* pkg) {
  struct uci_element* e;
  //e = list_to_element((pkg->sections).next);
  //for (;&e->list != &pkg->sections; ) {
  //  e = list_to_element(e->list.next);
  uci_foreach_element(&pkg->sections, e) {
    LOGV("UCI section: %s", e->name);
  }
}
  
// input: the rule to be written to config file
// return: 0 on success, -1 on failure
int write_rule(rule* r) {
  int fd;
  int ret;
  int tries = 0;

  struct uci_context* ctx;
  struct uci_package* pkg;

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
  LOGV("title:    %u", r->title);
  LOGV("src_vlan: %u", r->src_vlan);
  LOGV("dst_vlan: %u", r->dst_vlan);
  LOGV("protonum: %u", r->proto);
  LOGV("protocol: %s", get_protocol_string(r->proto));
  LOGV("src_ip:   %s", r->src_ip);
  LOGV("dst_ip:   %s", r->dst_ip);
  LOGV("src_port: %u", r->src_port);
  LOGV("dst_port: %u", r->dst_port);
  LOGV("target:   %d", r->target);

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

  // PRINT OUT ALL SECTIONS IN PACKAGE
  print_sections(pkg);

  // calculate hash of rule for its id
  hash_rule(r); // now r->hash stores the unique id for this rule
  // create new entry/section
  add_new_named_rule_section(pkg->ctx, r->hash);
  // populate section
  rule_uci_set_str(pkg->ctx, r->hash, "message", r->message); // required
  rule_uci_set_int(pkg->ctx, r->hash, "title", r->title); // required
  if (r->src_vlan != 0) { // optional
    rule_uci_set_int(pkg->ctx, r->hash, "src_vlan", r->src_vlan);
  }
  if (r->dst_vlan != 0) { // optional
    rule_uci_set_int(pkg->ctx, r->hash, "dst_vlan", r->dst_vlan);
  }
  rule_uci_set_str(pkg->ctx, r->hash, "proto", get_protocol_string(r->proto)); // required
  if (strncmp(r->src_ip, "\0", sizeof(r->src_ip)) != 0) { // optional
    rule_uci_set_str(pkg->ctx, r->hash, "src_ip", r->src_ip);
  }
  if (strncmp(r->dst_ip, "\0", sizeof(r->dst_ip)) != 0) { // optional
    rule_uci_set_str(pkg->ctx, r->hash, "dst_ip", r->dst_ip);
  }
  if (r->src_port != 0) { // optional
    rule_uci_set_int(pkg->ctx, r->hash, "src_port", r->src_port);
  }
  if (r->dst_port != 0) { // optional
    rule_uci_set_int(pkg->ctx, r->hash, "dst_port", r->dst_port);
  }
  rule_uci_set_str(pkg->ctx, r->hash, "verdict", get_verdict_string(r->target)); // required
  rule_uci_set_int(pkg->ctx, r->hash, "approved", 0); // required, always set to 0 because the user has not approved it yet


  // PRINT OUT ALL SECTIONS IN PACKAGE
  print_sections(pkg);

  // save and commit changes
  //LOGV("Saving changes to config file");
  //ret = uci_save(ctx, pkg);
  //if (ret != UCI_OK) {
  //  LOGW("Didn't properly save config file.");
  //  uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  //}
  LOGV("Committing changes to config file");
  ret = uci_commit(pkg->ctx, &pkg, false); // false should be true, library got it backwards
  if (ret != UCI_OK) {
    LOGW("Didn't properly commit config file.");
    uci_perror(pkg->ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  }
  LOGV("Done adding rule to config file");

  // PRINT OUT ALL SECTIONS IN PACKAGE
  print_sections(pkg);

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

void add_new_named_rule_section(struct uci_context *ctx, const char* hash) {
  struct uci_ptr ptr;
  char ptr_string[128];
  snprintf(ptr_string, sizeof(ptr_string), "dreamcatcher.%s=rule", hash);
  uci_lookup_ptr(ctx, &ptr, ptr_string, false);
  uci_set(ctx, &ptr);
}

void rule_uci_set_int(struct uci_context *ctx, const char* hash, const char* option, const unsigned int value) {
  struct uci_ptr ptr;
  char ptr_string[128];
  sprintf(ptr_string, "dreamcatcher.%s.%s=%d", hash, option, value);
  uci_lookup_ptr(ctx, &ptr, ptr_string, false);
  uci_set(ctx, &ptr);
}

void rule_uci_set_str(struct uci_context *ctx, const char* hash, const char* option, const char* value) {
  struct uci_ptr ptr;
  char ptr_string[128];
  sprintf(ptr_string, "dreamcatcher.%s.%s=%s", hash, option, value);
  uci_lookup_ptr(ctx, &ptr, ptr_string, false);
  uci_set(ctx, &ptr);
}

// this function is usused now, leaving for now but can probably be removed
void clean_config() {
  int ret;
  int fd;
  int tries = 0;
  struct uci_context* ctx;
  struct uci_package* pkg;
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

void initialize_rule_queue() {
  rule_queue = calloc(RULE_QUEUE_SIZE, sizeof(rule));
  lock = calloc(1, sizeof(pthread_mutex_t));
  pthread_mutex_init(lock, NULL);
  start = rule_queue;
  end = rule_queue;
}

// pass a filled rule struct to be pushed
int push_rule_to_queue(rule* r) {
  LOGV("PUSH RULE");
  acquire_lock();
  if (((end+1) - start) % (RULE_QUEUE_SIZE*sizeof(rule)) == 0) { // failure condition
    LOGV("can't push, full");
    release_lock();
    return -1; // do not push
  }
  memcpy(end, r, sizeof(rule));
  end += 1;
  if ((end - rule_queue) > RULE_QUEUE_SIZE*sizeof(rule)) {
    end -= RULE_QUEUE_SIZE;
  }
  release_lock();
  return 0;
}

// pass a blank rule struct to be filled
int pop_rule_from_queue(rule* r) {
  LOGV("POP RULE");
  acquire_lock();
  if (start == end) {
    release_lock();
    return -1; // do not pop, empty
  }
  memcpy(r, start, sizeof(rule));
  start += 1;
  if ((start - rule_queue) > RULE_QUEUE_SIZE*sizeof(rule)) {
    start -= RULE_QUEUE_SIZE;
  }
  release_lock();
  return 0;
}

void acquire_lock() {
  pthread_mutex_lock(lock);
}

void release_lock() {
  pthread_mutex_unlock(lock);
}





