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
  switch (r->type) {
    case (UNICAST):
      snprintf(r->message, sizeof(r->message), "%d wants to send messages to %d", r->src_vlan, r->dst_vlan);
      break;
    case (BROADCAST):
      snprintf(r->message, sizeof(r->message), "%d wants to broadcast messages to your network", r->src_vlan);
      break;
    case (DISCOVER):
      snprintf(r->message, sizeof(r->message), "%d wants to discover services on your network", r->src_vlan);
      break;
    case (ADVERTISE):
      snprintf(r->message, sizeof(r->message), "%d wants to advertise itself on your network as %s", r->src_vlan, r->device_name);
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
    case UNSPEC:
      LOGW("Verdict string requested for unspecified verdict.");
      return NULL;
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
  snprintf(hash_string, sizeof(hash_string)-1, "%stype%d", hash_string, r->type);
  if (r->src_vlan != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%ssrc_vlan%d", hash_string, r->src_vlan);
  }
  if (r->dst_vlan != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%sdst_vlan%d", hash_string, r->dst_vlan);
  }
  // required
  snprintf(hash_string, sizeof(hash_string)-1, "%sproto%s", hash_string, get_protocol_string(r->proto));
  if (strncmp(r->src_ip, "\0", IP_ADDR_LEN) != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%ssrc_ip%s", hash_string, r->src_ip);
  }
  if (strncmp(r->dst_ip, "\0", IP_ADDR_LEN) != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%sdst_ip%s", hash_string, r->dst_ip);
  }
  if (r->src_port != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%ssrc_port%d", hash_string, r->src_port);
  }
  if (r->dst_port != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%sdst_port%d", hash_string, r->dst_port);
  }
  if (strncmp(r->device_name, "\0", DEVICE_NAME_SIZE) != 0) {
    snprintf(hash_string, sizeof(hash_string)-1, "%sdevice_name%s", hash_string, r->device_name);
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
// return: 0 on success, nonzero on failure
int write_rule(rule* r) {
  int fd;
  int ret;
  int lock_ret;
  int tries = 0;

  struct uci_context* ctx;
  struct uci_package* pkg;

  // print out the rule to be written
  LOGV("New rule:");
  LOGV("type:        %u", r->type);
  LOGV("src_vlan:    %u", r->src_vlan);
  LOGV("dst_vlan:    %u", r->dst_vlan);
  LOGV("protonum:    %u", r->proto);
  LOGV("protocol:    %s", get_protocol_string(r->proto));
  LOGV("src_ip:      %s", r->src_ip);
  LOGV("dst_ip:      %s", r->dst_ip);
  LOGV("src_port:    %u", r->src_port);
  LOGV("dst_port:    %u", r->dst_port);
  LOGV("target:      %d", r->target);
  LOGV("device_name: %s", r->device_name);

  // calculate hash of rule for its id
  hash_rule(r); // now r->hash stores the unique id for this rule

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
  //print_sections(pkg);

  // see if this rule already exists
  if (rule_exists(ctx, r->hash)) {
    LOGV("Rule for %s already exists.", r->hash);
    ret = -1;
    goto cleanup;
  }

  // create new entry/section
  if (r->type >= DISCOVER) { // if a dpi_rule
    add_new_named_rule_section(ctx, r->hash, 1); // dpi == true
  } else {
    add_new_named_rule_section(ctx, r->hash, 0); // dpi == false
  }
  // populate section
  rule_uci_set_str(ctx, r->hash, "message", r->message); // required
  rule_uci_set_int(ctx, r->hash, "type", r->type); // required
  if (r->src_vlan != 0) { // optional
    rule_uci_set_int(ctx, r->hash, "src_vlan", r->src_vlan);
  }
  if (r->dst_vlan != 0) { // optional
    rule_uci_set_int(ctx, r->hash, "dst_vlan", r->dst_vlan);
  }
  rule_uci_set_str(ctx, r->hash, "proto", get_protocol_string(r->proto)); // required
  if (strncmp(r->src_ip, "\0", IP_ADDR_LEN) != 0) { // optional
    rule_uci_set_str(ctx, r->hash, "src_ip", r->src_ip);
  }
  if (strncmp(r->dst_ip, "\0", IP_ADDR_LEN) != 0) { // optional
    rule_uci_set_str(ctx, r->hash, "dst_ip", r->dst_ip);
  }
  if (r->src_port != 0) { // optional
    rule_uci_set_int(ctx, r->hash, "src_port", r->src_port);
  }
  if (r->dst_port != 0) { // optional
    rule_uci_set_int(ctx, r->hash, "dst_port", r->dst_port);
  }
  if (strncmp(r->device_name, "\0", DEVICE_NAME_SIZE) != 0) { // optional
    rule_uci_set_str(ctx, r->hash, "device_name", r->device_name);
  }
  rule_uci_set_str(ctx, r->hash, "verdict", get_verdict_string(r->target)); // required
  rule_uci_set_int(ctx, r->hash, "approved", 0); // required, always set to 0 because the user has not approved it yet

  // save and commit changes
  //LOGV("Saving changes to config file");
  //ret = uci_save(ctx, pkg);
  //if (ret != UCI_OK) {
  //  LOGW("Didn't properly save config file.");
  //  uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  //}
  LOGV("Committing changes to config file");
  ret = uci_commit(ctx, &pkg, false); // false should be true, library got it backwards
  if (ret != UCI_OK) {
    LOGW("Didn't properly commit config file.");
    uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  }
  LOGV("Done adding rule to config file");

cleanup:
  // unlock the config file
  LOGV("Unlocking config file");
  lock_ret = -1;
  for (tries = 0; lock_ret == -1 && tries < MAX_TRIES; tries++) {
    lock_ret = unlock_close_config(fd);
  }
  if (lock_ret == -1) {
    LOGE("Could not unlock or close config file.");
    return 1;
  }

  return ret;
}

// returns 1 if exists, 0 if not
int rule_exists(struct uci_context* ctx, const char* hash) {
  struct uci_ptr ptr;
  char ptr_string[128];
  snprintf(ptr_string, sizeof(ptr_string), "dreamcatcher.%s", hash);
  uci_lookup_ptr(ctx, &ptr, ptr_string, false);
  return (ptr.s != NULL); // true if the target exists (ptr.s having a value means there's a pointer to an actual section struct)
}

void add_new_named_rule_section(struct uci_context* ctx, const char* hash, int dpi_rule) {
  struct uci_ptr ptr;
  char ptr_string[128];
  if (dpi_rule) {
    snprintf(ptr_string, sizeof(ptr_string), "dreamcatcher.%s=dpi_rule", hash);
  } else {
    snprintf(ptr_string, sizeof(ptr_string), "dreamcatcher.%s=rule", hash);
  }
  uci_lookup_ptr(ctx, &ptr, ptr_string, false);
  uci_set(ctx, &ptr);
}

void rule_uci_set_int(struct uci_context* ctx, const char* hash, const char* option, const unsigned int value) {
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

// reads the question name from the payload and write it into buf
void get_dns_question_name(unsigned char* payload, char* buf) {
  unsigned char* ptr = payload;
  int num_chars;
  *buf = '\0'; // clear buf, just in case
  // METHOD 1 : get entire name
  //// iterate until we reach a null byte
  //while (*ptr != 0) {
  //  snprintf(buf, DEVICE_NAME_SIZE, "%s%.*s", buf, *ptr, (ptr+1)); // append next segment of device name
  //  ptr += ((*ptr) + 1); // ptr points at the number of characters in this segment of the name, so move it to the end of the segment
  //  if (*ptr != 0) { // if we're going to add another segment
  //    snprintf(buf, DEVICE_NAME_SIZE, "%s.", buf); // append a '.' character between segments
  //  }
  //}
  // METHOD 2 : get name up to first .
  snprintf(buf, DEVICE_NAME_SIZE, "%s%.*s", buf, *ptr, (ptr+1)); // append next segment of device name
}

// returns 1 if rule already exists, 0 if not
// sets verdict to NF_ACCEPT if existing rule specifies ACCEPT target
// sets rule.device_name if a new ADVERTISE rule needs to be made
int check_dpi_rule(rule* r, dns_header* dns, unsigned char* payload, u_int32_t* verdict) {
  int fd;
  int ret;
  int load_ret;
  int lock_ret;
  int tries = 0;

  struct uci_context* ctx;
  struct uci_package* pkg;
  struct uci_element* e;

  if (dns->questions > 0) {
    get_dns_question_name(payload, r->device_name);
  } else {
    LOGW("No questions to query!");
    // TODO: check the first answer then?
  }
  LOGV("This dns packet refers to %s", r->device_name);

  if (r->type != ADVERTISE) { // only the ADVERTISE rules should have the device name
    *r->device_name = '\0'; // zero it out
  }

  // calculate hash of rule for its id
  hash_rule(r); // now r->hash stores the unique id for this rule


  LOGV("Checking existing DPI rules to see if they match this packet.");

  // lock the config file
  LOGV("Locking config file");
  fd = -1;
  for (tries = 0; fd == -1 && tries < MAX_TRIES; tries++) {
    fd = lock_open_config();
  }
  if (fd == -1) {
    LOGE("Could not open or lock config file.");
    return 1; // not sure what to do here, for now just say the rule exists (default block) and do nothing
  }

  // initialize uci context for dreamcatcher file
  LOGV("Initializing config file context");
  ctx = uci_alloc_context();
  if (!ctx) {
    LOGW("Didn't properly initialize context");
  }
  load_ret = uci_load(ctx, "dreamcatcher", &pkg); // config file loaded into pkg
  if (load_ret != UCI_OK) {
    LOGW("Didn't properly load config file");
    uci_perror(ctx,""); // TODO: replace this with uci_get_errorstr() and use our own logging functions
  }

  ret = dpi_rule_exists(ctx, r->hash, verdict); // verdict is set if rule is found
  LOGV("Rule already exists: %d", ret);

  // unlock the config file
  LOGV("Unlocking config file");
  lock_ret = -1;
  for (tries = 0; lock_ret == -1 && tries < MAX_TRIES; tries++) {
    lock_ret = unlock_close_config(fd);
  }
  if (lock_ret == -1) {
    LOGE("Could not unlock or close config file.");
    return 1; // not sure what to do here, for now just say the rule exists (default block) and do nothing
  }

  return ret;
}

// returns 1 if exists, 0 if not
// if rule exists, sets verdict
int dpi_rule_exists(struct uci_context* ctx, const char* hash, u_int32_t* verdict) {
  struct uci_ptr ptr;
  char ptr_string[128];
  struct uci_parse_option popt = {"verdict",0};
  struct uci_option* opt;

  snprintf(ptr_string, sizeof(ptr_string), "dreamcatcher.%s", hash);
  uci_lookup_ptr(ctx, &ptr, ptr_string, false);
  if (ptr.s == NULL) { // false if the target exists (ptr.s having a value means there's a pointer to an actual section struct)
    return 0;
  }
  // find verdict
  uci_parse_section(ptr.s, &popt, 1, &opt); // finds verdict and puts it in opt
  LOGV("existing rule: %s -> %s", opt->e.name, opt->v.string);
  if (strncmp("ACCEPT", opt->v.string, sizeof("ACCEPT")) == 0) { // if verdict is ACCEPT
    *verdict = NF_ACCEPT;
    LOGD("Accepting dpi rule.");
  } // else leave to default NF_DROP
  return 1;
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

