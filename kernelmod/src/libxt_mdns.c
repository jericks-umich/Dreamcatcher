/*
 *  mDNS match extension for iptables
 *  
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License; either version 3 of the
 *  License, or any later version, as published by the Free Software Foundation.
 *  
 */


// For help deciphering this file, read the excellent guide on writing
// netfilter modules here: http://inai.de/documents/Netfilter_Modules.pdf

// Examples can be found here:
// https://sourceforge.net/p/xtables-addons/xtables-addons/ci/master/tree/extensions/

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include <xtables.h>
#include "xt_mdns.h"
#include "compat_user.h"

//////////
// HELP //
//////////
static void mdns_mt_help(void) {
  printf(
      "mdns match options:\n"
      "  --type type               Either \"discovery\" or \"advertisement\"\n"
      "                            match mDNS packets of the specified type\n"
      "  --names name1.name2. ...  match mDNS advertisement packets with a\n"
      "                              subset of the specified names\n"
      "                              Note: '.' is used as a delimeter.\n"
      "                              Up to %d names are supported, %d chars each.\n"
      , XT_MDNS_MAX_NAMES, XT_MDNS_MAX_NAME_SIZE);
}


/////////////
// OPTIONS //
///////////// 
static const struct option mdns_mt_opts[] = {
  {.name = "type",  .has_arg = true,  .val = 't'},
  {.name = "names", .has_arg = true,  .val = 'n'},
  {NULL},
};


///////////
// PARSE //
///////////
static int mdns_mt_parse(int c, char** argv, int invert, unsigned int* flags,
    const void* entry, struct xt_entry_match** match) {

  char* name;
  const char delim[1] = ".";
  struct xt_mdns_mtinfo* info = (void*)(*match)->data; // re-cast match struct reference

  switch (c) {

  case 't': // type
    if (strncmp("discovery", optarg, 8) == 0) { // if this is a discover type
      info->type = XT_MDNS_TYPE_DISCOVERY;
    } else if (strncmp("advertisement", optarg, 13) == 0) { // if this is an advertisement type
      info->type = XT_MDNS_TYPE_ADVERTISEMENT;
    } else { // this is an invalid type, so don't parse it
      return false;
    }
    return true;

  case 'n': // names
    if (optarg == NULL || *optarg == 0) { // if there is no argument, or an empty string
      return false;
    }
    // tokenize the argument into a list of names
    name = strtok(optarg, delim);
    for (int i=0; i<XT_MDNS_MAX_NAMES && name!=NULL; i++) {
      strncpy(info->names[i], name, XT_MDNS_MAX_NAME_SIZE);
    }
    return true;
  }

  return false;
}


//////////
// SAVE //
//////////
static void mdns_mt_save(const void* ip, const struct xt_entry_match* match) {
  const struct xt_mdns_mtinfo* info = (const void*)match->data; // re-cast match struct reference

  // check type
  if (info->type == XT_MDNS_TYPE_DISCOVERY) {
    printf(" --type discovery");
  } else { // type == XT_MDNS_TYPE_ADVERTISEMENT
    printf(" --type advertisement");
    printf(" --names %s", info->names[0]);
    for (int i=1; *info->names[i] != '\0'; i++) {
      printf(".%s",info->names[i]);
    }
  }
  printf(" ");
}


///////////
// PRINT //
///////////
static void mdns_mt_print(const void* ip, const struct xt_entry_match* match, int numeric) {
  printf(" -m mdns");
  mdns_mt_save(ip, match);
}


//////////////
// REGISTER //
//////////////
static struct xtables_match mdns_mt_reg = {
  .version        = XTABLES_VERSION,
  .name           = "mdns",
  .revision       = 0,
  .family         = NFPROTO_IPV4,
  .size           = XT_ALIGN(sizeof(struct xt_mdns_mtinfo)),
  .userspacesize  = offsetof(struct xt_mdns_mtinfo, names), // names are not important for deletion or replacement
  .help           = mdns_mt_help,
  //.init           = 
  .parse          = mdns_mt_parse,
  //.final_check    = 
  .print          = mdns_mt_print,
  .save           = mdns_mt_save,
  .extra_opts     = mdns_mt_opts,
};


//////////
// INIT //
//////////
static void _init(void) {
  xtables_register_match(&mdns_mt_reg);
}
// Will be expanded to:
// static void __attribute__((constructor)) libxt_mdns_init(void)


