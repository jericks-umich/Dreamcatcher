
#include <linux/module.h>

#include "xt_mdns.h"
#include "compat_xtables.h"


static bool xt_mdns_mt(const struct sk_buff* skb, struct xt_action_param* par) {
  return false;
}

static struct xt_match mdns_mt_reg __read_mostly = {
  .name       = "mdns",
  .revision   = 0,
  .family     = NFPROTO_IPV4,
  .proto      = IPPROTO_UDP, // only match UDP traffic
  .match      = xt_mdns_mt,
  //.checkentry = xt_mdns_mt_check,
  //.destroy    = xt_mdns_mt_destroy,
  .matchsize  = sizeof(struct xt_mdns_mtinfo),
  .me         = THIS_MODULE,
};

static int __init mdns_mt_init(void) {
  return xt_register_match(&mdns_mt_reg);
}

static void __exit mdns_mt_exit(void) {
  xt_unregister_match(&mdns_mt_reg);
}

module_init(mdns_mt_init);
module_exit(mdns_mt_exit);

MODULE_ALIAS("ipt_mdns");
MODULE_AUTHOR("Jeremy Erickson, jericks@umich.edu");
MODULE_DESCRIPTION("Xtables: Match mDNS discovery or advertisement packets with specific names");
MODULE_LICENSE("GPLv3");
