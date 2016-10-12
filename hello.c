#include <linux/module.h> /* Needed by all modules */
#include <linux/kernel.h> /* Needed for KERN_INFO */
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

// struct holding set of hook function options
static struct nf_hook_ops nfho; 

unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb,
                      const struct net_device *in, const struct net_device *out,
                      int (*okfn)(struct sk_buff *)) {
  printk(KERN_INFO "packet dropped\n");
  return NF_DROP;
}

/* Kernel Modules must have at least the following two functions
*/

int init_module(void) {
  //Start Function
  printk(KERN_INFO "Hello world!\n");
  
  //function to call when cnditions below met
  nfho.hook = hook_func;
  // called right after packet received, first hook in Netfilter
  nfho.hooknum = NF_INET_PRE_ROUTING;
  //IPV4 packets
  nfho.pf = PF_INET;
  //set to highest priority over all other hook functions
  nfho.priority = NF_IP_PRI_FIRST;
  //register hook
  nf_register_hook(&nfho);
  
  /* A non 0 return means init_module failed; module can't be loaded */
  return 0;

}

void cleanup_module(void) {
  //End Function
  nf_unregister_hook(&nfho);
  return;
}
