#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

static struct nf_hook_ops my_hook;

static unsigned int my_hook_function(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    if (skb->protocol != htons(ETH_P_IP)) {
        return NF_ACCEPT;
    }
    ip_header = ip_hdr(skb);
    if (skb->len >= (unsigned int)(ip_header->ihl * 4 + sizeof(struct ethhdr))) {
        char *payload = skb->data + ip_header->ihl * 4 + sizeof(struct ethhdr);
        payload[0] = ~payload[0];
    }
    return NF_ACCEPT;
}

static int __init my_module_init(void){
    my_hook.hook = my_hook_function;
    my_hook.hooknum = NF_INET_PRE_ROUTING;
    my_hook.pf = PF_INET;
    my_hook.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&my_hook);
    printk(KERN_INFO "Netfilter Module Loaded\n");
    return 0;
}

static void __exit my_module_exit(void) {
    nf_unregister_hook(&my_hook);
    printk(KERN_INFO "Netfilter Module Unloaded\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");