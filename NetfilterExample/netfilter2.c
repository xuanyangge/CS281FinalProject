//’Hello World’ v2 netfilter hooks example
//For any packet, get the ip header and check the protocol field
//if the protocol number equal to UDP (17), log in var/log/messages
//default action of module to let all packets through
 

#define __KERNEL__
#define MODULE
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/inet.h>



static struct nf_hook_ops nfho;   //net filter hook option struct
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct (not used)


 
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, 
			const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;            //ip header struct

        sock_buff = skb;
        if(!sock_buff) { return NF_ACCEPT;}
 
 
        ip_header = ip_hdr(sock_buff);    //grab network header using accessor
        


	char source[50];
	char destination[50];
	snprintf(source, 50, "%pI4", &ip_header->saddr);
	snprintf(destination, 50, "%pI4", &ip_header->daddr);


	printk(KERN_INFO "got source address: %s\n", source); 
	printk(KERN_INFO "got destination address: %s\n", destination); 
	
	
	// now first load the proc kernel module
	// printk(KERN_INFO "loading /proc module\n");
	// system("sudo insmod ../procExamples/hello_proc.ko");
	// sleep(10); // make sure the proc module is loaded.



	// if the source address and destination address is in the proc file, drop it;
	
	



        if (ip_header->protocol==17) {
                udp_header = (struct udphdr *)skb_transport_header(sock_buff);  //grab transport header
 
                printk(KERN_INFO "got udp packet \n");     //log we’ve got udp packet to /var/log/messages
                return NF_DROP;
        }
               
        return NF_ACCEPT;
}

int init_module()
{

	printk(KERN_INFO "-----Netfilter Kernel starts-----");	

        nfho.hook = hook_func;
        nfho.hooknum = NF_INET_PRE_ROUTING;
        nfho.pf = PF_INET;
        nfho.priority = NF_IP_PRI_FIRST;

        nf_register_hook(&nfho);
       
        return 0;
}
 
void cleanup_module()
{
	printk(KERN_INFO "-----Netfilter Kernel stops-----");	
        nf_unregister_hook(&nfho);     
}
 

MODULE_AUTHOR("Ziqi Yang");
MODULE_LICENSE("GPL");








