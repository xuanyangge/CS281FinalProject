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

#include <linux/proc_fs.h>
#include<linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>




int len, temp;
static char *msg = 0;

char * filter[500];


static struct nf_hook_ops nfho;   //net filter hook option struct
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct (not used)



static ssize_t read_proc (struct file *filp, char __user * buf, size_t count, loff_t * offp)
{
  if (count > temp)
    {
      count = temp;
    }
  temp = temp - count;
  copy_to_user (buf, msg, count);
  if (count == 0)
    temp = len;

  return count;
}

static ssize_t write_proc (struct file *filp, const char __user * buf, size_t count,
	    loff_t * offp)
{

  if (msg == 0 || count > 100)
    {
      printk (KERN_INFO " either msg is 0 or count >100\n");
    }

  // you have to move data from user space to kernel buffer
  copy_from_user (msg, buf, count);
  len = count;
  temp = len;
  return count;
}


static const struct file_operations proc_fops = {
  .owner = THIS_MODULE,
  .read = read_proc,
  .write = write_proc,
};


 
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
	

	// if the source address and destination address is in the proc file, drop it;
	
	



        if (ip_header->protocol==17) {
                udp_header = (struct udphdr *)skb_transport_header(sock_buff);  //grab transport header
 
                printk(KERN_INFO "got udp packet \n");     //log we’ve got udp packet to /var/log/messages
                return NF_DROP;
        }
               
        return NF_ACCEPT;
}


void create_new_proc_entry (void)
{
  proc_create ("userlist", 0666, NULL, &proc_fops);
  msg = kmalloc (100 * sizeof (char), GFP_KERNEL);
  if (msg == 0)
    {
      printk (KERN_INFO "why is msg 0 \n");
    }
}



int init_module()
{
	printk(KERN_INFO "-----Proc Kernel starts-----");	
	create_new_proc_entry ();


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
	printk(KERN_INFO "-----Proc entry removed-----");	
	remove_proc_entry ("userlist", NULL);
	printk(KERN_INFO "-----Netfilter Kernel stops-----");	
        nf_unregister_hook(&nfho);     
}
 

MODULE_AUTHOR("Ziqi Yang");
MODULE_LICENSE("GPL");








