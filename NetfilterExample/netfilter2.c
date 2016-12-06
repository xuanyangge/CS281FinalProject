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



int ipindex=0; // index to write next ip address
int in_index = 0, out_index= 0; // index for iniplist and outiplist
char *allip;


char *iniplist[50]; // array holding incomming ip address to block
char *outiplist[50]; // array holding outgoing ip address to block



int len, temp;
static char *msg = 0;


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

  //if (msg == 0 || count > 100)
  //  {
  //    printk (KERN_INFO " either msg is 0 or count >100\n");
  //  }

  // you have to move data from user space to kernel buffer
  copy_from_user (msg, buf, count);
  if (copy_from_user (&allip[ipindex], buf, count)) {
	return -EFAULT;
  }

  printk(KERN_INFO "read data:\n%s\n",msg);
  printk(KERN_INFO "count is %d\n", count);
  
  len = count;
  temp += len;

  if(msg[0] == 'r'){
    in_index=0;
    out_index= 0;
    ipindex=0;
    return count;
  }

  if (msg[0] == '0'|| msg[0] == '2') { 
    iniplist[in_index] = kmalloc((count-2)*sizeof(char) , GFP_KERNEL);
    strcpy(iniplist[in_index], &allip[ipindex+2]);
    in_index += 1;
  }
  

  if (msg[0] == '1'|| msg[0] == '2') {
    outiplist[out_index] = kmalloc((count-2)*sizeof(char) , GFP_KERNEL);
    strcpy(outiplist[out_index], &allip[ipindex+2]);
    out_index += 1;

  }

  printk(KERN_INFO "current allip: %s\n", allip);
  printk(KERN_INFO "current ipindex: %d\n", ipindex);
  printk(KERN_INFO "current inip: %s\n", iniplist[in_index-1]);
  printk(KERN_INFO "current outip: %s\n", outiplist[out_index-1]);

  
  ipindex += count;
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
	int i;
        for(i =0; i < in_index;i++){
          if(strcmp(source,iniplist[i])==0){
            printk("Drop packet from ..%s\n",source);
            return NF_DROP;
          }
        }
        
        for(i=0; i< out_index;i++){
          if(strcmp(destination,outiplist[i])==0){
            printk("Drop packet to ..%s\n",destination);
            return NF_DROP;
          }
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

	// malloc space for allip
	allip = (char *)kmalloc(1000*sizeof(char), GFP_KERNEL);
        return 0;
}
 
void cleanup_module()
{
	printk(KERN_INFO "-----Proc entry removed-----");	
	remove_proc_entry ("userlist", NULL);
	printk(KERN_INFO "-----Netfilter Kernel stops-----");	
        nf_unregister_hook(&nfho);     
	kfree(allip);
}
 

MODULE_AUTHOR("Ziqi Yang");
MODULE_LICENSE("GPL");