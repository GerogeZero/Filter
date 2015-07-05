#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/string.h>
#include <linux/slab.h>                 //kmalloc>

#include <linux/ioctl.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <asm/uaccess.h> 
#include <asm/errno.h>

#define MEMDEV_MAJOR 254
//#define MEMDEV_NR_DEVS 1
//#define MEMDEV_SIZE 4096

#define NF_IP_PRE_ROUTING 0
#define NF_IP_LOCAL_IN 1
#define NF_IP_FORWARD 2
#define NF_IP_LOCAL_OUT 3
#define NF_IP_POST_ROUTING 4

//#define IPPROTO_IP 0 /* dummy for IP */ 
//#define IPPROTO_HOPOPTS 0 /* IPv6 hop-by-hop options */ 
//#define IPPROTO_ICMP 1 /* control message protocol */ 
//#define IPPROTO_IGMP 2 /* internet group management protocol */ 
//#define IPPROTO_GGP 3 /* gateway^2 (deprecated) */ 
//#define IPPROTO_IPV4 4 /* IPv4 */ 
//#define IPPROTO_TCP 6 /* tcp */ 
//#define IPPROTO_UDP 12 /* pup */ 
//#define MEMDEV_IOCPRINTF 0
//#define MEMDEV_IOCGETDATA 1
//#define MEMDEV_IOCSETDATA 2

#define ADD_IP 0
#define DEL_IP 1
#define ADD_PORT 3
#define DEL_PORT 4

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARG(x) ((u8*)(x))[0],((u8*)(x))[1],((u8*)(x))[2],((u8*)(x))[3],((u8*)(x))[4],((u8*)(x))[5]

#define MAX_NR 100

static int check_ip_packet(struct sk_buff *skb);
static int check_port_packet(struct sk_buff *skb);

//sttic char *deny_if = NULL;
static unsigned int *deny_ip = 0;
static unsigned short *deny_port = 0;

static int flag = -1;

static int mem_major = 0; 

struct cdev cdev;  
int mem_open(struct inode *inode,struct file *filp)  
{  	
	return 0;  
}  
  
int mem_release(struct inode *inode,struct file *filp)  
{  	
    	return 0;  
}  

long memdev_ioctl(struct file *filp,unsigned int cmd,unsigned long arg)
{
	int ret = 0;
	int ioarg = 0;
	int i;
	
	printk(KERN_DEBUG "in memdev ioctl\n");	

	switch(cmd)
	{		
	case 0:
		get_user(ioarg, (int *)arg);					
		for(i=0; i<MAX_NR; i++)
		{
			if(*(deny_ip+i) == 0)
			{
				*(deny_ip+i) = ioarg;
				flag = 0;
				printk(KERN_DEBUG "-----------ADD_IP---------%x-----\n",htonl(*(deny_ip+i)));
				break;
			}
		}			
		break;
	case 1:
		get_user(ioarg, (int *)arg);
		for(i=0; i<MAX_NR; i++)
		{				
			if(*(deny_ip+i) == ioarg)
			{
				*(deny_ip+i) = 0;
				flag = 0;
				printk(KERN_DEBUG "-----------DEL_IP----------%x----\n",htonl(ioarg));
				break;
			}
		}		
		break;
	case 3:
		get_user(ioarg, (int *)arg);
		for(i=0; i<MAX_NR; i++)
		{
			if(*(deny_port+i) == 0)
			{
				*(deny_port+i) = ioarg;
				flag = 1;
				printk(KERN_DEBUG "---------ADD_PORT--------%d-----\n",*(deny_port+i));
				break;
			}
		}			
		break;		
	case 4:
		get_user(ioarg,(int *)arg);
		for(i=0; i<MAX_NR; i++)
		{
			if(*(deny_port+i) == ioarg);
			{
				*(deny_port+i) = 0;
				flag = 1;
				printk(KERN_DEBUG"--------DEL_PORT-------%d-----\n", ioarg);
				break;
			}
		}		
		break;
	default :
		printk(KERN_DEBUG "--------CMD is error---------\n");
		return -ENOTTY;
	}
	return ret;	
}


/*声明五个钩子*/
const char* hooks[] ={ "NF_IP_PRE_ROUTING",
                             "NF_IP_LOCAL_IN",
                             "NF_IP_FORWARD",
                             "NF_IP_LOCAL_OUT",
                             "NF_IP_POST_ROUTING"};


/*void print_mac(struct ethhdr* eth)
{
	if(eth==NULL)
	        return;
#if 1     
	if(eth->h_source!=NULL)
	        printk("<0>SOURCE:" MAC_FMT "\n", MAC_ARG(eth->h_source));
	if(eth->h_dest!=NULL)
	        printk("<0>DEST:" MAC_FMT "\n", MAC_ARG(eth->h_dest));
#endif
}
*/

/*Register the network hooks*/
unsigned int packet_filter(unsigned int hooknum,				
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *));

static struct nf_hook_ops packet_filter_opt =
{
	.hook = packet_filter,
	.owner = THIS_MODULE,
	.pf = PF_INET,			  /*IPv4 protocol hook*/
	.hooknum = NF_IP_PRE_ROUTING,     /*First stage hook*/
	.priority = NF_IP_PRI_FIRST,      /*Hook to come first*/
};

/*static struct nf_hook_ops packet_filter_opt[] = {
        {		
                .hook                = packet_filter,//ÖØÒª
		.pf                = PF_INET,
		.hooknum        = NF_IP_PRE_ROUTING,//ÖØÒª
		.priority 	= NF_IP_PRI_FIRST,
                .owner                = THIS_MODULE,	
                
        },
        {
                .hook                = packet_filter,
                .owner                = THIS_MODULE,
                .pf                = PF_INET,
                .hooknum        = NF_IP_LOCAL_IN,
                .priority = NF_IP_PRI_FIRST,
        },
        {
                .hook                = packet_filter,
                .owner                = THIS_MODULE,
                .pf                = PF_INET,
                .hooknum        = NF_IP_FORWARD,
                .priority = NF_IP_PRI_FIRST,
        },
        {
                .hook                = packet_filter,
                .owner                = THIS_MODULE,
                .pf                = PF_INET,
                .hooknum        = NF_IP_LOCAL_OUT,
                .priority = NF_IP_POST_ROUTING,
        },
};

*/

/*文件操作结构体*/
static const struct file_operations netfilter_fops =  
{  
	.owner = THIS_MODULE,  
	.open = mem_open,  
	.release = mem_release,  
	.unlocked_ioctl = memdev_ioctl,	
};  



/*hook 函数的实现*/
unsigned int packet_filter(unsigned int hooknum,
				struct sk_buff *skb,
				const struct net_device *in,
				const struct net_device *out,
				int (*okfn)(struct sk_buff *))
				{	
	int ret = NF_DROP;
		
	if(skb == NULL)
	{
		printk("%s\n","*skb is NULL");
		return NF_ACCEPT;
	}
	
	if(flag == 0)
	{		
		ret = check_ip_packet(skb);
		if(ret != NF_ACCEPT)
		{
			return ret;
		}
	}	
	else if(flag == 1)
	{		
		ret = check_port_packet(skb);
		if(ret != NF_ACCEPT)
			return ret;
	}
	
	return NF_ACCEPT;	
		
}

/* check ip*/
static int check_ip_packet(struct sk_buff *skb)
{
	int i;
	struct iphdr *iph;
	iph = ip_hdr(skb);
	
	if(!skb) return NF_ACCEPT;
	
	if(!ip_hdr(skb)) return NF_ACCEPT;

	for(i=0; i<MAX_NR; i++)
	{
		if(iph->saddr == *(deny_ip+i) && *(deny_ip+i) != 0)
		{
			printk(KERN_DEBUG"------------->%x ip is drop<-------\n",htonl(*(deny_ip+i)));
			printk(KERN_DEBUG"------------->%x iph->saddr is drop<-------\n",htonl(iph->saddr));
			printk(KERN_DEBUG"------------->%x iph->daddr is drop<-------\n",htonl(iph->daddr));
			printk(KERN_DEBUG"------------->%x iph->protocol is drop<-------\n",htonl(iph->protocol));
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

/* check port*/
static int check_port_packet(struct sk_buff *skb)
{
	int i;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;	
	
	iph = ip_hdr(skb);
	
	if(!skb) return NF_ACCEPT;
	
	if(!ip_hdr(skb)) return NF_ACCEPT;	
	
	switch(iph->protocol)
	{
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));				
			for(i=0; i<MAX_NR; i++)
			{
				if((ntohs(tcph->dest) == *(deny_port+i)) && *(deny_port+i) != 0 )
				{
					printk(KERN_DEBUG "----------->%d tcp port is drop<--------\n",*(deny_port+i));
					printk(KERN_DEBUG "----------->%d tcph->source port is drop<--------\n",ntohs(tcph->source));
					printk(KERN_DEBUG "----------->%d tcph->dest port is drop<--------\n",ntohs(tcph->dest));
					return NF_DROP;	
				}
			}
			break;

		case IPPROTO_UDP:
			udph = (struct udphdr *)(skb->data + (iph->ihl * 4));	
			for(i=0; i<MAX_NR; i++)
			{
				if((ntohs(udph->dest) == *(deny_port+i)) && *(deny_port+i) != 0)
				{
					printk(KERN_DEBUG "----------->%d udp port is drop<--------\n",*(deny_port+i));
					printk(KERN_DEBUG "----------->%d udph->source port is drop<--------\n",ntohs(udph->source));
					printk(KERN_DEBUG "----------->%d udph->dest port is drop<--------\n",ntohs(udph->source));
					return NF_DROP;	
				}
			}
			break;
		default :
		return -ENOTTY;		
	}

	return NF_ACCEPT;
}

/*netfilter init module */
static int filter_init(void)
{
	int err;
	int result = 0;
	dev_t devno;
	
	/*Regiser the control device, /dev/netfilter */
	if(mem_major)
	{
		result = register_chrdev_region(devno,1,"filter");
	}	
	else
	{
		result = alloc_chrdev_region(&devno,0,1,"filter"); 
		mem_major = MAJOR(devno);
	}	   
	
	if(result < 0)  
		return result;  
	
	//初始化cdev结构，并传递file_operations结构指针。	
	devno = MKDEV(mem_major, 0);  
	printk(KERN_DEBUG"-----major is %d-----------\n", MAJOR(devno)); 
	printk(KERN_DEBUG"-----minor is %d-----------\n", MINOR(devno)); 
	cdev_init(&cdev, &netfilter_fops);  
	cdev.owner = THIS_MODULE;  
	cdev.ops = &netfilter_fops;  
	
	//注册字符设备。
	err = cdev_add(&cdev, MKDEV(mem_major, 0), 1);
	if(err != 0)
	{
		printk(KERN_DEBUG"--------cdev_add error--------\n");
	}
	
	printk(KERN_DEBUG"netfilter: Control device successfully registered.\n");

	/*Register the network hooks*/
	nf_register_hook(&packet_filter_opt);
	//nf_register_hooks(packet_filter_opt, ARRAY_SIZE(packet_filter_opt)); // register hook
	printk(KERN_DEBUG"netfilter: Network hooks successfully installed.\n");

	deny_ip = (unsigned int*)kmalloc(sizeof(unsigned int)*MAX_NR, GFP_KERNEL);
	deny_port = (unsigned short*)kmalloc(sizeof(unsigned short)*MAX_NR, GFP_KERNEL);
	
	if((deny_ip == NULL) || (deny_port == NULL)) 
	{
		return -ENOMEM;
		goto fail_malloc;
	} 
	memset(deny_ip, 0, sizeof(unsigned int)*MAX_NR);
	memset(deny_port, 0, sizeof(unsigned short)*MAX_NR);
	
	fail_malloc:
		unregister_chrdev_region(MKDEV(mem_major,0),2);
	
	printk(KERN_DEBUG"netfilter: Module installation successful.\n");
	
	return 0;	
	
}

/*netfilter exit module*/
static void filter_exit(void)
{	
	/* Remove IPV4 hook */	
	//nf_unregister_hooks(packet_filter_opt, ARRAY_SIZE(packet_filter_opt)); // unregister hook
	nf_unregister_hook(&packet_filter_opt);

	//注销设备	
	cdev_del(&cdev);
	unregister_chrdev_region(MKDEV(mem_major,0),2);

	//释放设备结构体内存
	kfree(deny_ip);
	kfree(deny_port);		  

	printk(KERN_DEBUG"netfilter:Remove of Module from Kernel successful!.\n");
}

MODULE_LICENSE("GPL");
module_init(filter_init); // insmod module
module_exit(filter_exit); // rmmod module

