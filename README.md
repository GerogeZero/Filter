# Filter
基于Netfilter框架的防火墙设计与实现

# Content
这是一外个网络层轻量级防火墙项目。主要包涵Driver，Application。

##底层：Driver
底层驱动在linux3.13内核中实现。主要是巧妙利用了内核的Netfilter框架中
nf_hook钩子函数，然后，建立自己的Filter规则，从而达到过滤应用层传递过来了IP,PORT
的作用。

##应用：Application
应用层的UI是利用Qt5，利用Qt的方便构建UI界面来简单布置可视化操作界面。方便
用户直接输入需要过滤的IP，Port。

# Install
 1. insmod flter.ko
 2. cat /proc/dev
 3. mknod c /dev/filter xx xx
 4. rmmod filter
 
# Getting Started 
 1. cd /Qt5.0.3/bin
 2. sudo ./qtcreator
 3. open netfilter.proc/dev
  
# Examples

 Filt IP：

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
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

