/*
 * Copyright (c) 2010 Mathew Heard <mheard@x4b.net>
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/skbuff.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include "xt_IPSTATS.h"

static DEFINE_SPINLOCK(ipstats_lock);

/* Structure for conting bytes and packets */
typedef struct byte_packet_counter_s {
	atomic_t bytes;
	atomic_t packets;
} byte_packet_counter;

/* Counters for bytes/packets tranferred in a direction */
typedef struct ipstat_directional_counters_s {
	byte_packet_counter gre;
	byte_packet_counter ipip;
	byte_packet_counter tcp;
	byte_packet_counter udp;
	byte_packet_counter icmp;
	byte_packet_counter ipsec;
	byte_packet_counter other;
} ipstat_directional_counters;

/* A statistical entry */
struct ipstat_entry;
typedef struct ipstat_entry_s {
	struct ipstat_entry* next;
	ipstat_directional_counters in;
	ipstat_directional_counters out;
	char ip[8];
	uint8_t version;
	bool used;
	bool isnew;
	
} ipstat_entry;

#define PAGES 65536

struct ipstats_net {
	struct proc_dir_entry *pde;
	ipstat_entry ** pages[PAGES];  // list of pages,
    // initialized so every element points to sentinel
};

static unsigned int ipstats_net_id;
static inline struct ipstats_net *ipstats_pernet(struct net *net)
{
	return net_generic(net, ipstats_net_id);
}


ipstat_entry *sentinel[PAGES] = { 0 };  // sentinel page, initialized to NULLs.
							  
							  
/* Hash an IPv6 address */
static uint32_t ipv6_hash(const char* ip){
	uint16_t* twos = (uint16_t*)ip;
	return twos[0] ^ twos[1] ^ twos[2] ^ twos[3] ^ ((twos[4] ^ twos[5] ^ twos[6] ^ twos[7]) >> 16);
}

/* Increment a counter */
static inline void increment_counter(byte_packet_counter* counter, u_int16_t length){
	atomic_inc(&counter->packets);
	atomic_add(length, &counter->bytes);
}


/* Increment a counter for a protocol, in a direction */
static void increment_direction(uint8_t protocol, ipstat_directional_counters* counter, uint16_t length){
	byte_packet_counter* bp;

	switch (protocol){
	case IPPROTO_TCP:
		bp = &counter->tcp;
		break;
	case IPPROTO_UDP:
		bp = &counter->udp;
		break;
	case IPPROTO_GRE:
		bp = &counter->gre;
		break;
	case IPPROTO_IPIP:
		bp = &counter->ipip;
		break;
	case IPPROTO_ICMP:
		bp = &counter->icmp;
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		bp = &counter->ipsec;
		break;
	default:
		bp = &counter->other;
		break;
	}

	increment_counter(bp, length);
}

static ipstat_entry** allocate_new_null_filled_page(void)
{
	ipstat_entry** page = (ipstat_entry**)kmalloc(sizeof(ipstat_entry*) * PAGES, GFP_ATOMIC) ;
	if(page == NULL){
		return NULL;
	}
	memset(page, 0, sizeof(ipstat_entry*) * PAGES);
	return page;
}


/* Handle an IPv4 packet */
void ipv4_handler(const u_char* packet, bool incomming, ipstat_entry *** pages)
{
	const struct iphdr* ip;   /* packet structure         */
	u_int16_t len;               /* length holder            */
	ipstat_entry* c;
	ipstat_entry* last = NULL;
	ipstat_directional_counters* counter;
	uint32_t addr;
	ipstat_entry** page;

	//IP Header
	ip = (struct iphdr*)packet;
	len = ntohs(ip->tot_len); /* get packet length */
	
	if (ip->version != 4){
		return;
	}
	
	addr = incomming ? ip->daddr : ip->saddr;

	//Get the src bucket
	c = pages[addr & 0xFFFF][addr >> 16];

	while (c != NULL && (c->version != 4 || *(uint32_t*)c->ip == addr))
	{
		last = c;
		c = c->next;
	}
	if (c == NULL)
	{
		spin_lock_bh(&ipstats_lock);
		
		//Repeat search, it may have changed while waiting on lock
		c = pages[addr & 0xFFFF][addr >> 16];
		while (c != NULL && (c->version != 4 || *(uint32_t*)c->ip == addr))
		{
			last = c;
			c = c->next;
		}
		
		c = (ipstat_entry*)kmalloc(sizeof(ipstat_entry), GFP_ATOMIC);
		if(c == NULL){
			goto unlock;
		}
		memset(c, 0, sizeof(ipstat_entry));
		c->version = 4;
		*(uint32_t*)c->ip = addr;
		c->isnew = true;
		if (last == NULL)
		{
			page = pages[addr & 0xFFFF];
			if (page == sentinel)
			{
				page = allocate_new_null_filled_page();
				if(page == NULL){
					goto unlock;
				}
				pages[addr & 0xFFFF] = page;
			}
			page[addr >> 16] = c;
		}
		else
		{
			last->next = c;
		}
		spin_unlock_bh(&ipstats_lock);
	}
	
	counter = incomming ? &c->in : &c->out;

	increment_direction(ip->protocol, counter, len);
	c->used = true;
	return;
	
unlock:
	spin_unlock_bh(&ipstats_lock);
}

static unsigned int
ipstats_tg4(struct sk_buff *skb, u8 direction_in, struct ipstats_net* inet)
{
	ipv4_handler(skb_network_header(skb), direction_in, inet->pages);

	return XT_CONTINUE;
}

static unsigned int
ipstats_tg6(struct sk_buff *skb, u8 direction_in, struct ipstats_net* inet)
{
	//ipv4_handler(skb_network_header(skb), direction_in);

	return XT_CONTINUE;
}

static unsigned int ipstats_tg_in4(struct sk_buff *skb, const struct xt_action_param *par){
	return ipstats_tg4(skb, 1, ipstats_pernet(par->net));
}

static unsigned int ipstats_tg_out4(struct sk_buff *skb, const struct xt_action_param *par){
	return ipstats_tg4(skb, 0, ipstats_pernet(par->net));
}

static unsigned int ipstats_tg_in6(struct sk_buff *skb, const struct xt_action_param *par){
	return ipstats_tg6(skb, 1, ipstats_pernet(par->net));
}

static unsigned int ipstats_tg_out6(struct sk_buff *skb, const struct xt_action_param *par){
	return ipstats_tg6(skb, 0, ipstats_pernet(par->net));
}

static int ipstats_chk(const struct xt_tgchk_param *par)
{
	return 0;
}

static void xt_ipstats_tg_destroy(const struct xt_tgdtor_param *par,
			     struct xt_ipstats_target_info *info)
{
}


static void xt_ipstats_tg_destroy_v0(const struct xt_tgdtor_param *par)
{
}

static struct xt_target ipstats_tg_reg[] __read_mostly = {
	{
	.name		= "IPSTATS",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.checkentry	= ipstats_chk,
	.target		= ipstats_tg_in4,
	.destroy	= xt_ipstats_tg_destroy_v0,
	.targetsize     = sizeof(struct xt_ipstats_target_info),
	.hooks		= 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_LOCAL_IN | 1 << NF_INET_LOCAL_OUT,
	.me		= THIS_MODULE,
	},
	{
	.name		= "IPSTATS",
	.revision	= 0,
	.family		= NFPROTO_IPV6,
	.checkentry	= ipstats_chk,
	.target		= ipstats_tg_in6,
	.destroy	= xt_ipstats_tg_destroy_v0,
	.targetsize     = sizeof(struct xt_ipstats_target_info),
	.hooks		= 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_LOCAL_IN | 1 << NF_INET_LOCAL_OUT,
	.me		= THIS_MODULE,
	}
};


/* PROC stuff */
static void *dl_seq_start(struct seq_file *s, loff_t *pos)
	__acquires(htable->lock)
{
	struct xt_ipstats_htable *htable = s->private;
	unsigned int *bucket;

	spin_lock_bh(&htable->lock);
	if (*pos >= htable->cfg.size)
		return NULL;

	bucket = kmalloc(sizeof(unsigned int), GFP_ATOMIC);
	if (!bucket)
		return ERR_PTR(-ENOMEM);

	*bucket = *pos;
	return bucket;
}

static void *dl_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct xt_ipstats_htable *htable = s->private;
	unsigned int *bucket = (unsigned int *)v;

	*pos = ++(*bucket);
	if (*pos >= htable->cfg.size) {
		kfree(v);
		return NULL;
	}
	return bucket;
}

static void dl_seq_stop(struct seq_file *s, void *v)
	__releases(htable->lock)
{
	struct xt_ipstats_htable *htable = s->private;
	unsigned int *bucket = (unsigned int *)v;

	if (!IS_ERR(bucket))
		kfree(bucket);
	spin_unlock_bh(&htable->lock);
}

static void dl_seq_print(struct ipstat_entry_s *c, struct seq_file *s)
{
	switch (c->version) {
	case 4:
		seq_printf(s, "IN %pI4 ", c->ip);
		break;
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	case 6:
		seq_printf(s, "IN %pI6 ", c->ip);
		break;
#endif
	default:
		BUG();
	}
	
	if (c->isnew && prev_time != 0)
	{
		seq_write(s, "0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
	}else{
		//DIR TCP UDP GRE IPIP ICMP IPSEC OTHER
		seq_printf(s, "%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\n",
		atomic_get(&c->in.tcp.packets),
		atomic_get(&c->in.tcp.bytes),
		atomic_get(&c->in.udp.packets),
		atomic_get(&c->in.udp.bytes),
		atomic_get(&c->in.gre.packets),
		atomic_get(&c->in.gre.bytes),
		atomic_get(&c->in.ipip.packets),
		atomic_get(&c->in.ipip.bytes),
		atomic_get(&c->in.icmp.packets),
		atomic_get(&c->in.icmp.bytes),
		atomic_get(&c->in.ipsec.packets),
		atomic_get(&c->in.ipsec.bytes),
		atomic_get(&c->in.other.packets),
		atomic_get(&c->in.other.bytes));
	}
	
	switch (c->version) {
	case 4:
		seq_printf(s, "OUT %pI4 ", c->ip);
		break;
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	case 6:
		seq_printf(s, "OUT %pI6 ", c->ip);
		break;
#endif
	default:
		BUG();
	}
		
	if (c->isnew && prev_time != 0)
	{
		seq_write(s,"0 0 0 0 0 0 0 0 0 0 0 0 0 0\n");
		c->isnew = false;
	}else{		
		seq_printf(s, "%" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 "\n",
			atomic_get(&c->out.tcp.packets),
			atomic_get(&c->out.tcp.bytes),
			atomic_get(&c->out.udp.packets),
			atomic_get(&c->out.udp.bytes),
			atomic_get(&c->out.gre.packets),
			atomic_get(&c->out.gre.bytes),
			atomic_get(&c->out.ipip.packets),
			atomic_get(&c->out.ipip.bytes),
			atomic_get(&c->out.icmp.packets),
			atomic_get(&c->out.icmp.bytes),
			atomic_get(&c->out.ipsec.packets),
			atomic_get(&c->out.ipsec.bytes),
			atomic_get(&c->out.other.packets),
			atomic_get(&c->out.other.bytes));
	}
}

static inline int dl_seq_real_show(struct dsthash_ent *ent, u_int8_t family,
			    struct seq_file *s)
{
	dl_seq_print(ent, family, s);
	return seq_has_overflowed(s);
}

static int dl_seq_show(struct seq_file *s, void *v)
{
	struct xt_ipstats_htable *htable = s->private;
	unsigned int *bucket = (unsigned int *)v;
	struct dsthash_ent *ent;

	for(i=0;i<PAGES;i++){
		if(pages[i] != sentinel){
			for(f=0;f<PAGES;f++){
				if(pages[i][f] != NULL){
					if (dl_seq_real_show(pages[i][f], s))
						return -1;
				}
			}
		}
	}
	
	return 0;
}


static const struct seq_operations dl_seq_ops = {
	.start = dl_seq_start,
	.next  = dl_seq_next,
	.stop  = dl_seq_stop,
	.show  = dl_seq_show
};

static int dl_proc_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &dl_seq_ops);

	if (!ret) {
		struct seq_file *sf = file->private_data;

		sf->private = PDE_DATA(inode);
	}
	return ret;
}

static const struct file_operations dl_file_ops = {
	.owner   = THIS_MODULE,
	.open    = dl_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};



static int __net_init ipstats_proc_net_init(struct net *net)
{
	struct ipstats_net *ipstats_net = ipstats_pernet(net);

	hinfo->pde = proc_create_data("ipstats", 0, NULL, &dl_file_ops, hinfo);
		
	return 0;
}

static void __net_exit ipstats_proc_net_exit(struct net *net)
{
	remove_proc_entry("ipstats",net);
}

static int __net_init ipstats_net_init(struct net *net)
{
	return ipstats_proc_net_init(net);
}

static void __net_exit ipstats_net_exit(struct net *net)
{
	struct ipstats_net *ipstats_net = ipstats_pernet(net);	
	
	spin_lock_bh(&ipstats_lock);
	for(i=0;i<PAGES;i++){
		if(ipstats_net->pages[i] != sentinel){
			for(f=0;f<PAGES;f++){
				if(ipstats_net->pages[i][f] != NULL){
					kfree(ipstats_net->pages[i][f]);
				}
			}
			kfree(pages[i]);
		}
	}
	spin_unlock_bh(&ipstats_lock);
	
	ipstats_proc_net_exit(net);
}

static struct pernet_operations ipstats_net_ops = {
	.init	= ipstats_net_init,
	.exit	= ipstats_net_exit,
	.id	= &ipstats_net_id,
	.size	= sizeof(struct ipstats_net),
};

static int __init xt_ct_tg_init(void)
{
	int ret;

	ret = xt_register_targets(ipstats_tg_reg, ARRAY_SIZE(ipstats_tg_reg));
	if (ret < 0)
		return ret;
	
	
	ret = register_pernet_subsys(&ipstats_net_ops);
	if (ret < 0)
		return ret;

	return 0;
}

static void __exit xt_ct_tg_exit(void)
{
	int i, f;
	xt_unregister_targets(ipstats_tg_reg, ARRAY_SIZE(ipstats_tg_reg));
	unregister_pernet_subsys(&ipstats_net_ops);
}

module_init(xt_ct_tg_init);
module_exit(xt_ct_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: ipstats target");
MODULE_ALIAS("ipt_IPSTATS");
MODULE_ALIAS("ip6t_IPSTATS");