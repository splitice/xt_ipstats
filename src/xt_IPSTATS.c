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


/* Structure for conting bytes and packets */
typedef struct byte_packet_counter_s {
	uint32_t bytes;
	uint32_t packets;
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
typedef struct ipstat_entry_s {
	ipstat_entry_s* next;
	ipstat_directional_counters in;
	ipstat_directional_counters out;
	struct ip_address ip;
	bool used;
	bool isnew;
} ipstat_entry;


#define PAGES 65536
ipstat_entry *sentinel[PAGES] = { 0 };  // sentinel page, initialized to NULLs.
ipstat_entry ** pages[PAGES];  // list of pages,
                              // initialized so every element points to sentinel
							  
							  
/* Hash an IPv6 address */
static uint32_t ipv6_hash(const ipv6_address& ip){
	uint16_t* twos = (uint16_t*)&ip;
	return twos[0] ^ twos[1] ^ twos[2] ^ twos[3] ^ ((twos[4] ^ twos[5] ^ twos[6] ^ twos[7]) >> 16);
}

/* Increment a counter */
static inline void increment_counter(byte_packet_counter* counter, u_int16_t length, uint32_t sampling_rate){
	counter->packets += sampling_rate;
	counter->bytes += length * sampling_rate;
}


/* Increment a counter for a protocol, in a direction */
static void increment_direction(uint8_t protocol, ipstat_directional_counters* counter, uint16_t length, uint32_t sampling_rate){
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

	increment_counter(bp, length, sampling_rate);
}

static ipstat_entry** allocate_new_null_filled_page()
{
	ipstat_entry** page = (ipstat_entry**)malloc(sizeof(ipstat_entry*) * PAGES) ;
	memset(page, 0, sizeof(ipstat_entry*) * PAGES);
	return page;
}


/* Handle an IPv4 packet */
void ipv4_handler(const u_char* packet, bool incomming, uint32_t sampling_rate)
{
	const struct ipv4_header* ip;   /* packet structure         */
	u_int version;               /*  version                 */
	u_int16_t len;               /* length holder            */
	u_int32_t addr_idx;
	ipstat_entry* c;
	ipstat_entry* last = NULL;
	ipstat_directional_counters* counter;

	//IP Header
	ip = (struct ipv4_header*)(packet + sizeof(struct ether_header));
	len = ntohs(ip->ip_len); /* get packet length */
	version = IP_V(ip);          /* get ip version    */

	if (version != 4){
		return;
	}
	
	struct ipv4_address addr = incomming ? ip->ip_dst : ip->ip_src;

	//Get the src bucket
	addr_idx = IPV4_UINT32(addr);
	c = pages[addr_idx & 0xFFFF][addr_idx >> 16];

	while (c != NULL && (c->ip.ver != 4 || memcmp(&c->ip.v4, &addr, sizeof(addr) != 0)))
	{
		last = c;
		c = c->next;
	}
	if (c == NULL)
	{
		c = (ipstat_entry*)malloc(sizeof(ipstat_entry));
		memset(c, 0, sizeof(ipstat_entry));
		c->ip.ver = 4;
		memcpy(&c->ip.v4, &addr, sizeof(addr));
		c->isnew = true;
		if (last == NULL)
		{
			if (pages[addr_idx & 0xFFFF] == sentinel)
			{
				pages[addr_idx & 0xFFFF] = allocate_new_null_filled_page();
			}
			pages[addr_idx & 0xFFFF][addr_idx >> 16] = c;
		}
		else
		{
			last->next = c;
		}
	}
	
	counter = incomming ? &c->in : &c->out;

	increment_direction(ip->ip_p, counter, len, sampling_rate);
	c->used = true;
}

static unsigned int
ipstats_tg4(struct sk_buff *skb, u8 direction_in)
{
	const struct xt_ipstats_target_info *info = par->targinfo;
	
	ipv4_handler(skb_network_header(skb), direction_in);

	return XT_CONTINUE;
}

static unsigned int
ipstats_tg6(struct sk_buff *skb, u8 direction_in)
{
	const struct xt_ipstats_target_info *info = par->targinfo;
	
	//ipv4_handler(skb_network_header(skb), direction_in);

	return XT_CONTINUE;
}

static unsigned int ipstats_tg_in4(struct sk_buff *skb, const struct xt_action_param *par){
	return ipstats_tg4(skb, 1);
}

static unsigned int ipstats_tg_out4(struct sk_buff *skb, const struct xt_action_param *par){
	return ipstats_tg4(skb, 0);
}

static unsigned int ipstats_tg_in6(struct sk_buff *skb, const struct xt_action_param *par){
	return ipstats_tg6(skb, 1);
}

static unsigned int ipstats_tg_out6(struct sk_buff *skb, const struct xt_action_param *par){
	return ipstats_tg6(skb, 0);
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

static struct xt_target[] ipstats_tg_reg __read_mostly = {
	{
	.name		= "IPSTATS",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.checkentry	= ipstats_chk,
	.target		= ipstats_tg_in4,
	.destroy	= xt_ipstats_tg_destroy_v0,
	.targetsize     = sizeof(struct xt_ipstats_target_info),
	.hooks		= 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_INPUT,
	.me		= THIS_MODULE,
	},
	{
	.name		= "IPSTATS",
	.revision	= 0,
	.family		= NFPROTO_IPV4,
	.checkentry	= ipstats_chk,
	.target		= ipstats_tg_out4,
	.destroy	= xt_ipstats_tg_destroy_v0,
	.targetsize     = sizeof(struct xt_ipstats_target_info),
	.hooks		= 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_OUTPUT,
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
	.hooks		= 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_INPUT,
	.me		= THIS_MODULE,
	},
	{
	.name		= "IPSTATS",
	.revision	= 0,
	.family		= NFPROTO_IPV6,
	.checkentry	= ipstats_chk,
	.target		= ipstats_tg_out6,
	.destroy	= xt_ipstats_tg_destroy_v0,
	.targetsize     = sizeof(struct xt_ipstats_target_info),
	.hooks		= 1 << NF_INET_PRE_ROUTING | 1 << NF_INET_OUTPUT,
	.me		= THIS_MODULE,
	}
};

static int __init xt_ct_tg_init(void)
{
	int ret;

	ret = xt_register_target(&ipstats_tg_reg);
	if (ret < 0)
		return ret;

	return 0;
}

static void __exit xt_ct_tg_exit(void)
{
	xt_unregister_target(&ipstats_tg_reg);
}

module_init(xt_ct_tg_init);
module_exit(xt_ct_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Xtables: ipstats target");
MODULE_ALIAS("ipt_IPSTATS");
MODULE_ALIAS("ip6t_IPSTATS");