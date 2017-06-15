/*
 * Copyright (c) 2010-2013 Mathew Heard <mheard@x4b.net>
 */

#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include "xt_IPSTATS.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static void ct_help(void)
{
	printf(
"IPSTATS target options:\n"
" none\n"
	);
}


static void ct_save(const void *ip, const struct xt_entry_target *target)
{
}

static struct xtables_target ct_target_reg[] = {
	{
		.family        = NFPROTO_UNSPEC,
		.name          = "IPSTATS",
		.revision      = 0,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_ipstats_target_info)),
     	.save		   = ct_save,
		.userspacesize = offsetof(struct xt_ipstats_target_info, ct),
	}
};

void _init(void)
{
	xtables_register_targets(ct_target_reg, ARRAY_SIZE(ct_target_reg));
}