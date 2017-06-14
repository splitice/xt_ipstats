#ifndef XT_IPSTATS_H
#define XT_IPSTATS_H

#include <linux/types.h>

struct xt_ipstats_target_info {
	struct nf_conn  *ct __attribute__((aligned(8)));
};

#endif