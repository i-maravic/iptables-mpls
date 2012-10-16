/* Shared library add-on to iptables to add mpls target support. */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#include <xtables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_MPLS.h>
#include <linux/mpls.h>

/* Function which prints out usage message. */
static void help(void)
{
	printf(
"MPLS target options:\n"
"  --nhlfe key		      Set an outgoing MPLS NHLFE\n");
}

static const struct option opts[] = {
	{ "nhlfe", 1, NULL, '1' },
	{ .name = NULL }
};

/* Function which parses command options; returns true if it
   ate an option */
static int
parse(int c, char **argv, int invert, unsigned int *flags,
      const void *entry, struct xt_entry_target **target)
{
	struct xt_MPLS_target_info *mpls_info
		= (struct xt_MPLS_target_info *)(*target)->data;

	switch (c) {
	case '1':
		if (*flags) {
			xtables_error(PARAMETER_PROBLEM,
				   "mpls target: Can't specify --nhlfe twice");
		}

		if (!xtables_strtoui(optarg, NULL, &(mpls_info->key), 0, 0xffffffff)) {
			xtables_error(PARAMETER_PROBLEM, "Bad MPLS key `%s'",
				optarg);
		}

		*flags = 1;
		break;

	default:
		return 0;
	}

	return 1;
}

static void final_check(unsigned int flags)
{
	if (!flags)
		xtables_error(PARAMETER_PROBLEM,
			   "mpls target: Parameter --nhlfe is required");
}

/* Prints out the targinfo. */
static void print(const void *ip,
                  const struct xt_entry_target *target, int numeric)
{
	const struct xt_MPLS_target_info *mpls_info =
		(const struct xt_MPLS_target_info *)target->data;
	printf("nhlfe 0x%x ", mpls_info->key);
}

/* Saves the union ipt_targinfo in parsable form to stdout. */
static void save(const void *ip, const struct xt_entry_target *target)
{
	const struct xt_MPLS_target_info *mpls_info =
		(const struct xt_MPLS_target_info *)target->data;

	printf("--nhlfe 0x%x ", mpls_info->key);
}
static struct xtables_target mpls_tg_reg[] = {
		{
				.family		= NFPROTO_IPV4,
				.name		= "MPLS",
				.version	= XTABLES_VERSION,
				.revision	= 0,
				.size		= XT_ALIGN(sizeof(struct xt_MPLS_target_info)),
				.userspacesize	= XT_ALIGN(sizeof(struct xt_MPLS_target_info)),
				.help		= &help,
				.parse		= &parse,
				.final_check	= &final_check,
				.print		= &print,
				.save		= &save,
				.extra_opts	= opts
		},
		{
				.family		= NFPROTO_IPV6,
				.name		= "MPLS",
				.version	= XTABLES_VERSION,
				.revision	= 0,
				.size		= XT_ALIGN(sizeof(struct xt_MPLS_target_info)),
				.userspacesize	= XT_ALIGN(sizeof(struct xt_MPLS_target_info)),
				.help		= &help,
				.parse		= &parse,
				.final_check	= &final_check,
				.print		= &print,
				.save		= &save,
				.extra_opts	= opts
		}
};

void _init(void)
{
	xtables_register_targets(mpls_tg_reg, ARRAY_SIZE(mpls_tg_reg));
}
