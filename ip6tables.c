/* Code to take an iptables-style command line and do it. */

/*
 * Author: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <getopt.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <ip6tables.h>
#include <arpa/inet.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef IP6T_LIB_DIR
#define IP6T_LIB_DIR "/usr/local/lib/iptables"
#endif

#define FMT_NUMERIC	0x0001
#define FMT_NOCOUNTS	0x0002
#define FMT_KILOMEGAGIGA 0x0004
#define FMT_OPTIONS	0x0008
#define FMT_NOTABLE	0x0010
#define FMT_NOTARGET	0x0020
#define FMT_VIA		0x0040
#define FMT_NONEWLINE	0x0080
#define FMT_LINENUMBERS 0x0100

#define FMT_PRINT_RULE (FMT_NOCOUNTS | FMT_OPTIONS | FMT_VIA \
			| FMT_NUMERIC | FMT_NOTABLE)
#define FMT(tab,notab) ((format) & FMT_NOTABLE ? (notab) : (tab))


#define CMD_NONE		0x0000U
#define CMD_INSERT		0x0001U
#define CMD_DELETE		0x0002U
#define CMD_DELETE_NUM		0x0004U
#define CMD_REPLACE		0x0008U
#define CMD_APPEND		0x0010U
#define CMD_LIST		0x0020U
#define CMD_FLUSH		0x0040U
#define CMD_ZERO		0x0080U
#define CMD_NEW_CHAIN		0x0100U
#define CMD_DELETE_CHAIN	0x0200U
#define CMD_SET_POLICY		0x0400U
#define CMD_CHECK		0x0800U
#define CMD_RENAME_CHAIN	0x1000U
#define NUMBER_OF_CMD	13
static const char cmdflags[] = { 'I', 'D', 'D', 'R', 'A', 'L', 'F', 'Z',
				 'N', 'X', 'P', 'C', 'E' };

#define OPTION_OFFSET 256

#define OPT_NONE	0x00000U
#define OPT_NUMERIC	0x00001U
#define OPT_SOURCE	0x00002U
#define OPT_DESTINATION	0x00004U
#define OPT_PROTOCOL	0x00008U
#define OPT_JUMP	0x00010U
#define OPT_VERBOSE	0x00020U
#define OPT_EXPANDED	0x00040U
#define OPT_VIANAMEIN	0x00080U
#define OPT_VIANAMEOUT	0x00100U
#define OPT_LINENUMBERS 0x00200U
#define NUMBER_OF_OPT	10
static const char optflags[NUMBER_OF_OPT]
= { 'n', 's', 'd', 'p', 'j', 'v', 'x', 'i', 'o', '3'};

static struct option original_opts[] = {
	{ "append", 1, 0, 'A' },
	{ "delete", 1, 0,  'D' },
	{ "insert", 1, 0,  'I' },
	{ "replace", 1, 0,  'R' },
	{ "list", 2, 0,  'L' },
	{ "flush", 2, 0,  'F' },
	{ "zero", 2, 0,  'Z' },
	{ "check", 1, 0,  'C' },
	{ "new-chain", 1, 0,  'N' },
	{ "delete-chain", 2, 0,  'X' },
	{ "rename-chain", 2, 0,  'E' },
	{ "policy", 1, 0,  'P' },
	{ "source", 1, 0, 's' },
	{ "destination", 1, 0,  'd' },
	{ "src", 1, 0,  's' }, /* synonym */
	{ "dst", 1, 0,  'd' }, /* synonym */
	{ "protocol", 1, 0,  'p' },
	{ "in-interface", 1, 0, 'i' },
	{ "jump", 1, 0, 'j' },
	{ "table", 1, 0, 't' },
	{ "match", 1, 0, 'm' },
	{ "numeric", 0, 0, 'n' },
	{ "out-interface", 1, 0, 'o' },
	{ "verbose", 0, 0, 'v' },
	{ "exact", 0, 0, 'x' },
	{ "version", 0, 0, 'V' },
	{ "help", 2, 0, 'h' },
	{ "line-numbers", 0, 0, '0' },
	{ 0 }
};

static struct option *opts = original_opts;
static unsigned int global_option_offset = 0;

/* Table of legal combinations of commands and options.  If any of the
 * given commands make an option legal, that option is legal (applies to
 * CMD_LIST and CMD_ZERO only).
 * Key:
 *  +  compulsory
 *  x  illegal
 *     optional
 */

static char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] =
/* Well, it's better than "Re: Linux vs FreeBSD" */
{
	/*     -n  -s  -d  -p  -j  -v  -x  -i  -o  --line */
/*INSERT*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x'},
/*DELETE*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x'},
/*DELETE_NUM*/{'x','x','x','x','x',' ','x','x','x','x'},
/*REPLACE*/   {'x',' ',' ',' ',' ',' ','x',' ',' ','x'},
/*APPEND*/    {'x',' ',' ',' ',' ',' ','x',' ',' ','x'},
/*LIST*/      {' ','x','x','x','x',' ',' ','x','x',' '},
/*FLUSH*/     {'x','x','x','x','x',' ','x','x','x','x'},
/*ZERO*/      {'x','x','x','x','x',' ','x','x','x','x'},
/*NEW_CHAIN*/ {'x','x','x','x','x',' ','x','x','x','x'},
/*DEL_CHAIN*/ {'x','x','x','x','x',' ','x','x','x','x'},
/*SET_POLICY*/{'x','x','x','x','x',' ','x','x','x','x'},
/*CHECK*/     {'x','+','+','+','x',' ','x','+','+','x'},
/*RENAME*/    {'x','x','x','x','x',' ','x','x','x','x'}
};

static int inverse_for_options[NUMBER_OF_OPT] =
{
/* -n */ 0,
/* -s */ IP6T_INV_SRCIP,
/* -d */ IP6T_INV_DSTIP,
/* -p */ IP6T_INV_PROTO,
/* -j */ 0,
/* -v */ 0,
/* -x */ 0,
/* -i */ IP6T_INV_VIA_IN,
/* -o */ IP6T_INV_VIA_OUT,
/*--line*/ 0
};

const char *program_version;
const char *program_name;

/* Keeping track of external matches and targets: linked lists.  */
struct ip6tables_match *ip6tables_matches = NULL;
struct ip6tables_target *ip6tables_targets = NULL;

/* Extra debugging from libiptc */
extern void dump_entries6(const ip6tc_handle_t handle);

/* A few hardcoded protocols for 'all' and in case the user has no
   /etc/protocols */
struct pprot {
	char *name;
	u_int8_t num;
};

static const struct pprot chain_protos[] = {
	{ "tcp", IPPROTO_TCP },
	{ "udp", IPPROTO_UDP },
	{ "icmp", IPPROTO_ICMP },
	{ "all", 0 },
};

static char *
proto_to_name(u_int8_t proto, int nolookup)
{
	unsigned int i;

	if (proto && !nolookup) {
		struct protoent *pent = getprotobynumber(proto);
		if (pent)
			return pent->p_name;
	}

	for (i = 0; i < sizeof(chain_protos)/sizeof(struct pprot); i++)
		if (chain_protos[i].num == proto)
			return chain_protos[i].name;

	return NULL;
}

static void
in6addrcpy(struct in6_addr *dst, struct in6_addr *src)
{
	memcpy(dst, src, sizeof(struct in6_addr));
}

void
exit_error(enum exittype status, char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	fprintf(stderr, "%s v%s: ", program_name, program_version);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	if (status == PARAMETER_PROBLEM)
		exit_tryhelp(status);
	if (status == VERSION_PROBLEM)
		fprintf(stderr,
			"Perhaps iptables or your kernel needs to be upgraded.\n");
	exit(status);
}

void
exit_tryhelp(int status)
{
	fprintf(stderr, "Try `%s -h' or '%s --help' for more information.\n",
			program_name, program_name );
	exit(status);
}

void
exit_printhelp(void)
{
	struct ip6tables_match *m = NULL;
	struct ip6tables_target *t = NULL;

	printf("%s v%s\n\n"
"Usage: %s -[ADC] chain rule-specification [options]\n"
"       %s -[RI] chain rulenum rule-specification [options]\n"
"       %s -D chain rulenum [options]\n"
"       %s -[LFZ] [chain] [options]\n"
"       %s -[NX] chain\n"
"       %s -E old-chain-name new-chain-name\n"
"       %s -P chain target [options]\n"
"       %s -h (print this help information)\n\n",
	       program_name, program_version, program_name, program_name,
	       program_name, program_name, program_name, program_name,
	       program_name, program_name);

	printf(
"Commands:\n"
"Either long or short options are allowed.\n"
"  --append  -A chain		Append to chain\n"
"  --delete  -D chain		Delete matching rule from chain\n"
"  --delete  -D chain rulenum\n"
"				Delete rule rulenum (1 = first) from chain\n"
"  --insert  -I chain [rulenum]\n"
"				Insert in chain as rulenum (default 1=first)\n"
"  --replace -R chain rulenum\n"
"				Replace rule rulenum (1 = first) in chain\n"
"  --list    -L [chain]		List the rules in a chain or all chains\n"
"  --flush   -F [chain]		Delete all rules in  chain or all chains\n"
"  --zero    -Z [chain]		Zero counters in chain or all chains\n"
"  --check   -C chain		Test this packet on chain\n"
"  --new     -N chain		Create a new user-defined chain\n"
"  --delete-chain\n"
"            -X [chain]		Delete a user-defined chain\n"
"  --policy  -P chain target\n"
"				Change policy on chain to target\n"
"  --rename-chain\n"
"            -E old-chain new-chain\n"
"				Change chain name, (moving any references)\n"

"Options:\n"
"  --proto	-p [!] proto	protocol: by number or name, eg. `tcp'\n"
"  --source	-s [!] address[/mask]\n"
"				source specification\n"
"  --destination -d [!] address[/mask]\n"
"				destination specification\n"
"  --in-interface -i [!] input name[+]\n"
"				network interface name ([+] for wildcard)\n"
"  --jump	-j target\n"
"				target for rule\n"
"  --numeric	-n		numeric output of addresses and ports\n"
"  --out-interface -o [!] output name[+]\n"
"				network interface name ([+] for wildcard)\n"
"  --table	-t table	table to manipulate (default: `filter')\n"
"  --verbose	-v		verbose mode\n"
"  --exact	-x		expand numbers (display exact values)\n"
"[!] --fragment	-f		match second or further fragments only\n"
"[!] --version	-V		print package version.\n");

	/* Print out any special helps. A user might like to be able to add a --help 
	   to the commandline, and see expected results. So we call help for all 
	   matches & targets */
	for (t=ip6tables_targets;t;t=t->next) {
		printf("\n");
		t->help();
	}
	for (m=ip6tables_matches;m;m=m->next) {
		printf("\n");
		m->help();
	}
	exit(0);
}

static void
generic_opt_check(int command, int options)
{
	int i, j, legal = 0;

	/* Check that commands are valid with options.  Complicated by the
	 * fact that if an option is legal with *any* command given, it is
	 * legal overall (ie. -z and -l).
	 */
	for (i = 0; i < NUMBER_OF_OPT; i++) {
		legal = 0; /* -1 => illegal, 1 => legal, 0 => undecided. */

		for (j = 0; j < NUMBER_OF_CMD; j++) {
			if (!(command & (1<<j)))
				continue;

			if (!(options & (1<<i))) {
				if (commands_v_options[j][i] == '+')
					exit_error(PARAMETER_PROBLEM,
						   "You need to supply the `-%c' "
						   "option for this command\n",
						   optflags[i]);
			} else {
				if (commands_v_options[j][i] != 'x')
					legal = 1;
				else if (legal == 0)
					legal = -1;
			}
		}
		if (legal == -1)
			exit_error(PARAMETER_PROBLEM,
				   "Illegal option `-%c' with this command\n",
				   optflags[i]);
	}
}

static char
opt2char(int option)
{
	const char *ptr;
	for (ptr = optflags; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static char
cmd2char(int option)
{
	const char *ptr;
	for (ptr = cmdflags; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static void
add_command(int *cmd, const int newcmd, const int othercmds, int invert)
{
	if (invert)
		exit_error(PARAMETER_PROBLEM, "unexpected ! flag");
	if (*cmd & (~othercmds))
		exit_error(PARAMETER_PROBLEM, "Can't use -%c with -%c\n",
			   cmd2char(newcmd), cmd2char(*cmd & (~othercmds)));
	*cmd |= newcmd;
}

int
check_inverse(const char option[], int *invert)
{
	if (option && strcmp(option, "!") == 0) {
		if (*invert)
			exit_error(PARAMETER_PROBLEM,
				   "Multiple `!' flags not allowed");

		*invert = TRUE;
		return TRUE;
	}
	return FALSE;
}

static void *
fw_calloc(size_t count, size_t size)
{
	void *p;

	if ((p = calloc(count, size)) == NULL) {
		perror("iptables: calloc failed");
		exit(1);
	}
	return p;
}

static void *
fw_malloc(size_t size)
{
	void *p;

	if ((p = malloc(size)) == NULL) {
		perror("iptables: malloc failed");
		exit(1);
	}
	return p;
}

static struct in6_addr *
host_to_addr(const char *name, unsigned int *naddr)
{
	struct hostent *host;
	struct in6_addr *addr;
	unsigned int i;

	*naddr = 0;
	if ((host = gethostbyname2(name, AF_INET6)) != NULL) {
		if (host->h_addrtype != AF_INET6 ||
		    host->h_length != sizeof(struct in6_addr))
			return (struct in6_addr *) NULL;

		while (host->h_addr_list[*naddr] != (char *) NULL)
			(*naddr)++;
		addr = fw_calloc(*naddr, sizeof(struct in6_addr));
		for (i = 0; i < *naddr; i++)
			in6addrcpy(&(addr[i]),
				  (struct in6_addr *) host->h_addr_list[i]);
		return addr;
	}

	return (struct in6_addr *) NULL;
}

static char *
addr_to_host(const struct in6_addr *addr)
{
	struct hostent *host;

	if ((host = gethostbyaddr((char *) addr,
				  sizeof(struct in_addr), AF_INET6)) != NULL)
		return (char *) host->h_name;

	return (char *) NULL;
}

static char *
addr_to_numeric(const struct in6_addr *addrp)
{
	static char buf[20];
	return (char *)inet_ntop(AF_INET6, addrp, buf, sizeof buf);
}

static struct in6_addr *
numeric_to_addr(const char *num)
{
	static struct in6_addr ap;
	if (inet_pton(AF_INET6, num, &ap) == 1)
		return &ap;
	return (struct in6_addr *)NULL;
}

static char *
mask_to_numeric(const struct in6_addr *addrp)
{
	static char buf[20];
	int l = ipv6_prefix_length(addrp);
	if (l == -1)
		return addr_to_numeric(addrp);
	sprintf(buf, "%d", l);
	return buf;
}

static struct in6_addr *
network_to_addr(const char *name)
{
	abort();
}

static char *
addr_to_anyname(const struct in6_addr *addr)
{
	char *name;

	if ((name = addr_to_host(addr)) != NULL)
		return name;

	return addr_to_numeric(addr);
}

/*
 *	All functions starting with "parse" should succeed, otherwise
 *	the program fails.
 *	Most routines return pointers to static data that may change
 *	between calls to the same or other routines with a few exceptions:
 *	"host_to_addr", "parse_hostnetwork", and "parse_hostnetworkmask"
 *	return global static data.
*/

static struct in6_addr *
parse_hostnetwork(const char *name, unsigned int *naddrs)
{
	struct in6_addr *addrp, *addrptmp;

	if ((addrptmp = numeric_to_addr(name)) != NULL ||
	    (addrptmp = network_to_addr(name)) != NULL) {
		addrp = fw_malloc(sizeof(struct in6_addr));
		in6addrcpy(addrp, addrptmp);
		*naddrs = 1;
		return addrp;
	}
	if ((addrp = host_to_addr(name, naddrs)) != NULL)
		return addrp;

	exit_error(PARAMETER_PROBLEM, "host/network `%s' not found", name);
}

static struct in6_addr *
parse_mask(char *mask)
{
	static struct in6_addr maskaddr;
	struct in6_addr *addrp;
	int bits;

	if (mask == NULL) {
		/* no mask at all defaults to 128 bits */
		memset(&maskaddr, 0xff, sizeof maskaddr);
		return &maskaddr;
	}
	if ((addrp = numeric_to_addr(mask)) != NULL)
		return addrp;
	if ((bits = string_to_number(mask, 0, 128)) == -1)
		exit_error(PARAMETER_PROBLEM,
			   "invalid mask `%s' specified", mask);
	if (bits != 0) {
		char *p = (char *)&maskaddr;
		memset(p, 0xff, bits / 8);
		memset(p + (bits / 8) + 1, 0, (128 - bits) / 8);
		p[bits / 8] = 0xff << (8 - (bits & 7));
		return &maskaddr;
	}

	memset(&maskaddr, 0, sizeof maskaddr);
	return &maskaddr;
}

static void
parse_hostnetworkmask(const char *name, struct in6_addr **addrpp,
		      struct in6_addr *maskp, unsigned int *naddrs)
{
	struct in6_addr *addrp;
	char buf[256];
	char *p;
	int i, j, n;

	strncpy(buf, name, sizeof(buf) - 1);
	if ((p = strrchr(buf, '/')) != NULL) {
		*p = '\0';
		addrp = parse_mask(p + 1);
	} else
		addrp = parse_mask(NULL);
	in6addrcpy(maskp, addrp);

	/* if a null mask is given, the name is ignored, like in "any/0" */
	if (!memcmp(maskp, &in6addr_any, sizeof(in6addr_any)))
		strcpy(buf, "::");

	addrp = *addrpp = parse_hostnetwork(buf, naddrs);
	n = *naddrs;
	for (i = 0, j = 0; i < n; i++) {
		int k;
		for (k = 0; k < 4; k++)
			addrp[j].in6_u.u6_addr32[k] &= maskp->in6_u.u6_addr32[k];
		j++;
		for (k = 0; k < j - 1; k++) {
			if (!memcmp(&addrp[k], &addrp[j - 1], sizeof(struct in6_addr))) {
				(*naddrs)--;
				j--;
				break;
			}
		}
	}
}

struct ip6tables_match *
find_match(const char *name, enum ip6t_tryload tryload)
{
	struct ip6tables_match *ptr;

	for (ptr = ip6tables_matches; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
			break;
	}

	if (!ptr && tryload != DONT_LOAD) {
		char path[sizeof(IP6T_LIB_DIR) + sizeof("/libip6t_.so")
			 + strlen(name)];
		sprintf(path, IP6T_LIB_DIR "/libip6t_%s.so", name);
		if (dlopen(path, RTLD_NOW)) {
			/* Found library.  If it didn't register itself,
			   maybe they specified target as match. */
			ptr = find_match(name, DONT_LOAD);

			if (!ptr)
				exit_error(PARAMETER_PROBLEM,
					   "Couldn't load match `%s'\n",
					   name);
		} else if (tryload == LOAD_MUST_SUCCEED)
			exit_error(PARAMETER_PROBLEM,
				   "Couldn't load match `%s'\n", name);
	}

	return ptr;
}

/* Christophe Burki wants `-p 6' to imply `-m tcp'.  */
static struct ip6tables_match *
find_proto(const char *pname, enum ip6t_tryload tryload, int nolookup)
{
	int proto;

	proto = string_to_number(pname, 0, 255);
	if (proto != -1) 
		return find_match(proto_to_name(proto, nolookup), tryload);

	return find_match(pname, tryload);
}

static u_int16_t
parse_protocol(const char *s)
{
	int proto = string_to_number(s, 0, 255);

	if (proto == -1) {
		struct protoent *pent;

		if ((pent = getprotobyname(s)))
			proto = pent->p_proto;
		else {
			unsigned int i;
			for (i = 0;
			     i < sizeof(chain_protos)/sizeof(struct pprot);
			     i++) {
				if (strcmp(s, chain_protos[i].name) == 0) {
					proto = chain_protos[i].num;
					break;
				}
			}
			if (i == sizeof(chain_protos)/sizeof(struct pprot))
				exit_error(PARAMETER_PROBLEM,
					   "unknown protocol `%s' specified",
					   s);
		}
	}

	return (u_int16_t)proto;
}

static void
parse_interface(const char *arg, char *vianame, unsigned char *mask)
{
	int vialen = strlen(arg);
	unsigned int i;

	memset(mask, 0, IFNAMSIZ);
	memset(vianame, 0, IFNAMSIZ);

	if (vialen + 1 > IFNAMSIZ)
		exit_error(PARAMETER_PROBLEM,
			   "interface name `%s' must be shorter than IFNAMSIZ"
			   " (%i)", arg, IFNAMSIZ-1);

	strcpy(vianame, arg);
	if (vialen == 0)
		memset(mask, 0, IFNAMSIZ);
	else if (vianame[vialen - 1] == '+') {
		memset(mask, 0xFF, vialen - 1);
		memset(mask + vialen - 1, 0, IFNAMSIZ - vialen + 1);
		/* Remove `+' */
		vianame[vialen - 1] = '\0';
	} else {
		/* Include nul-terminator in match */
		memset(mask, 0xFF, vialen + 1);
		memset(mask + vialen + 1, 0, IFNAMSIZ - vialen - 1);
	}
	for (i = 0; vianame[i]; i++) {
		if (!isalnum(vianame[i])) {
			printf("Warning: wierd character in interface"
			       " `%s' (No aliases, :, ! or *).\n",
			       vianame);
			break;
		}
	}
}

/* Can't be zero. */
static int
parse_rulenumber(const char *rule)
{
	int rulenum = string_to_number(rule, 1, INT_MAX);

	if (rulenum == -1)
		exit_error(PARAMETER_PROBLEM,
			   "Invalid rule number `%s'", rule);

	return rulenum;
}

static const char *
parse_target(const char *targetname)
{
	const char *ptr;

	if (strlen(targetname) < 1)
		exit_error(PARAMETER_PROBLEM,
			   "Invalid target name (too short)");

	if (strlen(targetname)+1 > sizeof(ip6t_chainlabel))
		exit_error(PARAMETER_PROBLEM,
			   "Invalid target name `%s' (%i chars max)",
			   targetname, sizeof(ip6t_chainlabel)-1);

	for (ptr = targetname; *ptr; ptr++)
		if (isspace(*ptr))
			exit_error(PARAMETER_PROBLEM,
				   "Invalid target name `%s'", targetname);
	return targetname;
}

int
string_to_number(const char *s, int min, int max)
{
	int number;
	char *end;

	/* Handle hex, octal, etc. */
	number = (int)strtol(s, &end, 0);
	if (*end == '\0' && end != s) {
		/* we parsed a number, let's see if we want this */
		if (min <= number && number <= max)
			return number;
	}
	return -1;
}

static void
set_option(unsigned int *options, unsigned int option, u_int8_t *invflg,
	   int invert)
{
	if (*options & option)
		exit_error(PARAMETER_PROBLEM, "multiple -%c flags not allowed",
			   opt2char(option));
	*options |= option;

	if (invert) {
		unsigned int i;
		for (i = 0; 1 << i != option; i++);

		if (!inverse_for_options[i])
			exit_error(PARAMETER_PROBLEM,
				   "cannot have ! before -%c",
				   opt2char(option));
		*invflg |= inverse_for_options[i];
	}
}

struct ip6tables_target *
find_target(const char *name, enum ip6t_tryload tryload)
{
	struct ip6tables_target *ptr;

	/* Standard target? */
	if (strcmp(name, "") == 0
	    || strcmp(name, IP6TC_LABEL_ACCEPT) == 0
	    || strcmp(name, IP6TC_LABEL_DROP) == 0
	    || strcmp(name, IP6TC_LABEL_QUEUE) == 0
	    || strcmp(name, IP6TC_LABEL_RETURN) == 0)
		name = "standard";

	for (ptr = ip6tables_targets; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
			break;
	}

	if (!ptr && tryload != DONT_LOAD) {
		char path[sizeof(IP6T_LIB_DIR) + sizeof("/libip6t_.so")
			 + strlen(name)];
		sprintf(path, IP6T_LIB_DIR "/libip6t_%s.so", name);
		if (dlopen(path, RTLD_NOW)) {
			/* Found library.  If it didn't register itself,
			   maybe they specified match as a target. */
			ptr = find_target(name, DONT_LOAD);
			if (!ptr)
				exit_error(PARAMETER_PROBLEM,
					   "Couldn't load target `%s'\n",
					   name);
		} else if (tryload == LOAD_MUST_SUCCEED)
			exit_error(PARAMETER_PROBLEM,
				   "Couldn't load target `%s'\n", name);
	}

	return ptr;
}

static struct option *
merge_options(struct option *oldopts, struct option *newopts,
	      unsigned int *option_offset)
{
	unsigned int num_old, num_new, i;
	struct option *merge;

	for (num_old = 0; oldopts[num_old].name; num_old++);
	for (num_new = 0; newopts[num_new].name; num_new++);

	global_option_offset += OPTION_OFFSET;
	*option_offset = global_option_offset;

	merge = malloc(sizeof(struct option) * (num_new + num_old + 1));
	memcpy(merge, oldopts, num_old * sizeof(struct option));
	for (i = 0; i < num_new; i++) {
		merge[num_old + i] = newopts[i];
		merge[num_old + i].val += *option_offset;
	}
	memset(merge + num_old + num_new, 0, sizeof(struct option));

	return merge;
}

void
register_match6(struct ip6tables_match *me)
{
	if (strcmp(me->version, program_version) != 0) {
		fprintf(stderr, "%s: match `%s' v%s (I'm v%s).\n",
			program_name, me->name, me->version, program_version);
		exit(1);
	}

	if (find_match(me->name, DONT_LOAD)) {
		fprintf(stderr, "%s: match `%s' already registered.\n",
			program_name, me->name);
		exit(1);
	}

	/* Prepend to list. */
	me->next = ip6tables_matches;
	ip6tables_matches = me;
	me->m = NULL;
	me->mflags = 0;

	opts = merge_options(opts, me->extra_opts, &me->option_offset);
}

void
register_target6(struct ip6tables_target *me)
{
	if (strcmp(me->version, program_version) != 0) {
		fprintf(stderr, "%s: target `%s' v%s (I'm v%s).\n",
			program_name, me->name, me->version, program_version);
		exit(1);
	}

	if (find_target(me->name, DONT_LOAD)) {
		fprintf(stderr, "%s: target `%s' already registered.\n",
			program_name, me->name);
		exit(1);
	}

	/* Prepend to list. */
	me->next = ip6tables_targets;
	ip6tables_targets = me;
	me->t = NULL;
	me->tflags = 0;

	opts = merge_options(opts, me->extra_opts, &me->option_offset);
}

static void
print_header(unsigned int format, const char *chain, ip6tc_handle_t *handle)
{
	struct ip6t_counters counters;
	const char *pol = ip6tc_get_policy(chain, &counters, handle);
	printf("Chain %s", chain);
	if (pol) {
		printf(" (policy %s", pol);
		if (!(format & FMT_NOCOUNTS))
			printf(" %llu packets, %llu bytes",
			       counters.pcnt, counters.bcnt);
		printf(")\n");
	} else {
		unsigned int refs;
		if (!ip6tc_get_references(&refs, chain, handle))
			printf(" (ERROR obtaining refs)\n");
		else
			printf(" (%u references)\n", refs);
	}

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4s ", "%s "), "num");
	if (!(format & FMT_NOCOUNTS)) {
		if (format & FMT_KILOMEGAGIGA) {
			printf(FMT("%5s ","%s "), "pkts");
			printf(FMT("%5s ","%s "), "bytes");
		} else {
			printf(FMT("%8s ","%s "), "pkts");
			printf(FMT("%10s ","%s "), "bytes");
		}
	}
	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ","%s "), "target");
	fputs(" prot ", stdout);
	if (format & FMT_OPTIONS)
		fputs("opt", stdout);
	if (format & FMT_VIA) {
		printf(FMT(" %-6s ","%s "), "in");
		printf(FMT("%-6s ","%s "), "out");
	}
	printf(FMT(" %-19s ","%s "), "source");
	printf(FMT(" %-19s "," %s "), "destination");
	printf("\n");
}

static void
print_num(u_int64_t number, unsigned int format)
{
	if (format & FMT_KILOMEGAGIGA) {
		if (number > 99999) {
			number = (number + 500) / 1000;
			if (number > 9999) {
				number = (number + 500) / 1000;
				if (number > 9999) {
					number = (number + 500) / 1000;
					printf(FMT("%4lluG ","%lluG "),number);
				}
				else printf(FMT("%4lluM ","%lluM "), number);
			} else
				printf(FMT("%4lluK ","%lluK "), number);
		} else
			printf(FMT("%5llu ","%llu "), number);
	} else
		printf(FMT("%8llu ","%llu "), number);
}

static int
print_match(const struct ip6t_entry_match *m,
	    const struct ip6t_ip6 *ip,
	    int numeric)
{
	struct ip6tables_match *match = find_match(m->u.user.name, TRY_LOAD);

	if (match) {
		if (match->print)
			match->print(ip, m, numeric);
	} else {
		if (m->u.user.name[0])
			printf("UNKNOWN match `%s' ", m->u.user.name);
	}
	/* Don't stop iterating. */
	return 0;
}

/* e is called `fw' here for hysterical raisins */
static void
print_firewall(const struct ip6t_entry *fw,
	       const char *targname,
	       unsigned int num,
	       unsigned int format,
	       const ip6tc_handle_t handle)
{
	struct ip6tables_target *target = NULL;
	const struct ip6t_entry_target *t;
	u_int8_t flags;
	char buf[BUFSIZ];

	/* User creates a chain called "REJECT": this overrides the
	   `REJECT' target module.  Keep feeding them rope until the
	   revolution... Bwahahahahah */
	if (!ip6tc_is_chain(targname, handle))
		target = find_target(targname, TRY_LOAD);
	else
		target = find_target(IP6T_STANDARD_TARGET, LOAD_MUST_SUCCEED);

	t = ip6t_get_target((struct ip6t_entry *)fw);
	flags = fw->ipv6.flags;

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num+1);

	if (!(format & FMT_NOCOUNTS)) {
		print_num(fw->counters.pcnt, format);
		print_num(fw->counters.bcnt, format);
	}

	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ", "%s "), targname);

	fputc(fw->ipv6.invflags & IP6T_INV_PROTO ? '!' : ' ', stdout);
	{
		char *pname = proto_to_name(fw->ipv6.proto, 
					    format&FMT_NUMERIC);
		if (pname)
			printf(FMT("%-5s", "%s "), pname);
		else
			printf(FMT("%-5hu", "%hu "), fw->ipv6.proto);
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", stdout);
		fputc(' ', stdout);
		fputc(' ', stdout);
		fputc(' ', stdout);
	}

	if (format & FMT_VIA) {
		char iface[IFNAMSIZ+2];

		if (fw->ipv6.invflags & IP6T_INV_VIA_IN) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ipv6.iniface[0] != '\0') {
			strcat(iface, fw->ipv6.iniface);
			/* If it doesn't compare the nul-term, it's a
			   wildcard. */
			if (fw->ipv6.iniface_mask[strlen(fw->ipv6.iniface)] == 0)
				strcat(iface, "+");
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT(" %-6s ","in %s "), iface);

		if (fw->ipv6.invflags & IP6T_INV_VIA_OUT) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ipv6.outiface[0] != '\0') {
			strcat(iface, fw->ipv6.outiface);
			/* If it doesn't compare the nul-term, it's a
			   wildcard. */
			if (fw->ipv6.outiface_mask[strlen(fw->ipv6.outiface)] == 0)
				strcat(iface, "+");
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT("%-6s ","out %s "), iface);
	}

	fputc(fw->ipv6.invflags & IP6T_INV_SRCIP ? '!' : ' ', stdout);
	if (!memcmp(&fw->ipv6.smsk, &in6addr_any, sizeof in6addr_any) 
	    && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s/", addr_to_numeric(&(fw->ipv6.src)));
		else
			sprintf(buf, "%s/", addr_to_anyname(&(fw->ipv6.src)));
		strcat(buf, mask_to_numeric(&(fw->ipv6.smsk)));
		printf(FMT("%-19s ","%s "), buf);
	}

	fputc(fw->ipv6.invflags & IP6T_INV_DSTIP ? '!' : ' ', stdout);
	if (!memcmp(&fw->ipv6.dmsk, &in6addr_any, sizeof in6addr_any)
	    && !(format & FMT_NUMERIC))
		printf(FMT("%-19s","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			sprintf(buf, "%s/", addr_to_numeric(&(fw->ipv6.dst)));
		else
			sprintf(buf, "%s/", addr_to_anyname(&(fw->ipv6.dst)));
		strcat(buf, mask_to_numeric(&(fw->ipv6.dmsk)));
		printf(FMT("%-19s","-> %s"), buf);
	}

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

	IP6T_MATCH_ITERATE(fw, print_match, &fw->ipv6, format & FMT_NUMERIC);

	if (target) {
		if (target->print)
			/* Print the target information. */
			target->print(&fw->ipv6, t, format & FMT_NUMERIC);
	} else if (t->u.target_size != sizeof(*t))
		printf("[%u bytes of unknown target data] ",
		       t->u.target_size - sizeof(*t));

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);
}

static void
print_firewall_line(const struct ip6t_entry *fw,
		    const ip6tc_handle_t h)
{
	struct ip6t_entry_target *t;

	t = ip6t_get_target((struct ip6t_entry *)fw);
	print_firewall(fw, t->u.user.name, 0, FMT_PRINT_RULE, h);
}

static int
append_entry(const ip6t_chainlabel chain,
	     struct ip6t_entry *fw,
	     unsigned int nsaddrs,
	     const struct in6_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in6_addr daddrs[],
	     int verbose,
	     ip6tc_handle_t *handle)
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) {
		fw->ipv6.src = saddrs[i];
		for (j = 0; j < ndaddrs; j++) {
			fw->ipv6.dst = daddrs[j];
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= ip6tc_append_entry(chain, fw, handle);
		}
	}

	return ret;
}

static int
replace_entry(const ip6t_chainlabel chain,
	      struct ip6t_entry *fw,
	      unsigned int rulenum,
	      const struct in6_addr *saddr,
	      const struct in6_addr *daddr,
	      int verbose,
	      ip6tc_handle_t *handle)
{
	fw->ipv6.src = *saddr;
	fw->ipv6.dst = *daddr;

	if (verbose)
		print_firewall_line(fw, *handle);
	return ip6tc_replace_entry(chain, fw, rulenum, handle);
}

static int
insert_entry(const ip6t_chainlabel chain,
	     struct ip6t_entry *fw,
	     unsigned int rulenum,
	     unsigned int nsaddrs,
	     const struct in6_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in6_addr daddrs[],
	     int verbose,
	     ip6tc_handle_t *handle)
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) {
		fw->ipv6.src = saddrs[i];
		for (j = 0; j < ndaddrs; j++) {
			fw->ipv6.dst = daddrs[j];
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= ip6tc_insert_entry(chain, fw, rulenum, handle);
		}
	}

	return ret;
}

static unsigned char *
make_delete_mask(struct ip6t_entry *fw)
{
	/* Establish mask for comparison */
	unsigned int size;
	struct ip6tables_match *m;
	unsigned char *mask, *mptr;

	size = sizeof(struct ip6t_entry);
	for (m = ip6tables_matches; m; m = m->next)
		size += sizeof(struct ip6t_entry_match) + m->size;

	mask = fw_calloc(1, size
			 + sizeof(struct ip6t_entry_target)
			 + ip6tables_targets->size);

	memset(mask, 0xFF, sizeof(struct ip6t_entry));
	mptr = mask + sizeof(struct ip6t_entry);

	for (m = ip6tables_matches; m; m = m->next) {
		memset(mptr, 0xFF,
		       sizeof(struct ip6t_entry_match) + m->userspacesize);
		mptr += sizeof(struct ip6t_entry_match) + m->size;
	}

	memset(mptr, 0xFF, sizeof(struct ip6t_entry_target));
	mptr += sizeof(struct ip6t_entry_target);
	memset(mptr, 0xFF, ip6tables_targets->userspacesize);

	return mask;
}

static int
delete_entry(const ip6t_chainlabel chain,
	     struct ip6t_entry *fw,
	     unsigned int nsaddrs,
	     const struct in6_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in6_addr daddrs[],
	     int verbose,
	     ip6tc_handle_t *handle)
{
	unsigned int i, j;
	int ret = 1;
	struct ip6t_entry ipfw = *fw;
	unsigned char *mask;

	mask = make_delete_mask(fw);
	for (i = 0; i < nsaddrs; i++) {
		ipfw.ipv6.src = saddrs[i];
		for (j = 0; j < ndaddrs; j++) {
			ipfw.ipv6.dst = daddrs[j];
			if (verbose)
				print_firewall_line(fw, *handle);
			ret &= ip6tc_delete_entry(chain, &ipfw, mask, handle);
		}
	}
	return ret;
}

static int
check_packet(const ip6t_chainlabel chain,
	     struct ip6t_entry *fw,
	     unsigned int nsaddrs,
	     const struct in6_addr saddrs[],
	     unsigned int ndaddrs,
	     const struct in6_addr daddrs[],
	     int verbose,
	     ip6tc_handle_t *handle)
{
	int ret = 1;
	unsigned int i, j;
	struct ip6t_entry ipfw = *fw;
	const char *msg;

	for (i = 0; i < nsaddrs; i++) {
		ipfw.ipv6.src = saddrs[i];
		for (j = 0; j < ndaddrs; j++) {
			ipfw.ipv6.dst = daddrs[j];
			if (verbose)
				print_firewall_line(fw, *handle);
			msg = ip6tc_check_packet(chain, &ipfw, handle);
			if (!msg) ret = 0;
			else printf("%s\n", msg);
		}
	}

	return ret;
}

static int
for_each_chain(int (*fn)(const ip6t_chainlabel, int, ip6tc_handle_t *),
	       int verbose, int builtinstoo, ip6tc_handle_t *handle)
{
        int ret = 1;
	const char *chain;
	char *chains;
	unsigned int i, chaincount = 0;

	chain = ip6tc_first_chain(handle);
	while (chain) {
		chaincount++;
		chain = ip6tc_next_chain(handle);
        }

	chains = fw_malloc(sizeof(ip6t_chainlabel) * chaincount);
	i = 0;
	chain = ip6tc_first_chain(handle);
	while (chain) {
		strcpy(chains + i*sizeof(ip6t_chainlabel), chain);
		i++;
		chain = ip6tc_next_chain(handle);
        }

	for (i = 0; i < chaincount; i++) {
		if (!builtinstoo
		    && ip6tc_builtin(chains + i*sizeof(ip6t_chainlabel),
				    *handle))
			continue;
	        ret &= fn(chains + i*sizeof(ip6t_chainlabel), verbose, handle);
	}

	free(chains);
        return ret;
}

static int
flush_entries(const ip6t_chainlabel chain, int verbose,
	      ip6tc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(flush_entries, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Flushing chain `%s'\n", chain);
	return ip6tc_flush_entries(chain, handle);
}

static int
zero_entries(const ip6t_chainlabel chain, int verbose,
	     ip6tc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(zero_entries, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Zeroing chain `%s'\n", chain);
	return ip6tc_zero_entries(chain, handle);
}

static int
delete_chain(const ip6t_chainlabel chain, int verbose,
	     ip6tc_handle_t *handle)
{
	if (!chain)
		return for_each_chain(delete_chain, verbose, 0, handle);

	if (verbose)
	        fprintf(stdout, "Deleting chain `%s'\n", chain);
	return ip6tc_delete_chain(chain, handle);
}

static int
list_entries(const ip6t_chainlabel chain, int verbose, int numeric,
	     int expanded, int linenumbers, ip6tc_handle_t *handle)
{
	int found = 0;
	unsigned int format;
	const char *this;

	format = FMT_OPTIONS;
	if (!verbose)
		format |= FMT_NOCOUNTS;
	else
		format |= FMT_VIA;

	if (numeric)
		format |= FMT_NUMERIC;

	if (!expanded)
		format |= FMT_KILOMEGAGIGA;

	if (linenumbers)
		format |= FMT_LINENUMBERS;

	for (this = ip6tc_first_chain(handle);
	     this;
	     this = ip6tc_next_chain(handle)) {
		const struct ip6t_entry *i;
		unsigned int num;

		if (chain && strcmp(chain, this) != 0)
			continue;

		if (found) printf("\n");

		print_header(format, this, handle);
		i = ip6tc_first_rule(this, handle);

		num = 0;
		while (i) {
			print_firewall(i,
				       ip6tc_get_target(i, handle),
				       num++,
				       format,
				       *handle);
			i = ip6tc_next_rule(i, handle);
		}
		found = 1;
	}

	errno = ENOENT;
	return found;
}

static struct ip6t_entry *
generate_entry(const struct ip6t_entry *fw,
	       struct ip6tables_match *matches,
	       struct ip6t_entry_target *target)
{
	unsigned int size;
	struct ip6tables_match *m;
	struct ip6t_entry *e;

	size = sizeof(struct ip6t_entry);
	for (m = matches; m; m = m->next)
		size += m->m->u.match_size;

	e = fw_malloc(size + target->u.target_size);
	*e = *fw;
	e->target_offset = size;
	e->next_offset = size + target->u.target_size;

	size = 0;
	for (m = matches; m; m = m->next) {
		memcpy(e->elems + size, m->m, m->m->u.match_size);
		size += m->m->u.match_size;
	}
	memcpy(e->elems + size, target, target->u.target_size);

	return e;
}

int do_command6(int argc, char *argv[], char **table, ip6tc_handle_t *handle)
{
	struct ip6t_entry fw, *e = NULL;
	int invert = 0;
	unsigned int nsaddrs = 0, ndaddrs = 0;
	struct in6_addr *saddrs = NULL, *daddrs = NULL;

	int c, verbose = 0;
	const char *chain = NULL;
	const char *shostnetworkmask = NULL, *dhostnetworkmask = NULL;
	const char *policy = NULL, *newname = NULL;
	unsigned int rulenum = 0, options = 0, command = 0;
	int ret = 1;
	struct ip6tables_match *m;
	struct ip6tables_target *target = NULL;
	const char *jumpto = "";
	char *protocol = NULL;

	memset(&fw, 0, sizeof(fw));

	/* Suppress error messages: we may add new options if we
           demand-load a protocol. */
	opterr = 0;

	while ((c = getopt_long(argc, argv,
	   "-A:C:D:R:I:L::F::Z::N:X::E:P:Vh::o:p:s:d:j:i:fbvnt:m:x",
					   opts, NULL)) != -1) {
		switch (c) {
			/*
			 * Command selection
			 */
		case 'A':
			add_command(&command, CMD_APPEND, CMD_NONE,
				    invert);
			chain = optarg;
			break;

		case 'D':
			add_command(&command, CMD_DELETE, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!') {
				rulenum = parse_rulenumber(argv[optind++]);
				command = CMD_DELETE_NUM;
			}
			break;

		case 'C':
			add_command(&command, CMD_CHECK, CMD_NONE,
				    invert);
			chain = optarg;
			break;

		case 'R':
			add_command(&command, CMD_REPLACE, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				rulenum = parse_rulenumber(argv[optind++]);
			else
				exit_error(PARAMETER_PROBLEM,
					   "-%c requires a rule number",
					   cmd2char(CMD_REPLACE));
			break;

		case 'I':
			add_command(&command, CMD_INSERT, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				rulenum = parse_rulenumber(argv[optind++]);
			else rulenum = 1;
			break;

		case 'L':
			add_command(&command, CMD_LIST, CMD_ZERO,
				    invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'F':
			add_command(&command, CMD_FLUSH, CMD_NONE,
				    invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'Z':
			add_command(&command, CMD_ZERO, CMD_LIST,
				    invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				&& argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'N':
			add_command(&command, CMD_NEW_CHAIN, CMD_NONE,
				    invert);
			chain = optarg;
			break;

		case 'X':
			add_command(&command, CMD_DELETE_CHAIN, CMD_NONE,
				    invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'E':
			add_command(&command, CMD_RENAME_CHAIN, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				newname = argv[optind++];
			break;

		case 'P':
			add_command(&command, CMD_SET_POLICY, CMD_NONE,
				    invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				policy = argv[optind++];
			else
				exit_error(PARAMETER_PROBLEM,
					   "-%c requires a chain and a policy",
					   cmd2char(CMD_SET_POLICY));
			break;

		case 'h':
			if (!optarg)
				optarg = argv[optind];

			/* iptables -p icmp -h */
			if (!ip6tables_matches && protocol)
				find_match(protocol, TRY_LOAD);

			exit_printhelp();

			/*
			 * Option selection
			 */
		case 'p':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_PROTOCOL, &fw.ipv6.invflags,
				   invert);

			/* Canonicalize into lower case */
			for (protocol = argv[optind-1]; *protocol; protocol++)
				*protocol = tolower(*protocol);

			protocol = argv[optind-1];
			fw.ipv6.proto = parse_protocol(protocol);
			fw.ipv6.flags |= IP6T_F_PROTO;

			if (fw.ipv6.proto == 0
			    && (fw.ipv6.invflags & IP6T_INV_PROTO))
				exit_error(PARAMETER_PROBLEM,
					   "rule would never match protocol");
			fw.nfcache |= NFC_IP6_PROTO;
			break;

		case 's':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_SOURCE, &fw.ipv6.invflags,
				   invert);
			shostnetworkmask = argv[optind-1];
			fw.nfcache |= NFC_IP6_SRC;
			break;

		case 'd':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_DESTINATION, &fw.ipv6.invflags,
				   invert);
			dhostnetworkmask = argv[optind-1];
			fw.nfcache |= NFC_IP6_DST;
			break;

		case 'j':
			set_option(&options, OPT_JUMP, &fw.ipv6.invflags,
				   invert);
			jumpto = parse_target(optarg);
			target = find_target(jumpto, TRY_LOAD);

			if (target) {
				size_t size;

				size = IP6T_ALIGN(sizeof(struct ip6t_entry_target)
						 + target->size);

				target->t = fw_calloc(1, size);
				target->t->u.target_size = size;
				strcpy(target->t->u.user.name, jumpto);
				target->init(target->t, &fw.nfcache);
			}
			break;


		case 'i':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_VIANAMEIN, &fw.ipv6.invflags,
				   invert);
			parse_interface(argv[optind-1],
					fw.ipv6.iniface,
					fw.ipv6.iniface_mask);
			fw.nfcache |= NFC_IP6_IF_IN;
			break;

		case 'o':
			if (check_inverse(optarg, &invert))
				optind++;
			set_option(&options, OPT_VIANAMEOUT, &fw.ipv6.invflags,
				   invert);
			parse_interface(argv[optind-1],
					fw.ipv6.outiface,
					fw.ipv6.outiface_mask);
			fw.nfcache |= NFC_IP6_IF_OUT;
			break;

		case 'v':
			if (!verbose)
				set_option(&options, OPT_VERBOSE,
					   &fw.ipv6.invflags, invert);
			verbose++;
			break;

		case 'm': {
			size_t size;

			if (invert)
				exit_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --match");

			m = find_match(optarg, LOAD_MUST_SUCCEED);
			size = IP6T_ALIGN(sizeof(struct ip6t_entry_match)
					 + m->size);
			m->m = fw_calloc(1, size);
			m->m->u.match_size = size;
			strcpy(m->m->u.user.name, m->name);
			m->init(m->m, &fw.nfcache);
		}
		break;

		case 'n':
			set_option(&options, OPT_NUMERIC, &fw.ipv6.invflags,
				   invert);
			break;

		case 't':
			if (invert)
				exit_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --table");
			*table = argv[optind-1];
			break;

		case 'x':
			set_option(&options, OPT_EXPANDED, &fw.ipv6.invflags,
				   invert);
			break;

		case 'V':
			if (invert)
				printf("Not %s ;-)\n", program_version);
			else
				printf("%s v%s\n",
				       program_name, program_version);
			exit(0);

		case '0':
			set_option(&options, OPT_LINENUMBERS, &fw.ipv6.invflags,
				   invert);
			break;

		case 1: /* non option */
			if (optarg[0] == '!' && optarg[1] == '\0') {
				if (invert)
					exit_error(PARAMETER_PROBLEM,
						   "multiple consecutive ! not"
						   " allowed");
				invert = TRUE;
				optarg[0] = '\0';
				continue;
			}
			printf("Bad argument `%s'\n", optarg);
			exit_tryhelp(2);

		default:
			/* FIXME: This scheme doesn't allow two of the same
			   matches --RR */
			if (!target
			    || !(target->parse(c - target->option_offset,
					       argv, invert,
					       &target->tflags,
					       &fw, &target->t))) {
				for (m = ip6tables_matches; m; m = m->next) {
					if (m->parse(c - m->option_offset,
						     argv, invert,
						     &m->mflags,
						     &fw,
						     &fw.nfcache,
						     &m->m))
						break;
				}

				/* If you listen carefully, you can
				   actually hear this code suck. */
				if (m == NULL
				    && protocol
				    && !find_proto(protocol, DONT_LOAD,
						   options&OPT_NUMERIC)
				    && (m = find_proto(protocol, TRY_LOAD,
						       options&OPT_NUMERIC))) {
					/* Try loading protocol */
					size_t size;

					size = IP6T_ALIGN(sizeof(struct ip6t_entry_match)
							 + m->size);

					m->m = fw_calloc(1, size);
					m->m->u.match_size = size;
					strcpy(m->m->u.user.name, m->name);
					m->init(m->m, &fw.nfcache);

					optind--;
					continue;
				}
				if (!m)
					exit_error(PARAMETER_PROBLEM,
						   "Unknown arg `%s'",
						   argv[optind-1]);
			}
		}
		invert = FALSE;
	}

	for (m = ip6tables_matches; m; m = m->next)
		m->final_check(m->mflags);
	if (target)
		target->final_check(target->tflags);

	/* Fix me: must put inverse options checking here --MN */

	if (optind < argc)
		exit_error(PARAMETER_PROBLEM,
			   "unknown arguments found on commandline");
	if (!command)
		exit_error(PARAMETER_PROBLEM, "no command specified");
	if (invert)
		exit_error(PARAMETER_PROBLEM,
			   "nothing appropriate following !");

	if (command & (CMD_REPLACE | CMD_INSERT | CMD_DELETE | CMD_APPEND |
	    CMD_CHECK)) {
		if (!(options & OPT_DESTINATION))
			dhostnetworkmask = "0.0.0.0/0";
		if (!(options & OPT_SOURCE))
			shostnetworkmask = "0.0.0.0/0";
	}

	if (shostnetworkmask)
		parse_hostnetworkmask(shostnetworkmask, &saddrs,
				      &(fw.ipv6.smsk), &nsaddrs);

	if (dhostnetworkmask)
		parse_hostnetworkmask(dhostnetworkmask, &daddrs,
				      &(fw.ipv6.dmsk), &ndaddrs);

	if ((nsaddrs > 1 || ndaddrs > 1) &&
	    (fw.ipv6.invflags & (IP6T_INV_SRCIP | IP6T_INV_DSTIP)))
		exit_error(PARAMETER_PROBLEM, "! not allowed with multiple"
			   " source or destination IP addresses");

	if (command == CMD_CHECK && fw.ipv6.invflags != 0)
		exit_error(PARAMETER_PROBLEM, "! not allowed with -%c",
			   cmd2char(CMD_CHECK));

	if (command == CMD_REPLACE && (nsaddrs != 1 || ndaddrs != 1))
		exit_error(PARAMETER_PROBLEM, "Replacement rule does not "
			   "specify a unique address");

	generic_opt_check(command, options);

	if (chain && strlen(chain) > IP6T_FUNCTION_MAXNAMELEN)
		exit_error(PARAMETER_PROBLEM,
			   "chain name `%s' too long (must be under %i chars)",
			   chain, IP6T_FUNCTION_MAXNAMELEN);

	*handle = ip6tc_init(*table);
	if (!*handle)
		exit_error(VERSION_PROBLEM,
			   "can't initialize iptables table `%s': %s",
			   *table, ip6tc_strerror(errno));

	if (command == CMD_CHECK
	    || command == CMD_APPEND
	    || command == CMD_DELETE
	    || command == CMD_INSERT
	    || command == CMD_REPLACE) {
		/* -o not valid with incoming packets. */
		if (options & OPT_VIANAMEOUT)
			if (strcmp(chain, "PREROUTING") == 0
		    	    || strcmp(chain, "INPUT") == 0) {
				exit_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEOUT),
					   chain);
		}

		/* -i not valid with outgoing packets */
		if (options & OPT_VIANAMEIN)
			if (strcmp(chain, "POSTROUTING") == 0
			    || strcmp(chain, "OUTPUT") == 0) {
				exit_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEIN),
					   chain);
		}

		if (target && ip6tc_is_chain(jumpto, *handle)) {
			printf("Warning: using chain %s, not extension\n",
			       jumpto);

			target = NULL;
		}

		/* If they didn't specify a target, or it's a chain
		   name, use standard. */
		if (!target
		    && (strlen(jumpto) == 0
			|| ip6tc_is_chain(jumpto, *handle))) {
			size_t size;

			target = find_target(IP6T_STANDARD_TARGET,
					     LOAD_MUST_SUCCEED);

			size = sizeof(struct ip6t_entry_target)
				+ target->size;
			target->t = fw_calloc(1, size);
			target->t->u.target_size = size;
			strcpy(target->t->u.user.name, jumpto);
			target->init(target->t, &fw.nfcache);
		}

		if (!target) {
			struct ip6t_entry_target unknown_target;

			/* Don't know it.  Must be extension with no
                           options? */
			unknown_target.u.target_size = sizeof(unknown_target);
			strcpy(unknown_target.u.user.name, jumpto);

			e = generate_entry(&fw, ip6tables_matches,
					   &unknown_target);
		} else {
			e = generate_entry(&fw, ip6tables_matches, target->t);
		}
	}

	switch (command) {
	case CMD_APPEND:
		ret = append_entry(chain, e,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE,
				   handle);
		break;
	case CMD_CHECK:
		ret = check_packet(chain, e,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE, handle);
		break;
	case CMD_DELETE:
		ret = delete_entry(chain, e,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE,
				   handle);
		break;
	case CMD_DELETE_NUM:
		ret = ip6tc_delete_num_entry(chain, rulenum - 1, handle);
		break;
	case CMD_REPLACE:
		ret = replace_entry(chain, e, rulenum - 1,
				    saddrs, daddrs, options&OPT_VERBOSE,
				    handle);
		break;
	case CMD_INSERT:
		ret = insert_entry(chain, e, rulenum - 1,
				   nsaddrs, saddrs, ndaddrs, daddrs,
				   options&OPT_VERBOSE,
				   handle);
		break;
	case CMD_LIST:
		ret = list_entries(chain,
				   options&OPT_VERBOSE,
				   options&OPT_NUMERIC,
				   options&OPT_EXPANDED,
				   options&OPT_LINENUMBERS,
				   handle);
		break;
	case CMD_FLUSH:
		ret = flush_entries(chain, options&OPT_VERBOSE, handle);
		break;
	case CMD_ZERO:
		ret = zero_entries(chain, options&OPT_VERBOSE, handle);
		break;
	case CMD_LIST|CMD_ZERO:
		ret = list_entries(chain,
				   options&OPT_VERBOSE,
				   options&OPT_NUMERIC,
				   options&OPT_EXPANDED,
				   options&OPT_LINENUMBERS,
				   handle);
		if (ret)
			ret = zero_entries(chain,
					   options&OPT_VERBOSE, handle);
		break;
	case CMD_NEW_CHAIN:
		ret = ip6tc_create_chain(chain, handle);
		break;
	case CMD_DELETE_CHAIN:
		ret = delete_chain(chain, options&OPT_VERBOSE, handle);
		break;
	case CMD_RENAME_CHAIN:
		ret = ip6tc_rename_chain(chain, newname,	handle);
		break;
	case CMD_SET_POLICY:
		ret = ip6tc_set_policy(chain, policy, handle);
		break;
	default:
		/* We should never reach this... */
		exit_tryhelp(2);
	}

	if (verbose > 1)
		dump_entries6(*handle);

	return ret;
}