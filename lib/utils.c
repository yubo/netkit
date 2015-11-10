#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "net.h"
#include "utils.h"

unsigned char fld_active[2*MAXFLD] = "LS NABWV";
int           fld_index[256];
char          available_options[MAXFLD];
int   enablempls = 0;
struct fields data_fields[MAXFLD] = {
  /* key, Remark, Header, Format, Width, CallBackFunc */
  {' ', "<sp>: Space between fields", " ",  " ",        1, &net_drop  },
  {'L', "L: Loss Ratio",          "Loss%",  " %4.1f%%", 6, &net_loss  },
  {'D', "D: Dropped Packets",     "Drop",   " %4d",     5, &net_drop  },
  {'R', "R: Received Packets",    "Rcv",    " %5d",     6, &net_returned},
  {'S', "S: Sent Packets",        "Snt",    " %5d",     6, &net_xmit  },
  {'N', "N: Newest RTT(ms)",      "Last",   " %5.1f",   6, &net_last  },
  {'B', "B: Min/Best RTT(ms)",    "Best",   " %5.1f",   6, &net_best  },
  {'A', "A: Average RTT(ms)",     "Avg",    " %5.1f",   6, &net_avg   },
  {'W', "W: Max/Worst RTT(ms)",   "Wrst",   " %5.1f",   6, &net_worst },
  {'V', "V: Standard Deviation",  "StDev",  " %5.1f",   6, &net_stdev },
  {'G', "G: Geometric Mean",      "Gmean",  " %5.1f",   6, &net_gmean },
  {'J', "J: Current Jitter",      "Jttr",   " %4.1f",   5, &net_jitter},
  {'M', "M: Jitter Mean/Avg.",    "Javg",   " %4.1f",   5, &net_javg  },
  {'X', "X: Worst Jitter",        "Jmax",   " %4.1f",   5, &net_jworst},
  {'I', "I: Interarrival Jitter", "Jint",   " %4.1f",   5, &net_jinta },
  {'\0', NULL, NULL, NULL, 0, NULL}
};

char * trim(char * s)
{
	char * p = s;
	int l = strlen(p);
	while(isspace(p[l-1]) && l) p[--l] = 0;
	while(*p && isspace(*p) && l) ++p, --l;
	return p;
}

static char *strlongip(struct nettask *t, ip_t * ip)
{
#ifdef ENABLE_IPV6
  static char addrstr[INET6_ADDRSTRLEN];

  return (char *) inet_ntop(t->af, ip, addrstr, sizeof addrstr );
#else
  return inet_ntoa( *ip );
#endif
}

static size_t snprint_addr(struct nettask *t, char *dst, size_t dst_len, ip_t *addr)
{
	if(addrcmp((void *) addr, (void *) &unspec_addr, t->af)) {
		return snprintf(dst, dst_len, "%s", strlongip(t, addr));
	} else 
		return snprintf(dst, dst_len, "%s", "???");
}

void init_fld_options (void)
{
  int i;

  for (i=0;i < 256;i++)
    fld_index[i] = -1;

  for (i=0;data_fields[i].key != 0;i++) {
    available_options[i] = data_fields[i].key;
    fld_index[data_fields[i].key] = i;
  }
  available_options[i] = 0;
}

void report(struct nettask *t, char *LocalHostname) 
{
	int i, j, at, max, z, w;
	struct mplslen *mpls, *mplss;
	ip_t *addr;
	ip_t *addr2 = NULL;  
	char name[81];
	char buf[1024];
	char fmt[16];
	int len=0;
	int len_hosts = 33;
	int reportwide = 1;

	if (reportwide)
	{
		// get the longest hostname
		len_hosts = strlen(LocalHostname);
		max = net_max(t);
		at  = net_min(t);
		for (; at < max; at++) {
			int nlen;
			addr = net_addr(t, at);
			if ((nlen = snprint_addr(t, name, sizeof(name), addr)))
				if (len_hosts < nlen)
					len_hosts = nlen;
		}
	}

	snprintf( fmt, sizeof(fmt), "HOST: %%-%ds", len_hosts);
	snprintf(buf, sizeof(buf), fmt, LocalHostname);
	len = reportwide ? strlen(buf) : len_hosts;
	for( i=0; i<MAXFLD; i++ ) {
		j = fld_index[fld_active[i]];
		if (j < 0) continue;

		snprintf( fmt, sizeof(fmt), "%%%ds", data_fields[j].length );
		snprintf( buf + len, sizeof(buf), fmt, data_fields[j].title );
		len +=  data_fields[j].length;
	}
	printf("%s\n",buf);

	max = net_max(t);
	at  = net_min(t);
	for(; at < max; at++) {
		addr = net_addr(t, at);
		mpls = net_mpls(t, at);
		snprint_addr(t, name, sizeof(name), addr);

		snprintf( fmt, sizeof(fmt), " %%2d.|-- %%-%ds", len_hosts);
		snprintf(buf, sizeof(buf), fmt, at+1, name);
		len = reportwide ? strlen(buf) : len_hosts;  
		for( i=0; i<MAXFLD; i++ ) {
			j = fld_index[fld_active [i]];
			if (j < 0) continue;

			/* 1000.0 is a temporay hack for stats usec to ms, impacted net_loss. */
			if( index( data_fields[j].format, 'f' ) ) {
				snprintf( buf + len, sizeof(buf), data_fields[j].format,
						data_fields[j].net_xxx(t, at) /1000.0 );
			} else {
				snprintf( buf + len, sizeof(buf), data_fields[j].format,
						data_fields[j].net_xxx(t, at) );
			}
			len +=  data_fields[j].length;
		}
		printf("%s\n",buf);

		/* This feature shows 'loadbalances' on routes */

		/* z is starting at 1 because addrs[0] is the same that addr */
		for (z = 1; z < MAXPATH ; z++) {
			addr2 = net_addrs(t, at, z);
			mplss = net_mplss(t, at, z);
			int found = 0;
			if ((addrcmp ((void *) &unspec_addr, (void *) addr2, t->af)) == 0)
				break;
			for (w = 0; w < z; w++)
				/* Ok... checking if there are ips repeated on same hop */
				if ((addrcmp ((void *)addr2, (void *)net_addrs(t, at,w), t->af)) == 0) {
					found = 1;
					break;
				}   

			if (!found) {

				int k;
				if (mpls->labels && z == 1 && enablempls) {
					for (k=0; k < mpls->labels; k++) {
						printf("    |  |+-- [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mpls->label[k], mpls->exp[k], mpls->s[k], mpls->ttl[k]);
					}
				}

				if (z == 1) {
					printf("    |  `|-- %s\n", strlongip(t, addr2));
					for (k=0; k < mplss->labels && enablempls; k++) {
						printf("    |   +-- [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mplss->label[k], mplss->exp[k], mplss->s[k], mplss->ttl[k]);
					}
				} else {
					printf ("    |   |-- %s\n", strlongip(t, addr2));
					for (k=0; k < mplss->labels && enablempls; k++) {
						printf("    |   +-- [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mplss->label[k], mplss->exp[k], mplss->s[k], mplss->ttl[k]);
					}
				}
			}
		}

		/* No multipath */
		if(mpls->labels && z == 1 && enablempls) {
			int k;
			for (k=0; k < mpls->labels; k++) {
				printf("    |   +-- [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mpls->label[k], mpls->exp[k], mpls->s[k], mpls->ttl[k]);
			}
		}
	}
}


