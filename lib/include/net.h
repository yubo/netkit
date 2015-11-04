/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*  Prototypes for functions in net.c  */
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif
#include <sys/socket.h>
#include <sys/time.h>

#include "utils.h"

struct nettask;

struct nettask *net_init(int fstTTL, int maxTTL,
		int cpacketsize, int bitpattern, int tos, int af,
		int mtrtype, int remoteport, int tcp_timeout, int mark);
int net_preopen(struct nettask *t);
int net_selectsocket(struct nettask *t);
int net_open(struct nettask *t, struct hostent *host);
void net_reopen(struct nettask *t, struct hostent *address);
int net_set_interfaceaddress (struct nettask *t, char *InterfaceAddress); 
void net_reset(struct nettask *t);
void net_close(struct nettask *t);
int net_waitfd(struct nettask *t);
void net_process_return(struct nettask *t);
void net_harvest_fds(struct nettask *t);

int net_max(struct nettask *t);
int net_min(struct nettask *t);
ip_t * net_addr(struct nettask *t, int at);
void * net_mpls(struct nettask *t, int at);
void * net_mplss(struct nettask *t, int, int);
int net_loss(struct nettask *t, int at);
int net_drop(struct nettask *t, int at);
int net_last(struct nettask *t, int at);
int net_best(struct nettask *t, int at);
int net_worst(struct nettask *t, int at);
int net_avg(struct nettask *t, int at);
int net_gmean(struct nettask *t, int at);
int net_stdev(struct nettask *t, int at);
int net_jitter(struct nettask *t, int at);
int net_jworst(struct nettask *t, int at);
int net_javg(struct nettask *t, int at);
int net_jinta(struct nettask *t, int at);
ip_t * net_addrs(struct nettask *t, int at, int i);
char *net_localaddr(struct nettask *t); 

int net_send_batch(struct nettask *t);
void net_end_transit(struct nettask *t);

int calc_deltatime(struct nettask *t, float WaitTime);

int net_returned(struct nettask *t, int at);
int net_xmit(struct nettask *t, int at);
int net_transit(struct nettask *t, int at);

int net_up(struct nettask *t, int at);

int* net_saved_pings(struct nettask *t, int at);
void net_save_xmit(struct nettask *t, int at);
void net_save_return(struct nettask *t, int at, int seq, int ms);
int net_duplicate(struct nettask *t, int at, int seq);

void sockaddrtop(struct sockaddr * saddr, char * strptr, size_t len );
int addrcmp( char * a, char * b, int af );
void addrcpy( char * a, char * b, int af );

void net_add_fds(struct nettask *t, fd_set *writefd, int *maxfd);
void net_process_fds(struct nettask *t, fd_set *writefd);

#define SAVED_PINGS 200
#define MAXPATH 8
#define MaxHost 256
#define MinSequence 33000
#define MaxSequence 65536
#define MinPort 1024

#define MAXPACKET 4470		/* largest test packet size */
#define MINPACKET 28		/* 20 bytes IP header and 8 bytes ICMP or UDP */
#define MAXLABELS 8 		/* http://kb.juniper.net/KB2190 (+ 3 just in case) */

/* stuff used by display such as report, curses... */
#define MAXFLD 20		/* max stats fields to display */

#if defined (__STDC__) && __STDC__
#define CONST const
#else
#define CONST /* */
#endif


/* XXX This doesn't really belong in this header file, but as the
   right c-files include it, it will have to do for now. */

/* dynamic field drawing */
struct fields {
  CONST unsigned char key;
  CONST char *descr;
  CONST char *title;
  CONST char *format;
  int length;
  int (*net_xxx)();
};

extern struct fields data_fields[MAXFLD];


/* keys: the value in the array is the index number in data_fields[] */
extern int fld_index[];
extern unsigned char fld_active[];
extern char available_options[];

ip_t unspec_addr;

/* MPLS label object */
struct mplslen {
  unsigned long label[MAXLABELS]; /* label value */
  uint8 exp[MAXLABELS]; /* experimental bits */
  uint8 ttl[MAXLABELS]; /* MPLS TTL */
  char s[MAXLABELS]; /* bottom of stack */
  char labels; /* how many labels did we get? */
};

void decodempls(int, char *, struct mplslen *, int);

struct nethost {
	ip_t addr;
	ip_t addrs[MAXPATH];	/* for multi paths byMin */
	int xmit;
	int returned;
	int sent;
	int up;
	long long var;/* variance, could be overflowed */
	int last;
	int best;
	int worst;
	int avg;	/* average:  addByMin */
	int gmean;	/* geometirc mean: addByMin */
	int jitter;	/* current jitter, defined as t1-t0 addByMin */
	/*int jbest;*/	/* min jitter, of cause it is 0, not needed */
	int javg;	/* avg jitter */
	int jworst;	/* max jitter */
	int jinta;	/* estimated variance,? rfc1889's "Interarrival Jitter" */
	int transit;
	int saved[SAVED_PINGS];
	int saved_seq_offset;
	struct mplslen mpls;
	struct mplslen mplss[MAXPATH];
};


struct sequence {
	int index;
	int transit;
	int saved_seq;
	struct timeval time;
	int socket;
};


struct nettask {
	int fstTTL;		/* initial hub(ttl) to ping byMin */
	int maxTTL;		/* last hub to ping byMin*/
	int cpacketsize;		/* packet size used by ping */
	int packetsize;		/* packet size used by ping */
	int bitpattern;		/* packet bit pattern used by ping */
	int tos;			/* type of service set in ping packet*/
	int af;			/* address family of remote target */
	int mtrtype;		/* type of query packet used */
	int remoteport;          /* target port for TCP tracing */
	int tcp_timeout;             /* timeout for TCP connections */
	int mark;		/* SO_MARK to set for ping packet*/
	struct nethost host[MaxHost];
	struct sequence sequence[MaxSequence];
	struct timeval reset;

	int batch_at;
	int numhosts;

#ifdef ENABLE_IPV6
	struct sockaddr_storage sourcesockaddr_struct;
	struct sockaddr_storage remotesockaddr_struct;
	struct sockaddr_in6 * ssa6;
	struct sockaddr_in6 * rsa6;
#else
	struct sockaddr_in sourcesockaddr_struct;
	struct sockaddr_in remotesockaddr_struct;
#endif
	
	struct sockaddr * sourcesockaddr;
	struct sockaddr * remotesockaddr;
	struct sockaddr_in * ssa4;
	struct sockaddr_in * rsa4;
	
	ip_t * sourceaddress;
	ip_t * remoteaddress;

	/* BSD-derived kernels use host byte order for the IP length and 
	offset fields when using raw sockets.  We detect this automatically at 
	run-time and do the right thing. */
	int BSDfix;
	
	
/*	int    timestamp; */
	int    sendsock4;
	int    sendsock4_icmp;
	int    sendsock4_udp;
	int    recvsock4;
	int    sendsock6;
	int    sendsock6_icmp;
	int    sendsock6_udp;
	int    recvsock6;
	int    sendsock;
	int    recvsock;

	/* XXX How do I code this to be IPV6 compatible??? */
#ifdef ENABLE_IPV6
	char localaddr[INET6_ADDRSTRLEN];
#else
#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
	char localaddr[INET_ADDRSTRLEN];
#endif

};


