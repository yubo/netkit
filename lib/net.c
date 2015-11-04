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

#include "config.h"

#if defined(HAVE_SYS_XTI_H)
#include <sys/xti.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <memory.h>
#include <unistd.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>

#include "utils.h"
#include "net.h"
#include "dns.h"

/*  We can't rely on header files to provide this information, because
	the fields have different names between, for instance, Linux and 
	Solaris  */
struct ICMPHeader {
	uint8 type;
	uint8 code;
	uint16 checksum;
	uint16 id;
	uint16 sequence;
};

/* Structure of an UDP header.  */
struct UDPHeader {
	uint16 srcport;
	uint16 dstport;
	uint16 length;
	uint16 checksum;
};

/* Structure of an TCP header, as far as we need it.  */
struct TCPHeader {
	uint16 srcport;
	uint16 dstport;
	uint32 seq;
};

/* Structure of an SCTP header */
struct SCTPHeader {
	uint16 srcport;
	uint16 dstport;
	uint32 veri_tag;
};

/* Structure of an IPv4 UDP pseudoheader.  */
struct UDPv4PHeader {
	uint32 saddr;
	uint32 daddr;
	uint8 zero;
	uint8 protocol;
	uint16 len;
};

/*  Structure of an IP header.  */
struct IPHeader {
	uint8 version;
	uint8 tos;
	uint16 len;
	uint16 id;
	uint16 frag;
	uint8 ttl;
	uint8 protocol;
	uint16 check;
	uint32 saddr;
	uint32 daddr;
};


#define ICMP_ECHO		8
#define ICMP_ECHOREPLY		0

#define ICMP_TSTAMP		13
#define ICMP_TSTAMPREPLY	14

#define ICMP_TIME_EXCEEDED	11
#define ICMP_UNREACHABLE        3

#ifndef SOL_IP
#define SOL_IP 0
#endif

/* Configuration parameter: How many queries to unknown hosts do we
   send? (This limits the amount of traffic generated if a host is not
   reachable) */
#define MAX_UNKNOWN_HOSTS 5



struct nettask *net_init( int fstTTL, int maxTTL,
		int cpacketsize, int bitpattern, int tos, int af,
		int mtrtype, int remoteport, int tcp_timeout, int mark){
	struct nettask *t;
	t = (struct nettask *)calloc(1, sizeof(*t));
	t->fstTTL = fstTTL;
	t->maxTTL = maxTTL;
	t->cpacketsize = cpacketsize;
	t->bitpattern = bitpattern;
	t->tos = tos;
	t->af = af;
	t->mtrtype = mtrtype;
	t->remoteport = remoteport;
	t->tcp_timeout = tcp_timeout;
	t->mark = mark;
#ifdef ENABLE_IPV6
	t->ssa6 = (struct sockaddr_in6 *) &t->sourcesockaddr_struct;
	t->rsa6 = (struct sockaddr_in6 *) &t->remotesockaddr_struct;
#endif
	t->sourcesockaddr = (struct sockaddr *) &t->sourcesockaddr_struct;
	t->remotesockaddr = (struct sockaddr *) &t->remotesockaddr_struct;
	t->ssa4 = (struct sockaddr_in *) &t->sourcesockaddr_struct;
	t->rsa4 = (struct sockaddr_in *) &t->remotesockaddr_struct;
	t->numhosts = 10;
	t->batch_at = 0;
	t->BSDfix = 0;
	return t;
}


/* return the number of microseconds to wait before sending the next
   ping */
int calc_deltatime (struct nettask *t, float waittime)
{
	waittime /= t->numhosts;
	return 1000000 * waittime;
}


/* This doesn't work for odd sz. I don't know enough about this to say
   that this is wrong. It doesn't seem to cripple mtr though. -- REW */
int checksum(void *data, int sz) 
{
	unsigned short *ch;
	unsigned int sum;

	sum = 0;
	ch = data;
	sz = sz / 2;
	while (sz--) {
		sum += *(ch++);
	}

	sum = (sum >> 16) + (sum & 0xffff);  

	return (~sum & 0xffff);  
}


/* Prepend pseudoheader to the udp datagram and calculate checksum */
int udp_checksum(struct nettask *t, void *pheader, void *udata, int psize, int dsize)
{
	unsigned int tsize = psize + dsize;
	char csumpacket[tsize];
	memset(csumpacket, (unsigned char) abs(t->bitpattern), abs(tsize));

	struct UDPv4PHeader *prepend = (struct UDPv4PHeader *) csumpacket;
	struct UDPv4PHeader *udppheader = (struct UDPv4PHeader *) pheader;
	prepend->saddr = udppheader->saddr;
	prepend->daddr = udppheader->daddr;
	prepend->zero = 0;
	prepend->protocol = udppheader->protocol;
	prepend->len = udppheader->len;

	struct UDPHeader *content = (struct UDPHeader *)(csumpacket + psize);
	struct UDPHeader *udpdata = (struct UDPHeader *) udata;
	content->srcport = udpdata->srcport;
	content->dstport = udpdata->dstport;
	content->length = udpdata->length;
	content->checksum = udpdata->checksum;

	return checksum(csumpacket,tsize);
}


void save_sequence(struct nettask *t, int index, int seq)
{
	//display_rawxmit(index, seq);

	t->sequence[seq].index = index;
	t->sequence[seq].transit = 1;
	t->sequence[seq].saved_seq = ++t->host[index].xmit;
	memset(&t->sequence[seq].time, 0, sizeof(t->sequence[seq].time));

	t->host[index].transit = 1;
	if (t->host[index].sent)
		t->host[index].up = 0;
	t->host[index].sent = 1;
	net_save_xmit(t, index);
}

int new_sequence(struct nettask *t, int index)
{
	static int next_sequence = MinSequence;
	int seq;

	seq = next_sequence++;
	if (next_sequence >= MaxSequence)
		next_sequence = MinSequence;

	save_sequence(t, index, seq);

	return seq;
}

/*  Attempt to connect to a TCP port with a TTL */
void net_send_tcp(struct nettask *t, int index)
{
	int ttl, s;
	int opt = 1;
	int port;
	struct sockaddr_storage local;
	struct sockaddr_storage remote;
	struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
	struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
	struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
	struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
	socklen_t len;

	ttl = index + 1;

	s = socket(t->af, SOCK_STREAM, 0);
	if (s < 0) {
		//display_clear();
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	memset(&local, 0, sizeof (local));
	memset(&remote, 0, sizeof (remote));
	local.ss_family = t->af;
	remote.ss_family = t->af;

	switch (t->af) {
		case AF_INET:
			addrcpy((void *) &local4->sin_addr, (void *) &t->ssa4->sin_addr, t->af);
			addrcpy((void *) &remote4->sin_addr, (void *) t->remoteaddress, t->af);
			remote4->sin_port = htons(t->remoteport);
			len = sizeof (struct sockaddr_in);
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			addrcpy((void *) &local6->sin6_addr, (void *) &t->ssa6->sin6_addr, t->af);
			addrcpy((void *) &remote6->sin6_addr, (void *) t->remoteaddress, t->af);
			remote6->sin6_port = htons(t->remoteport);
			len = sizeof (struct sockaddr_in6);
			break;
#endif
	}

	if (bind(s, (struct sockaddr *) &local, len)) {
		//display_clear();
		perror("bind()");
		exit(EXIT_FAILURE);
	}

	if (getsockname(s, (struct sockaddr *) &local, &len)) {
		//display_clear();
		perror("getsockname()");
		exit(EXIT_FAILURE);
	}

	opt = 1;
	if (ioctl(s, FIONBIO, &opt)) {
		//display_clear();
		perror("ioctl FIONBIO");
		exit(EXIT_FAILURE);
	}

	switch (t->af) {
		case AF_INET:
			if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl))) {
				//display_clear();
				perror("setsockopt IP_TTL");
				exit(EXIT_FAILURE);
			}
			if (setsockopt(s, IPPROTO_IP, IP_TOS, &t->tos, sizeof (t->tos))) {
				//display_clear();
				perror("setsockopt IP_TOS");
				exit(EXIT_FAILURE);
			}
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl))) {
				//display_clear();
				perror("setsockopt IP_TTL");
				exit(EXIT_FAILURE);
			}
			break;
#endif
	}

#ifdef SO_MARK
	if (t->mark >= 0 && setsockopt( s, SOL_SOCKET, SO_MARK, &t->mark, sizeof t->mark ) ) {
		perror( "setsockopt SO_MARK" );
		exit( EXIT_FAILURE );
	}
#endif

	switch (local.ss_family) {
		case AF_INET:
			port = ntohs(local4->sin_port);
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			port = ntohs(local6->sin6_port);
			break;
#endif
		default:
			//display_clear();
			perror("unknown AF?");
			exit(EXIT_FAILURE);
	}

	save_sequence(t, index, port);
	gettimeofday(&t->sequence[port].time, NULL);
	t->sequence[port].socket = s;

	connect(s, (struct sockaddr *) &remote, len);
}

/*  Attempt to connect to a SCTP port with a TTL */
void net_send_sctp(struct nettask *t, int index)
{
	int ttl, s;
	int opt = 1;
	int port;
	struct sockaddr_storage local;
	struct sockaddr_storage remote;
	struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
	struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
	struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
	struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
	socklen_t len;

	ttl = index + 1;

	s = socket(t->af, SOCK_STREAM, IPPROTO_SCTP);
	if (s < 0) {
		//display_clear();
		perror("socket()");
		exit(EXIT_FAILURE);
	}

	memset(&local, 0, sizeof (local));
	memset(&remote, 0, sizeof (remote));
	local.ss_family = t->af;
	remote.ss_family = t->af;

	switch (t->af) {
		case AF_INET:
			addrcpy((void *) &local4->sin_addr, (void *) &t->ssa4->sin_addr, t->af);
			addrcpy((void *) &remote4->sin_addr, (void *) t->remoteaddress, t->af);
			remote4->sin_port = htons(t->remoteport);
			len = sizeof (struct sockaddr_in);
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			addrcpy((void *) &local6->sin6_addr, (void *) &t->ssa6->sin6_addr, t->af);
			addrcpy((void *) &remote6->sin6_addr, (void *) t->remoteaddress, t->af);
			remote6->sin6_port = htons(t->remoteport);
			len = sizeof (struct sockaddr_in6);
			break;
#endif
	}

	if (bind(s, (struct sockaddr *) &local, len)) {
		//display_clear();
		perror("bind()");
		exit(EXIT_FAILURE);
	}

	if (getsockname(s, (struct sockaddr *) &local, &len)) {
		//display_clear();
		perror("getsockname()");
		exit(EXIT_FAILURE);
	}

	opt = 1;
	if (ioctl(s, FIONBIO, &opt)) {
		//display_clear();
		perror("ioctl FIONBIO");
		exit(EXIT_FAILURE);
	}

	switch (t->af) {
		case AF_INET:
			if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl))) {
				//display_clear();
				perror("setsockopt IP_TTL");
				exit(EXIT_FAILURE);
			}
			if (setsockopt(s, IPPROTO_IP, IP_TOS, &t->tos, sizeof (t->tos))) {
				//display_clear();
				perror("setsockopt IP_TOS");
				exit(EXIT_FAILURE);
			}
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl))) {
				//display_clear();
				perror("setsockopt IP_TTL");
				exit(EXIT_FAILURE);
			}
			break;
#endif
	}

#ifdef SO_MARK
	if (t->mark >= 0 && setsockopt( s, SOL_SOCKET, SO_MARK, &t->mark, sizeof t->mark ) ) {
		perror( "setsockopt SO_MARK" );
		exit( EXIT_FAILURE );
	}
#endif

	switch (local.ss_family) {
		case AF_INET:
			port = ntohs(local4->sin_port);
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			port = ntohs(local6->sin6_port);
			break;
#endif
		default:
			//display_clear();
			perror("unknown AF?");
			exit(EXIT_FAILURE);
	}

	save_sequence(t, index, port);
	gettimeofday(&t->sequence[port].time, NULL);
	t->sequence[port].socket = s;

	connect(s, (struct sockaddr *) &remote, len);
}

/*  Attempt to find the host at a particular number of hops away  */
void net_send_query(struct nettask *t, int index) 
{
	if (t->mtrtype == IPPROTO_TCP) {
		net_send_tcp(t, index);
		return;
	}

	if (t->mtrtype == IPPROTO_SCTP) {
		net_send_sctp(t, index);
		return;
	}

	/*ok  char packet[sizeof(struct IPHeader) + sizeof(struct ICMPHeader)];*/
	char packet[MAXPACKET];
	struct IPHeader *ip = (struct IPHeader *) packet;
	struct ICMPHeader *icmp = NULL;
	struct UDPHeader *udp = NULL;
	struct UDPv4PHeader *udpp = NULL;
	uint16 mypid;

	/*ok  int t->packetsize = sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + datasize;*/
	int rv;
	static int first=1;
	int ttl, iphsize = 0, echotype = 0, salen = 0;

	ttl = index + 1;

#ifdef ENABLE_IPV6
	/* offset for ipv6 checksum calculation */
	int offset = 6;
#endif

	if ( t->packetsize < MINPACKET ) t->packetsize = MINPACKET;
	if ( t->packetsize > MAXPACKET ) t->packetsize = MAXPACKET;

	memset(packet, (unsigned char) abs(t->bitpattern), abs(t->packetsize));

	switch ( t->af ) {
		case AF_INET:
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
			iphsize = 0;
			if ( setsockopt( t->sendsock, IPPROTO_IP, IP_TOS, &t->tos, sizeof t->tos ) ) {
				perror( "setsockopt IP_TOS" );
				exit( EXIT_FAILURE );
			}    
			if ( setsockopt( t->sendsock, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl ) ) {
				perror( "setsockopt IP_TTL" );
				exit( EXIT_FAILURE );
			}    
#else
			iphsize = sizeof (struct IPHeader);

			ip->version = 0x45;
			ip->tos = t->tos;
			ip->len = t->BSDfix ? abs(t->packetsize): htons (abs(t->packetsize));
			ip->id = 0;
			ip->frag = 0;    /* 1, if want to find mtu size? Min */
			ip->ttl = ttl;
			ip->protocol = t->mtrtype;
			ip->check = 0;

			/* BSD needs the source address here, Linux & others do not... */
			addrcpy( (void *) &(ip->saddr), (void *) &(t->ssa4->sin_addr), AF_INET );
			addrcpy( (void *) &(ip->daddr), (void *) t->remoteaddress, AF_INET );
#endif
			echotype = ICMP_ECHO;
			salen = sizeof (struct sockaddr_in);
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			iphsize = 0;
			if ( setsockopt( t->sendsock, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
						&ttl, sizeof ttl ) ) {
				perror( "setsockopt IPV6_UNICAST_HOPS" );
				exit( EXIT_FAILURE);
			}
			echotype = ICMP6_ECHO_REQUEST;
			salen = sizeof (struct sockaddr_in6);
			break;
#endif
	}

#ifdef SO_MARK
	if (t->mark >= 0 && setsockopt( t->sendsock, SOL_SOCKET, SO_MARK, &t->mark, sizeof t->mark ) ) {
		perror( "setsockopt SO_MARK" );
		exit( EXIT_FAILURE );
	}
#endif

	switch ( t->mtrtype ) {
		case IPPROTO_ICMP:
			icmp = (struct ICMPHeader *)(packet + iphsize);
			icmp->type     = echotype;
			icmp->code     = 0;
			icmp->checksum = 0;
			icmp->id       = getpid();
			icmp->sequence = new_sequence(t, index);
			icmp->checksum = checksum(icmp, abs(t->packetsize) - iphsize);

			gettimeofday(&t->sequence[icmp->sequence].time, NULL);
			break;

		case IPPROTO_UDP:
			udp = (struct UDPHeader *)(packet + iphsize);
			udp->checksum  = 0;
			mypid = (uint16)getpid();
			if (mypid < MinPort)
				mypid += MinPort;

			udp->srcport = htons(mypid);
			udp->length = abs(t->packetsize) - iphsize;
			if(!t->BSDfix)
				udp->length = htons(udp->length);

			udp->dstport = new_sequence(t, index);
			gettimeofday(&t->sequence[udp->dstport].time, NULL);
			udp->dstport = htons(udp->dstport);
			break;
	}

	switch ( t->af ) {
		case AF_INET:
			switch ( t->mtrtype ) {
				case IPPROTO_UDP:
					/* checksum is not mandatory. only calculate if we know ip->saddr */
					if (ip->saddr) {
						udpp = (struct UDPv4PHeader *)(malloc(sizeof(struct UDPv4PHeader)));
						udpp->saddr = ip->saddr;
						udpp->daddr = ip->daddr;
						udpp->protocol = ip->protocol;
						udpp->len = udp->length;
						udp->checksum = udp_checksum(t, udpp, udp, sizeof(struct UDPv4PHeader), abs(t->packetsize) - iphsize);
					}
					break;
			}

			ip->check = checksum(packet, abs(t->packetsize));
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			switch ( t->mtrtype ) {
				case IPPROTO_UDP:
					/* kernel checksum calculation */
					if ( setsockopt(t->sendsock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) ) {
						perror( "setsockopt IPV6_CHECKSUM" );
						exit( EXIT_FAILURE);
					}
					break;
			}
			break;
#endif
	}

	rv = sendto(t->sendsock, packet, abs(t->packetsize), 0, 
			t->remotesockaddr, salen);
	if (first && (rv < 0) && ((errno == EINVAL) || (errno == EMSGSIZE))) {
		/* Try the first packet again using host byte order. */
		ip->len = abs (t->packetsize);
		rv = sendto(t->sendsock, packet, abs(t->packetsize), 0, 
				t->remotesockaddr, salen);
		if (rv >= 0) {
			t->BSDfix = 1;
		}
	}
	first = 0;
}


/*   We got a return on something we sent out.  Record the address and
	 time.  */
void net_process_ping(struct nettask *t, int seq, struct mplslen mpls, void * addr, struct timeval now) 
{
	int index;
	int totusec;
	int oldavg;	/* usedByMin */
	int oldjavg;	/* usedByMin */
	int i;	/* usedByMin */
#ifdef ENABLE_IPV6
	char addrcopy[sizeof(struct in6_addr)];
#else
	char addrcopy[sizeof(struct in_addr)];
#endif

	/* Copy the from address ASAP because it can be overwritten */
	addrcpy( (void *) &addrcopy, addr, t->af );

	if (seq < 0 || seq >= MaxSequence)
		return;

	if (!t->sequence[seq].transit)
		return;
	t->sequence[seq].transit = 0;

	if (t->sequence[seq].socket > 0) {
		close(t->sequence[seq].socket);
		t->sequence[seq].socket = 0;
	}

	index = t->sequence[seq].index;

	totusec = (now.tv_sec  - t->sequence[seq].time.tv_sec ) * 1000000 +
		(now.tv_usec - t->sequence[seq].time.tv_usec);
	/* impossible? if( totusec < 0 ) totusec = 0 */;

	if ( addrcmp( (void *) &(t->host[index].addr),
				(void *) &unspec_addr, t->af ) == 0 ) {
		/* should be out of if as addr can change */
		addrcpy( (void *) &(t->host[index].addr), addrcopy, t->af );
		t->host[index].mpls = mpls;
		//display_rawhost(index, (void *) &(t->host[index].addr));

		/* multi paths */
		addrcpy( (void *) &(t->host[index].addrs[0]), addrcopy, t->af );
		t->host[index].mplss[0] = mpls;
	} else {
		for( i=0; i<MAXPATH; ) {
			if( addrcmp( (void *) &(t->host[index].addrs[i]), (void *) &addrcopy,
						t->af ) == 0 ||
					addrcmp( (void *) &(t->host[index].addrs[i]),
						(void *) &unspec_addr, t->af ) == 0 ) break;
			i++;
		}
		if( addrcmp( (void *) &(t->host[index].addrs[i]), addrcopy, t->af ) != 0 && 
				i<MAXPATH ) {
			addrcpy( (void *) &(t->host[index].addrs[i]), addrcopy, t->af );
			t->host[index].mplss[i] = mpls;
			//display_rawhost(index, (void *) &(t->host[index].addrs[i]));
		}
	}

	t->host[index].jitter = totusec - t->host[index].last;
	if (t->host[index].jitter < 0 ) t->host[index].jitter = - t->host[index].jitter;
	t->host[index].last = totusec;

	if (t->host[index].returned < 1) {
		t->host[index].best = t->host[index].worst = t->host[index].gmean = totusec;
		t->host[index].avg  = t->host[index].var  = 0;

		t->host[index].jitter = t->host[index].jworst = t->host[index].jinta= 0;
	}

	/* some time best can be too good to be true, experienced 
	 * at least in linux 2.4.x.
	 *  safe guard 1) best[index]>=best[index-1] if index>0
	 *             2) best >= average-20,000 usec (good number?)
	 if (index > 0) {
	 if (totusec < t->host[index].best &&
	 totusec>= t->host[index-1].best) t->host[index].best  = totusec;
	 } else {
	 if(totusec < t->host[index].best) t->host[index].best  = totusec;
	 }
	 */
	if (totusec < t->host[index].best ) t->host[index].best  = totusec;
	if (totusec > t->host[index].worst) t->host[index].worst = totusec;

	if (t->host[index].jitter > t->host[index].jworst)
		t->host[index].jworst = t->host[index].jitter;

	t->host[index].returned++;
	oldavg = t->host[index].avg;
	t->host[index].avg += (totusec - oldavg +.0) / t->host[index].returned;
	t->host[index].var += (totusec - oldavg +.0) * (totusec - t->host[index].avg) / 1000000;

	oldjavg = t->host[index].javg;
	t->host[index].javg += (t->host[index].jitter - oldjavg) / t->host[index].returned;
	/* below algorithm is from rfc1889, A.8 */
	t->host[index].jinta += t->host[index].jitter - ((t->host[index].jinta + 8) >> 4);

	if ( t->host[index].returned > 1 )
		t->host[index].gmean = pow( (double) t->host[index].gmean, (t->host[index].returned-1.0)/t->host[index].returned )
			* pow( (double) totusec, 1.0/t->host[index].returned );
	t->host[index].sent = 0;
	t->host[index].up = 1;
	t->host[index].transit = 0;

	net_save_return(t, index, t->sequence[seq].saved_seq, totusec);
	//display_rawping(index, totusec, seq);
}


/*  We know a packet has come in, because the main select loop has called us,
	now we just need to read it, see if it is for us, and if it is a reply 
	to something we sent, then call net_process_ping()  */
void net_process_return(struct nettask *t) 
{
	char packet[MAXPACKET];
#ifdef ENABLE_IPV6
	struct sockaddr_storage fromsockaddr_struct;
	struct sockaddr_in6 * fsa6 = (struct sockaddr_in6 *) &fromsockaddr_struct;
#else
	struct sockaddr_in fromsockaddr_struct;
#endif
	struct sockaddr * fromsockaddr = (struct sockaddr *) &fromsockaddr_struct;
	struct sockaddr_in * fsa4 = (struct sockaddr_in *) &fromsockaddr_struct;
	socklen_t fromsockaddrsize;
	int num;
	struct ICMPHeader *header = NULL;
	struct UDPHeader *udpheader = NULL;
	struct TCPHeader *tcpheader = NULL;
	struct SCTPHeader *sctpheader = NULL;
	struct timeval now;
	ip_t * fromaddress = NULL;
	int echoreplytype = 0, timeexceededtype = 0, unreachabletype = 0;
	int sequence = 0;

	/* MPLS decoding */
	struct mplslen mpls;
	mpls.labels = 0;

	gettimeofday(&now, NULL);
	switch ( t->af ) {
		case AF_INET:
			fromsockaddrsize = sizeof (struct sockaddr_in);
			fromaddress = (ip_t *) &(fsa4->sin_addr);
			echoreplytype = ICMP_ECHOREPLY;
			timeexceededtype = ICMP_TIME_EXCEEDED;
			unreachabletype = ICMP_UNREACHABLE;
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			fromsockaddrsize = sizeof (struct sockaddr_in6);
			fromaddress = (ip_t *) &(fsa6->sin6_addr);
			echoreplytype = ICMP6_ECHO_REPLY;
			timeexceededtype = ICMP6_TIME_EXCEEDED;
			unreachabletype = ICMP6_DST_UNREACH;
			break;
#endif
	}

	num = recvfrom(t->recvsock, packet, MAXPACKET, 0, 
			fromsockaddr, &fromsockaddrsize);

	switch ( t->af ) {
		case AF_INET:
			if((size_t) num < sizeof(struct IPHeader) + sizeof(struct ICMPHeader))
				return;
			header = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			if(num < sizeof(struct ICMPHeader))
				return;

			header = (struct ICMPHeader *) packet;
			break;
#endif
	}

	switch ( t->mtrtype ) {
		case IPPROTO_ICMP:
			if (header->type == echoreplytype) {
				if(header->id != (uint16)getpid())
					return;

				sequence = header->sequence;
			} else if (header->type == timeexceededtype) {
				switch ( t->af ) {
					case AF_INET:

						if ((size_t) num < sizeof(struct IPHeader) + 
								sizeof(struct ICMPHeader) + 
								sizeof (struct IPHeader) + 
								sizeof (struct ICMPHeader))
							return;
						header = (struct ICMPHeader *)(packet + sizeof (struct IPHeader) + 
								sizeof (struct ICMPHeader) + 
								sizeof (struct IPHeader));

						if(num > 160)
							decodempls(num, packet, &mpls, 156);

						break;
#ifdef ENABLE_IPV6
					case AF_INET6:
						if ( num < sizeof (struct ICMPHeader) + 
								sizeof (struct ip6_hdr) + sizeof (struct ICMPHeader) )
							return;
						header = (struct ICMPHeader *) ( packet + 
								sizeof (struct ICMPHeader) +
								sizeof (struct ip6_hdr) );

						if(num > 140)
							decodempls(num, packet, &mpls, 136);

						break;
#endif
				}

				if (header->id != (uint16)getpid())
					return;

				sequence = header->sequence;
			}
			break;

		case IPPROTO_UDP:
			if (header->type == timeexceededtype || header->type == unreachabletype) {
				switch ( t->af ) {
					case AF_INET:

						if ((size_t) num < sizeof(struct IPHeader) +
								sizeof(struct ICMPHeader) +
								sizeof (struct IPHeader) +
								sizeof (struct UDPHeader))
							return;
						udpheader = (struct UDPHeader *)(packet + sizeof (struct IPHeader) +
								sizeof (struct ICMPHeader) +
								sizeof (struct IPHeader));

						if(num > 160)
							decodempls(num, packet, &mpls, 156);

						break;
#ifdef ENABLE_IPV6
					case AF_INET6:
						if ( num < sizeof (struct ICMPHeader) +
								sizeof (struct ip6_hdr) + sizeof (struct UDPHeader) )
							return;
						udpheader = (struct UDPHeader *) ( packet +
								sizeof (struct ICMPHeader) +
								sizeof (struct ip6_hdr) );

						if(num > 140)
							decodempls(num, packet, &mpls, 136);

						break;
#endif
				}
				sequence = ntohs(udpheader->dstport);
			}
			break;

		case IPPROTO_TCP:
			if (header->type == timeexceededtype || header->type == unreachabletype) {
				switch ( t->af ) {
					case AF_INET:

						if ((size_t) num < sizeof(struct IPHeader) +
								sizeof(struct ICMPHeader) +
								sizeof (struct IPHeader) +
								sizeof (struct TCPHeader))
							return;
						tcpheader = (struct TCPHeader *)(packet + sizeof (struct IPHeader) +
								sizeof (struct ICMPHeader) +
								sizeof (struct IPHeader));

						if(num > 160)
							decodempls(num, packet, &mpls, 156);

						break;
#ifdef ENABLE_IPV6
					case AF_INET6:
						if ( num < sizeof (struct ICMPHeader) +
								sizeof (struct ip6_hdr) + sizeof (struct TCPHeader) )
							return;
						tcpheader = (struct TCPHeader *) ( packet +
								sizeof (struct ICMPHeader) +
								sizeof (struct ip6_hdr) );

						if(num > 140)
							decodempls(num, packet, &mpls, 136);

						break;
#endif
				}
				sequence = ntohs(tcpheader->srcport);
			}
			break;

		case IPPROTO_SCTP:
			if (header->type == timeexceededtype || header->type == unreachabletype) {
				switch ( t->af ) {
					case AF_INET:

						if ((size_t) num < sizeof(struct IPHeader) +
								sizeof(struct ICMPHeader) +
								sizeof (struct IPHeader) +
								sizeof (struct SCTPHeader))
							return;
						sctpheader = (struct SCTPHeader *)(packet + sizeof (struct IPHeader) +
								sizeof (struct ICMPHeader) +
								sizeof (struct IPHeader));

						if(num > 160)
							decodempls(num, packet, &mpls, 156);

						break;
#ifdef ENABLE_IPV6
					case AF_INET6:
						if ( num < sizeof (struct ICMPHeader) +
								sizeof (struct ip6_hdr) + sizeof (struct SCTPHeader) )
							return;
						sctpheader = (struct SCTPHeader *) ( packet +
								sizeof (struct ICMPHeader) +
								sizeof (struct ip6_hdr) );

						if(num > 140)
							decodempls(num, packet, &mpls, 136);

						break;
#endif
				}
				sequence = ntohs(sctpheader->srcport);
			}
			break;
	}
	if (sequence)
		net_process_ping(t, sequence, mpls, (void *) fromaddress, now);
}


ip_t *net_addr(struct nettask *t, int at) 
{
	return (ip_t *)&(t->host[at].addr);
}


ip_t *net_addrs(struct nettask *t, int at, int i) 
{
	return (ip_t *)&(t->host[at].addrs[i]);
}

void *net_mpls(struct nettask *t, int at)
{
	return (struct mplslen *)&(t->host[at].mplss);
}

void *net_mplss(struct nettask *t, int at, int i)
{
	return (struct mplslen *)&(t->host[at].mplss[i]);
}

int net_loss(struct nettask *t, int at) 
{
	if ((t->host[at].xmit - t->host[at].transit) == 0) 
		return 0;
	/* times extra 1000 */
	return 1000*(100 - (100.0 * t->host[at].returned / (t->host[at].xmit - t->host[at].transit)) );
}


int net_drop(struct nettask *t, int at) 
{
	return (t->host[at].xmit - t->host[at].transit) - t->host[at].returned;
}


int net_last(struct nettask *t, int at) 
{
	return (t->host[at].last);
}


int net_best(struct nettask *t, int at) 
{
	return (t->host[at].best);
}


int net_worst(struct nettask *t, int at) 
{
	return (t->host[at].worst);
}


int net_avg(struct nettask *t, int at) 
{
	return (t->host[at].avg);
}


int net_gmean(struct nettask *t, int at) 
{
	return (t->host[at].gmean);
}


int net_stdev(struct nettask *t, int at) 
{
	if( t->host[at].returned > 1 ) {
		return ( 1000.0 * sqrt( t->host[at].var/(t->host[at].returned -1.0) ) );
	} else {
		return( 0 );
	}
}


int net_jitter(struct nettask *t, int at) 
{ 
	return (t->host[at].jitter); 
}


int net_jworst(struct nettask *t, int at) 
{ 
	return (t->host[at].jworst); 
}


int net_javg(struct nettask *t, int at) 
{ 
	return (t->host[at].javg); 
}


int net_jinta(struct nettask *t, int at) 
{ 
	return (t->host[at].jinta); 
}


int net_max(struct nettask *t) 
{
	int at;
	int max;

	max = 0;
	/* for(at = 0; at < MaxHost-2; at++) { */
	for(at = 0; at < t->maxTTL-1; at++) {
		if ( addrcmp( (void *) &(t->host[at].addr),
					(void *) t->remoteaddress, t->af ) == 0 ) {
			return at + 1;
		} else if ( addrcmp( (void *) &(t->host[at].addr),
					(void *) &unspec_addr, t->af ) != 0 ) {
			max = at + 2;
		}
	}

	return max;
}


int net_min(struct nettask *t) 
{
	return ( t->fstTTL - 1 );
}


int net_returned(struct nettask *t, int at) 
{ 
	return t->host[at].returned;
}


int net_xmit(struct nettask *t, int at) 
{ 
	return t->host[at].xmit;
}


int net_transit(struct nettask *t, int at) 
{ 
	return t->host[at].transit;
}


int net_up(struct nettask *t, int at) 
{
	return t->host[at].up;
}


char * net_localaddr (struct nettask *t)
{
	return t->localaddr;
}


void net_end_transit(struct nettask *t) 
{
	int at;

	for(at = 0; at < MaxHost; at++) {
		t->host[at].transit = 0;
	}
}

int net_send_batch(struct nettask *t) 
{
	int n_unknown=0, i;

	/* randomized packet size and/or bit pattern if t->packetsize<0 and/or 
	   bitpattern<0.  abs(t->packetsize) and/or abs(bitpattern) will be used 
	   */
	if( t->batch_at < t->fstTTL ) {
		if( t->cpacketsize < 0 ) {
			/* Someone used a formula here that tried to correct for the 
			   "end-error" in "rand()". By "end-error" I mean that if you 
			   have a range for "rand()" that runs to 32768, and the 
			   destination range is 10000, you end up with 4 out of 32768 
			   0-2768's and only 3 out of 32768 for results 2769 .. 9999. 
			   As our detination range (in the example 10000) is much 
			   smaller (reasonable packet sizes), and our rand() range much 
			   larger, this effect is insignificant. Oh! That other formula
			   didn't work. */
			t->packetsize = MINPACKET + rand () % (-t->cpacketsize - MINPACKET);
		} else {
			t->packetsize = t->cpacketsize;
		}
		if( t->bitpattern < 0 ) {
			t->bitpattern = - (int)(256 + 255*(rand()/(RAND_MAX+0.1)));
		}
	}

	/* printf ("cpacketsize = %d, t->packetsize = %d\n", cpacketsize, t->packetsize);  */

	net_send_query(t, t->batch_at);

	for (i=t->fstTTL-1;i<t->batch_at;i++) {
		if ( addrcmp( (void *) &(t->host[i].addr), (void *) &unspec_addr, t->af ) == 0 )
			n_unknown++;

		/* The second condition in the next "if" statement was added in mtr-0.56, 
		   but I don't remember why. It makes mtr stop skipping sections of unknown
		   hosts. Removed in 0.65. 
		   If the line proves neccesary, it should at least NOT trigger that line 
		   when host[i].addr == 0 */
		if ( ( addrcmp( (void *) &(t->host[i].addr),
						(void *) t->remoteaddress, t->af ) == 0 )
				/* || (t->host[i].addr == t->host[batch_at].addr)  */)
			n_unknown = MaxHost; /* Make sure we drop into "we should restart" */
	}

	if (	/* success in reaching target */
			( addrcmp( (void *) &(t->host[t->batch_at].addr),
					   (void *) t->remoteaddress, t->af ) == 0 ) ||
			/* fail in consecuitive MAX_UNKNOWN_HOSTS (firewall?) */
			(n_unknown > MAX_UNKNOWN_HOSTS) ||
			/* or reach limit  */
			(t->batch_at >= t->maxTTL-1)) {
		t->numhosts = t->batch_at+1;
		t->batch_at = t->fstTTL - 1;
		return 1;
	}

	t->batch_at++;
	return 0;
}


static void set_fd_flags(int fd)
{
#if defined(HAVE_FCNTL) && defined(FD_CLOEXEC)
	int oldflags;

	if (fd < 0) return; 

	oldflags = fcntl(fd, F_GETFD);
	if (oldflags == -1) {
		perror("Couldn't get fd's flags");
		return;
	}
	if (fcntl(fd, F_SETFD, oldflags | FD_CLOEXEC))
		perror("Couldn't set fd's flags");
#endif
}

int net_preopen(struct nettask *t) 
{
	int trueopt = 1;

#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
	t->sendsock4_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	t->sendsock4_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
#else
	t->sendsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
#endif
	if (t->sendsock4 < 0) 
		return -1;
#ifdef ENABLE_IPV6
	t->sendsock6_icmp = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	t->sendsock6_udp = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
#endif

#ifdef IP_HDRINCL
	/*  FreeBSD wants this to avoid sending out packets with protocol type RAW
		to the network.  */
	if (setsockopt(t->sendsock4, SOL_IP, IP_HDRINCL, &trueopt, sizeof(trueopt))) {
		perror("setsockopt(IP_HDRINCL,1)");
		return -1;
	}
#endif /* IP_HDRINCL */

	t->recvsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (t->recvsock4 < 0)
		return -1;
	set_fd_flags(t->recvsock4);
#ifdef ENABLE_IPV6
	t->recvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (t->recvsock6 >= 0)
		set_fd_flags(t->recvsock6);
#endif

	return 0;
}


int net_selectsocket(struct nettask *t)
{
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
	switch ( t->mtrtype ) {
		case IPPROTO_ICMP:
			t->sendsock4 = t->sendsock4_icmp;
			break;
		case IPPROTO_UDP:
			t->sendsock4 = t->sendsock4_udp;
			break;
	}
#endif
	if (t->sendsock4 < 0)
		return -1;
#ifdef ENABLE_IPV6
	switch ( t->mtrtype ) {
		case IPPROTO_ICMP:
			t->sendsock6 = t->sendsock6_icmp;
			break;
		case IPPROTO_UDP:
			t->sendsock6 = t->sendsock6_udp;
			break;
	}
	if ((t->sendsock6 < 0) && (t->sendsock4 < 0))
		return -1;
#endif

	return 0;
}


int net_open(struct nettask *t, struct hostent * host) 
{
#ifdef ENABLE_IPV6
	struct sockaddr_storage name_struct;
#else
	struct sockaddr_in name_struct; 
#endif
	struct sockaddr * name = (struct sockaddr *) &name_struct;
	socklen_t len; 

	net_reset(t);

	t->remotesockaddr->sa_family = host->h_addrtype;

	switch ( host->h_addrtype ) {
		case AF_INET:
			t->sendsock = t->sendsock4;
			t->recvsock = t->recvsock4;
			addrcpy( (void *) &(t->rsa4->sin_addr), host->h_addr, AF_INET );
			t->sourceaddress = (ip_t *) &(t->ssa4->sin_addr);
			t->remoteaddress = (ip_t *) &(t->rsa4->sin_addr);
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			if (t->sendsock6 < 0 || t->recvsock6 < 0) {
				fprintf( stderr, "Could not open IPv6 socket\n" );
				exit( EXIT_FAILURE );
			}
			t->sendsock = t->sendsock6;
			t->recvsock = t->recvsock6;
			addrcpy( (void *) &(t->rsa6->sin6_addr), host->h_addr, AF_INET6 );
			t->sourceaddress = (ip_t *) &(t->ssa6->sin6_addr);
			t->remoteaddress = (ip_t *) &(t->rsa6->sin6_addr);
			break;
#endif
		default:
			fprintf( stderr, "net_open bad address type\n" );
			exit( EXIT_FAILURE );
	}

	len = sizeof name_struct; 
	getsockname (t->recvsock, name, &len);
	sockaddrtop( name, t->localaddr, sizeof t->localaddr );
	printf ("got localaddr: %s\n", t->localaddr); 

	return 0;
}


void net_reopen(struct nettask *t, struct hostent * addr) 
{
	int at;

	for(at = 0; at < MaxHost; at++) {
		memset(&t->host[at], 0, sizeof(t->host[at]));
	}

	t->remotesockaddr->sa_family = addr->h_addrtype;
	addrcpy( (void *) t->remoteaddress, addr->h_addr, addr->h_addrtype );

	switch ( addr->h_addrtype ) {
		case AF_INET:
			addrcpy( (void *) &(t->rsa4->sin_addr), addr->h_addr, AF_INET );
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			addrcpy( (void *) &(t->rsa6->sin6_addr), addr->h_addr, AF_INET6 );
			break;
#endif
		default:
			fprintf( stderr, "net_reopen bad address type\n" );
			exit( EXIT_FAILURE );
	}

	net_reset(t);
	net_send_batch(t);
}


void net_reset(struct nettask *t) 
{
	int at;
	int i;

	t->batch_at = t->fstTTL - 1;	/* above replacedByMin */
	t->numhosts = 10;

	for (at = 0; at < MaxHost; at++) {
		t->host[at].xmit = 0;
		t->host[at].transit = 0;
		t->host[at].returned = 0;
		t->host[at].sent = 0;
		t->host[at].up = 0;
		t->host[at].last = 0;
		t->host[at].avg  = 0;
		t->host[at].best = 0;
		t->host[at].worst = 0;
		t->host[at].gmean = 0;
		t->host[at].var = 0;
		t->host[at].jitter = 0;
		t->host[at].javg = 0;
		t->host[at].jworst = 0;
		t->host[at].jinta = 0;
		for (i=0; i<SAVED_PINGS; i++) {
			t->host[at].saved[i] = -2;	/* unsent */
		}
		t->host[at].saved_seq_offset = -SAVED_PINGS+2;
	}

	for (at = 0; at < MaxSequence; at++) {
		t->sequence[at].transit = 0;
		if (t->sequence[at].socket > 0) {
			close(t->sequence[at].socket);
			t->sequence[at].socket = 0;
		}
	}

	gettimeofday(&t->reset, NULL);
}


int net_set_interfaceaddress (struct nettask *t, char *InterfaceAddress)
{
	int len = 0;

	if (!InterfaceAddress) return 0; 

	t->sourcesockaddr->sa_family = t->af;
	switch ( t->af ) {
		case AF_INET:
			t->ssa4->sin_port = 0;
			if ( inet_aton( InterfaceAddress, &(t->ssa4->sin_addr) ) < 1 ) {
				fprintf( stderr, "mtr: bad interface address: %s\n", InterfaceAddress );
				return( 1 );
			}
			len = sizeof (struct sockaddr);
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			t->ssa6->sin6_port = 0;
			if ( inet_pton( t->af, InterfaceAddress, &(t->ssa6->sin6_addr) ) < 1 ) {
				fprintf( stderr, "mtr: bad interface address: %s\n", InterfaceAddress );
				return( 1 );
			}
			len = sizeof (struct sockaddr_in6);
			break;
#endif
	}

	if ( bind( t->sendsock, t->sourcesockaddr, len ) == -1 ) {
		perror("mtr: failed to bind to interface");
		return( 1 );
	}
	return 0; 
}



void net_close(struct nettask *t)
{
	if (t->sendsock4 >= 0) {
		close(t->sendsock4_icmp);
		close(t->sendsock4_udp);
	}
	if (t->recvsock4 >= 0) close(t->recvsock4);
	if (t->sendsock6 >= 0) {
		close(t->sendsock6_icmp);
		close(t->sendsock6_udp);
	}
	if (t->recvsock6 >= 0) close(t->recvsock6);
}


int net_waitfd(struct nettask *t)
{
	return t->recvsock;
}


int* net_saved_pings(struct nettask *t, int at)
{
	return t->host[at].saved;
}


void net_save_increment(struct nettask *t)
{
	int at;
	for (at = 0; at < MaxHost; at++) {
		memmove(t->host[at].saved, t->host[at].saved+1, (SAVED_PINGS-1)*sizeof(int));
		t->host[at].saved[SAVED_PINGS-1] = -2;
		t->host[at].saved_seq_offset += 1;
	}
}


void net_save_xmit(struct nettask *t, int at)
{
	if (t->host[at].saved[SAVED_PINGS-1] != -2) 
		net_save_increment(t);
	t->host[at].saved[SAVED_PINGS-1] = -1;
}


void net_save_return(struct nettask *t, int at, int seq, int ms)
{
	int idx;
	idx = seq - t->host[at].saved_seq_offset;
	if (idx < 0 || idx >= SAVED_PINGS) {
		return;
	}
	t->host[at].saved[idx] = ms;
}

/* Similar to inet_ntop but uses a sockaddr as it's argument. */
void sockaddrtop(struct sockaddr * saddr, char * strptr, size_t len ) {
	struct sockaddr_in *  sa4;
#ifdef ENABLE_IPV6
	struct sockaddr_in6 * sa6;
#endif

	switch ( saddr->sa_family ) {
		case AF_INET:
			sa4 = (struct sockaddr_in *) saddr;
			strncpy( strptr, inet_ntoa( sa4->sin_addr ), len - 1 );
			strptr[ len - 1 ] = '\0';
			return;
#ifdef ENABLE_IPV6
		case AF_INET6:
			sa6 = (struct sockaddr_in6 *) saddr;
			inet_ntop( sa6->sin6_family, &(sa6->sin6_addr), strptr, len );
			return;
#endif
		default:
			fprintf( stderr, "sockaddrtop unknown address type\n" );
			strptr[0] = '\0';
			return;
	}
}

/* Address comparison. */
int addrcmp( char * a, char * b, int af ) {
	int rc = -1;

	switch ( af ) {
		case AF_INET:
			rc = memcmp( a, b, sizeof (struct in_addr) );
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			rc = memcmp( a, b, sizeof (struct in6_addr) );
			break;
#endif
	}

	return rc;
}

/* Address copy. */
void addrcpy( char * a, char * b, int af ) {

	switch ( af ) {
		case AF_INET:
			memcpy( a, b, sizeof (struct in_addr) );
			break;
#ifdef ENABLE_IPV6
		case AF_INET6:
			memcpy( a, b, sizeof (struct in6_addr) );
			break;
#endif
	}
}

/* Decode MPLS */
void decodempls(int num, char *packet, struct mplslen *mpls, int offset) {

	int i;
	unsigned int ext_ver, ext_res, ext_chk, obj_hdr_len;
	u_char obj_hdr_class, obj_hdr_type;

	/* loosely derived from the traceroute-nanog.c
	 * decoding by Jorge Boncompte */
	ext_ver = packet[offset]>>4;
	ext_res = (packet[offset]&15)+ packet[offset+1];
	ext_chk = ((unsigned int)packet[offset+2]<<8)+packet[offset+3];

	/* Check for ICMP extension header */
	if (ext_ver == 2 && ext_res == 0 && ext_chk != 0 && num >= (offset+6)) {
		obj_hdr_len = ((int)packet[offset+4]<<8)+packet[offset+5];
		obj_hdr_class = packet[offset+6];
		obj_hdr_type = packet[offset+7];

		/* make sure we have an MPLS extension */
		if (obj_hdr_len >= 8 && obj_hdr_class == 1 && obj_hdr_type == 1) {
			/* how many labels do we have?  will be at least 1 */
			mpls->labels = (obj_hdr_len-4)/4;

			/* save all label objects */
			for(i=0; (i<mpls->labels) && (i < MAXLABELS) && (num >= (offset+8)+(i*4)); i++) {

				/* piece together the 20 byte label value */
				mpls->label[i] = ((unsigned long) (packet[(offset+8)+(i*4)] << 12 & 0xff000) +
						(unsigned int) (packet[(offset+9)+(i*4)] << 4 & 0xff0) +
						(packet[(offset+10)+(i*4)] >> 4 & 0xf));
				mpls->exp[i] = (packet[(offset+10)+(i*4)] >> 1) & 0x7;
				mpls->s[i] = (packet[(offset+10)+(i*4)] & 0x1); /* should be 1 if only one label */
				mpls->ttl[i] = packet[(offset+11)+(i*4)];
			}
		}
	}
}

/* Add open sockets to select() */
void net_add_fds(struct nettask *t, fd_set *writefd, int *maxfd)
{
	int at, fd;
	for (at = 0; at < MaxSequence; at++) {
		fd = t->sequence[at].socket;
		if (fd > 0) {
			FD_SET(fd, writefd);
			if (fd >= *maxfd)
				*maxfd = fd + 1;
		}
	}
}

/* check if we got connection or error on any fds */
void net_process_fds(struct nettask *t, fd_set *writefd)
{
	int at, fd, r;
	struct timeval now;
	uint64_t unow, utime;

	/* Can't do MPLS decoding */
	struct mplslen mpls;
	mpls.labels = 0;

	gettimeofday(&now, NULL);
	unow = now.tv_sec * 1000000L + now.tv_usec;

	for (at = 0; at < MaxSequence; at++) {
		fd = t->sequence[at].socket;
		if (fd > 0 && FD_ISSET(fd, writefd)) {
			r = write(fd, "G", 1);
			/* if write was successful, or connection refused we have
			 * (probably) reached the remote address. Anything else happens to the
			 * connection, we write it off to avoid leaking sockets */
			if (r == 1 || errno == ECONNREFUSED)
				net_process_ping(t, at, mpls, t->remoteaddress, now);
			else if (errno != EAGAIN) {
				close(fd);
				t->sequence[at].socket = 0;
			}
		}
		if (fd > 0) {
			utime = t->sequence[at].time.tv_sec * 1000000L + t->sequence[at].time.tv_usec;
			if (unow - utime > t->tcp_timeout) {
				close(fd);
				t->sequence[at].socket = 0;
			}
		}
	}
}

/* for GTK frontend */
void net_harvest_fds(struct nettask *t)
{
	fd_set writefd;
	int maxfd = 0;
	struct timeval tv;

	FD_ZERO(&writefd);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	net_add_fds(t, &writefd, &maxfd);
	select(maxfd, NULL, &writefd, NULL, &tv);
	net_process_fds(t, &writefd);
}
