CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
#STATIC SHARED
ADD_DEFINITIONS(-D_GNU_SOURCE)
ADD_LIBRARY(trace SHARED clif.c as_lookups.c csum.c
	extension.c mod-dccp.c mod-icmp.c mod-raw.c
	mod-tcp.c mod-tcpconn.c mod-udp.c module.c
	poll.c random.c time.c)
