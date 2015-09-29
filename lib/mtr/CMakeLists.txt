CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

ADD_LIBRARY(mtr SHARED net.c dns.c raw.c split.c display.c report.c getopt.c getopt1.c select.c asn.c)
