#ifndef _UTILS_H_
#define _UTILS_H_
#include <stdint.h>
#include "utils.h"

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned long dword;

#ifdef ENABLE_IPV6
typedef struct in6_addr ip_t;
#else
typedef struct in_addr ip_t;
#endif

extern int enablempls;
extern int show_ips;

#ifdef __GNUC__
#define UNUSED __attribute__((__unused__))
#else
#define UNUSED
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t; 
#endif

char * trim(char * s);
#endif
