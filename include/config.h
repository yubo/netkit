/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.ac by autoheader.  */

/* Define to enable IPv6 */
#define ENABLE_IPV6 /**/

/* Define to 1 if you have the <arpa/nameser_compat.h> header file. */
#define HAVE_ARPA_NAMESER_COMPAT_H 1

/* Define to 1 if you have the `attron' function. */
#define HAVE_ATTRON 1

/* Define to 1 if you have the declaration of `errno', and to 0 if you don't.
   */
#define HAVE_DECL_ERRNO 1

/* Define to 1 if you have the `fcntl' function. */
#define HAVE_FCNTL 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `m' library (-lm). */
#define HAVE_LIBM 1

/* Define to 1 if you have the `nsl' library (-lnsl). */
/* #undef HAVE_LIBNSL */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <ncurses/curses.h> header file. */
/* #undef HAVE_NCURSES_CURSES_H */

/* Define to 1 if you have the <ncurses.h> header file. */
/* #define HAVE_NCURSES_H 1 */

/* Define to 1 if you have the `seteuid' function. */
#define HAVE_SETEUID 1

/* Define to 1 if you have the <socket.h> header file. */
/* #undef HAVE_SOCKET_H */

/* Define if your system has socklen_t */
#define HAVE_SOCKLEN_T /**/

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define if you have struct in_addr */
#define HAVE_STRUCT_INADDR /**/

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/xti.h> header file. */
/* #undef HAVE_SYS_XTI_H */

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define this if your curses library has the use_default_colors() command. */
#define HAVE_USE_DEFAULT_COLORS 1

/* Define if struct __res_state_ext needs to be defined. */
/* #undef NEED_RES_STATE_EXT */

/* Define if you don't have the curses libraries available. */
#define NO_CURSES 1

/* Define if you don't have the GTK+ libraries available. */
#define NO_GTK 1

/* Define if you don't have the herror() function available. */
/* #undef NO_HERROR */

/* Define to disable ipinfo lookup */
/* #undef NO_IPINFO */

/* Define if you don't have the strerror() function available. */
/* #undef NO_STRERROR */

/* Name of package */
#define PACKAGE "netkit"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME "netkit"

/* Define to the full name and version of this package. */
#define PACKAGE_STRING "netkit 0.86"

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME "netkit"

/* Define to the home page for this package. */
#define PACKAGE_URL ""

/* Define to the version of this package. */
#define PACKAGE_VERSION "0.86"

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/***
 *** This file is not to be included by any public header files, because
 *** it does not get installed.
 ***/

/* define to `int' if <sys/types.h> doesn't define.  */
/* #undef ssize_t */

/* define on DEC OSF to enable 4.4BSD style sa_len support */
/* #undef _SOCKADDR_LEN */

/* define if your system needs pthread_init() before using pthreads */
/* #undef NEED_PTHREAD_INIT */

/* define if your system has sigwait() */
/* #undef HAVE_SIGWAIT */

/* define if sigwait() is the UnixWare flavor */
/* #undef HAVE_UNIXWARE_SIGWAIT */

/* define on Solaris to get sigwait() to work using pthreads semantics */
/* #undef _POSIX_PTHREAD_SEMANTICS */

/* define if LinuxThreads is in use */
/* #undef HAVE_LINUXTHREADS */

/* define if sysconf() is available */
/* #undef HAVE_SYSCONF */

/* define if sysctlbyname() is available */
/* #undef HAVE_SYSCTLBYNAME */

/* define if catgets() is available */
#define HAVE_CATGETS 1

/* define if you have the NET_RT_IFLIST sysctl variable and sys/sysctl.h */
/* #undef HAVE_IFLIST_SYSCTL */

/* define if you need to #define _XPG4_2 before including sys/socket.h */
/* #undef NEED_XPG4_2_BEFORE_SOCKET_H */

/* define if you need to #define _XOPEN_SOURCE_ENTENDED before including
 * sys/socket.h
 */
/* #undef NEED_XSE_BEFORE_SOCKET_H */

/* define if chroot() is available */
#define HAVE_CHROOT 1

/* define if struct addrinfo exists */
#define HAVE_ADDRINFO 1

/* define if getaddrinfo() exists */
#define HAVE_GETADDRINFO 1

/* define if gai_strerror() exists */
#define HAVE_GAISTRERROR 1

/* define if arc4random() exists */
/* #undef HAVE_ARC4RANDOM */

/* define if pthread_setconcurrency() should be called to tell the
 * OS how many threads we might want to run.
 */
/* #undef CALL_PTHREAD_SETCONCURRENCY */

/* define if IPv6 is not disabled */
#define WANT_IPV6 1

/* define if flockfile() is available */
#define HAVE_FLOCKFILE 1

/* define if getc_unlocked() is available */
#define HAVE_GETCUNLOCKED 1

/* Shut up warnings about sputaux in stdio.h on BSD/OS pre-4.1 */
/* #undef SHUTUP_SPUTAUX */
#ifdef SHUTUP_SPUTAUX
struct __sFILE;
extern __inline int __sputaux(int _c, struct __sFILE *_p);
#endif

/* Shut up warnings about missing sigwait prototype on BSD/OS 4.0* */
/* #undef SHUTUP_SIGWAIT */
#ifdef SHUTUP_SIGWAIT
int sigwait(const unsigned int *set, int *sig);
#endif

/* Shut up warnings from gcc -Wcast-qual on BSD/OS 4.1. */
/* #undef SHUTUP_STDARG_CAST */
#if defined(SHUTUP_STDARG_CAST) && defined(__GNUC__)
#include <stdarg.h>		/* Grr.  Must be included *every time*. */
/*
 * The silly continuation line is to keep configure from
 * commenting out the #undef.
 */
#undef \
	va_start
#define	va_start(ap, last) \
	do { \
		union { const void *konst; long *var; } _u; \
		_u.konst = &(last); \
		ap = (va_list)(_u.var + __va_words(__typeof(last))); \
	} while (0)
#endif /* SHUTUP_STDARG_CAST && __GNUC__ */

/* define if the system has a random number generating device */
#define PATH_RANDOMDEV "/dev/random"

/* define if pthread_attr_getstacksize() is available */
/* #undef HAVE_PTHREAD_ATTR_GETSTACKSIZE */

/* define if pthread_attr_setstacksize() is available */
/* #undef HAVE_PTHREAD_ATTR_SETSTACKSIZE */

/* define if you have strerror in the C library. */
#define HAVE_STRERROR 1

/* Define to 1 if you have the <dlfcn.h> header file. */
/* #undef HAVE_DLFCN_H */

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `c' library (-lc). */
/* #undef HAVE_LIBC */

/* Define to 1 if you have the `c_r' library (-lc_r). */
/* #undef HAVE_LIBC_R */

/* Define to 1 if you have the `nsl' library (-lnsl). */
#define HAVE_LIBNSL 1

/* Define to 1 if you have the `pthread' library (-lpthread). */
/* #undef HAVE_LIBPTHREAD */

/* Define to 1 if you have the `socket' library (-lsocket). */
/* #undef HAVE_LIBSOCKET */

/* Define to 1 if you have the <linux/capability.h> header file. */
#define HAVE_LINUX_CAPABILITY_H 1

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the <sys/prctl.h> header file. */
#define HAVE_SYS_PRCTL_H 1

/* Define to 1 if you have the <sys/select.h> header file. */
#define HAVE_SYS_SELECT_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/sysctl.h> header file. */
#define HAVE_SYS_SYSCTL_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to 1 if you can safely include both <sys/time.h> and <time.h>. */
#define TIME_WITH_SYS_TIME 1
