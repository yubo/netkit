CMAKE_MINIMUM_REQUIRED(VERSION 2.6)


ADD_DEFINITIONS(-I./unix/include -I./nothreads/include -DLIBAGE=0
	-DLIBREVISION=2 -DLIBINTERFACE=11 -DVERSION="9.2.3")

ADD_LIBRARY(isc SHARED assertions.c base64.c bitstring.c buffer.c bufferlist.c commandline.c error.c event.c hash.c heap.c hex.c hmacmd5.c lex.c lfsr.c lib.c log.c md5.c mem.c mutexblock.c netaddr.c ondestroy.c quota.c random.c ratelimiter.c result.c rwlock.c serial.c sha1.c sockaddr.c string.c symtab.c task.c taskpool.c timer.c version.c unix/app.c unix/dir.c unix/entropy.c unix/errno2result.c unix/file.c unix/fsaccess.c unix/interfaceiter.c unix/keyboard.c unix/net.c unix/os.c unix/resource.c unix/socket.c unix/stdio.c unix/stdtime.c unix/strerror.c unix/syslog.c unix/time.c nls/msgcat.c nothreads/condition.c nothreads/mutex.c nothreads/thread.c)
