CMAKE_MINIMUM_REQUIRED(VERSION 2.6)


ADD_DEFINITIONS(-I${CMAKE_SOURCE_DIR}/lib/dns/sec/dst/include
	-I${CMAKE_SOURCE_DIR}/lib/isc/include
	-I${CMAKE_SOURCE_DIR}/lib/isc
	-I${CMAKE_SOURCE_DIR}/lib/isc/unix/include
	-I${CMAKE_SOURCE_DIR}/lib/isc/nothreads/include
	-DLIBAGE=0 -DLIBREVISION=2 -DLIBINTERFACE=11 -DVERSION="9.2.3")

ADD_LIBRARY(dns SHARED libdns.a a6.c acl.c adb.c byaddr.c cache.c callbacks.c compress.c db.c dbiterator.c dbtable.c diff.c dispatch.c dnssec.c forward.c journal.c keytable.c lib.c log.c lookup.c master.c masterdump.c message.c name.c ncache.c nxt.c peer.c rbt.c rbtdb.c rbtdb64.c rdata.c rdatalist.c rdataset.c rdatasetiter.c rdataslab.c request.c resolver.c result.c rootns.c sdb.c soa.c ssu.c stats.c tcpmsg.c time.c timer.c tkey.c tsig.c ttl.c validator.c version.c view.c xfrin.c zone.c zonekey.c zt.c  sec/dst/dst_api.c sec/dst/dst_lib.c sec/dst/dst_parse.c sec/dst/dst_result.c sec/dst/hmac_link.c sec/dst/key.c sec/dst/openssl_link.c sec/dst/openssldh_link.c sec/dst/openssldsa_link.c sec/dst/opensslrsa_link.c sec/dst/gssapi_link.c sec/dst/gssapictx.c)
