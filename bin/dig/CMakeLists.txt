CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(netkit C)

ADD_DEFINITIONS(
	-I${CMAKE_SOURCE_DIR}/lib/dns/include
	-I${CMAKE_SOURCE_DIR}/lib/dns/sec/dst/include
	-I${CMAKE_SOURCE_DIR}/lib/isc/include
	-I${CMAKE_SOURCE_DIR}/lib/isc/unix/include
	-I${CMAKE_SOURCE_DIR}/lib/isc/nothreads/include
	-DVERSION="9.2.3"
	)
ADD_EXECUTABLE(dig dig.c dighost.c)
TARGET_LINK_LIBRARIES(dig dns isc m)
