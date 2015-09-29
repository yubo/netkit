CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(netkit C)

add_subdirectory(dig)
add_subdirectory(mtr)
add_subdirectory(traceroute)

#ADD_EXECUTABLE(mtr_bin mtr.c)
#TARGET_LINK_LIBRARIES(mtr_bin mtr m resolv)
#SET_TARGET_PROPERTIES(mtr_bin PROPERTIES OUTPUT_NAME mtr)
#
#
#ADD_DEFINITIONS(
#	-I${CMAKE_SOURCE_DIR}/lib/dns/include
#	-I${CMAKE_SOURCE_DIR}/lib/dns/sec/dst/include
#	-I${CMAKE_SOURCE_DIR}/lib/isc/include
#	-I${CMAKE_SOURCE_DIR}/lib/isc/unix/include
#	-I${CMAKE_SOURCE_DIR}/lib/isc/nothreads/include
#	-DVERSION="9.2.3"
#	)
#ADD_EXECUTABLE(dig dig.c dighost.c)
#TARGET_LINK_LIBRARIES(dig dns isc m)
#
#ADD_DEFINITIONS(-D_GNU_SOURCE)
#ADD_EXECUTABLE(traceroute traceroute.c)
#TARGET_LINK_LIBRARIES(traceroute trace m)
