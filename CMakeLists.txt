CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(netkit C)

SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/exec)

ADD_DEFINITIONS(-I. -I./include -I${CMAKE_SOURCE_DIR}/include
	-I${CMAKE_SOURCE_DIR}/lib/mtr/include
	-I${CMAKE_SOURCE_DIR}/lib/traceroute/include
	-g -O2 -Wall -Wno-pointer-sign -Wno-unused-result)

add_subdirectory(lib/dns)
add_subdirectory(lib/isc)
add_subdirectory(lib/traceroute)
add_subdirectory(lib/mtr)
add_subdirectory(bin)
