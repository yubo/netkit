CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

PROJECT(netkit C)
ADD_DEFINITIONS(-D_GNU_SOURCE)

#SET(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/exec)

ADD_DEFINITIONS(-I. -I./include -I${CMAKE_SOURCE_DIR}/include
	-I${CMAKE_SOURCE_DIR}/lib/include
	-g -O2 -Wall -Wno-pointer-sign -Wno-unused-result)

add_subdirectory(lib)
add_subdirectory(test)
