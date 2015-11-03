CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

ADD_EXECUTABLE(mtr_bin mtr.c display.c getopt.c getopt1.c raw.c report.c select.c split.c asn.c)
TARGET_LINK_LIBRARIES(mtr_bin mtr m resolv)
SET_TARGET_PROPERTIES(mtr_bin PROPERTIES OUTPUT_NAME mtr)
