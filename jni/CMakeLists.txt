cmake_minimum_required (VERSION 2.6.4)
project (jicmp2)

# JNI header name
set (JNI_HEADER "IcmpSocket_java_interface.h")

# Output folder
set (CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/../dist")

# Java JNI headers
find_package(JNI REQUIRED)
message (STATUS "JNI_INCLUDE_DIRS=${JNI_INCLUDE_DIRS}")
message (STATUS "JNI_LIBRARIES=${JNI_LIBRARIES}")
include_directories(${JNI_INCLUDE_DIRS})

# Generic includes
INCLUDE (CheckIncludeFiles)
CHECK_INCLUDE_FILES (unistd.h HAVE_UNISTD_H)
CHECK_INCLUDE_FILES (string.h HAVE_STRING_H)
CHECK_INCLUDE_FILES (stdlib.h HAVE_STDLIB_H)
CHECK_INCLUDE_FILES (malloc.h HAVE_MALLOC_H)
CHECK_INCLUDE_FILES (getopt.h HAVE_GETOPT_H)
CHECK_INCLUDE_FILES (netinet/in.h HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES (netinet/ip.h HAVE_NETINET_IP_H)
CHECK_INCLUDE_FILES (netinet/ip_icmp.h HAVE_NETINET_IP_ICMP_H)
CHECK_INCLUDE_FILES (sys/socket.h HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES (sys/time.h HAVE_SYS_TIME_H)
CHECK_INCLUDE_FILES (errno.h HAVE_ERRNO_H)
CHECK_INCLUDE_FILES (netdb.h HAVE_NETDB_H)
CONFIGURE_FILE("${CMAKE_CURRENT_SOURCE_DIR}/include/config.h.in" "${CMAKE_CURRENT_SOURCE_DIR}/include/config.h")

# Turn all warnings into errors
IF(CMAKE_COMPILER_IS_GNUCC)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
ENDIF(CMAKE_COMPILER_IS_GNUCC)

# Build the shared library
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(jicmp2 MODULE src/IcmpSocket.c)
