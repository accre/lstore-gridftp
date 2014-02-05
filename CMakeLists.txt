cmake_minimum_required(VERSION 2.6)

# make a project
project( GRIDFTP C CXX)

# Set some cmake defaults
set(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_BUILD_TYPE "Release")

set(CMAKE_INCLUDE_CURRENT_DIR on)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
#INCLUDE(CheckIncludeFile)
#include(${CMAKE_SOURCE_DIR}/cmake/Date.cmake)
#include(${CMAKE_SOURCE_DIR}/cmake/CompilerVersion.cmake)
#include(${CMAKE_SOURCE_DIR}/cmake/CompilerFlags.cmake)

#Prefer to use static libs
#if(WIN32)
    #set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
 #else(WIN32)
    #set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
 #endif(WIN32)

# get dependancies
find_package(OpenSSL REQUIRED)
find_package(APR REQUIRED)
find_package(APRUtil REQUIRED)
find_package(Phoebus)
find_package(Jerasure REQUIRED)
find_package(ToolBox REQUIRED)
find_package(GOP REQUIRED)
find_package(IBP REQUIRED)
find_package(ZMQ REQUIRED)
find_package(CZMQ REQUIRED)
find_package(FUSE REQUIRED)
find_package(Zlib REQUIRED)
find_package(XATTR REQUIRED)
find_package(LIO REQUIRED)
find_package(Globus REQUIRED)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_REQUIRED_FLAGS} -O0 -Wall -g -DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 ${XATTR_FOUND}" )
set(CMAKE_C_FLAGS_RELEASE "-O ${CMAKE_REQUIRED_FLAGS} -DHAVE_CONFIG_H -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 ${XATTR_FOUND}" )


include_directories(${OPENSSL_INCLUDE_DIR} ${APR_INCLUDE_DIR} ${APRUTIL_INCLUDE_DIR} ${PHOEBUS_INCLUDE_DIR} ${ZLIB_INCLUDE_DIR}
    ${HWLOC_INCLUDE_DIR} ${JERASURE_INCLUDE_DIR} ${TOOLBOX_INCLUDE_DIR} ${GOP_INCLUDE_DIR} ${IBP_INCLUDE_DIR} ${FUSE_INCLUDE_DIR} ${CZMQ_INCLUDE_DIR}
    ${XATTR_INCLUDE_DIR} ${LIO_INCLUDE_DIR} ${Globus_INCLUDE_DIR})
SET(LIBS ${LIBS} ${IBP_LIBRARY} ${GOP_LIBRARY} ${CZMQ_LIBRARY} ${TOOLBOX_LIBRARY} ${JERASURE_LIBRARY} ${OPENSSL_LIBRARIES} ${CRYPTO_LIBRARIES} 
    ${APR_LIBRARY} ${APRUTIL_LIBRARY} ${HWLOC_LIBRARY} ${ZMQ_LIBRARY} ${FUSE_LIBRARY} ${ZLIB_LIBRARY} ${XATTR_LIBRARY} ${LIO_LIBARY} pthread m dl rt)

#Make the version file
#set(LIO_CLIENT_VERSION "lio_client: v1.0.0")
#site_name(BUILD_HOST)
#Date(BUILD_DATE)
#CompilerVersion(COMPILER_VERSION)
#CompilerFlags(COMPILER_FLAGS)
#configure_file("${PROJECT_SOURCE_DIR}/lio_client_version.c.in" "${PROJECT_BINARY_DIR}/lio_client_version.c")

set(GRIDFTP_OBJS
    src/gridftp_lfs.c
    src/gridftp_lfs_recv.c
    src/gridftp_lfs_send.c
    src/gridftp_lfs_stat.c
    src/gridftp_lfs_buffers.c
    src/gridftp_lfs_cksm.c
)

ADD_LIBRARY( globus_gridftp_server_lfs SHARED ${GRIDFTP_OBJS})
#SET_TARGET_PROPERTIES(lio PROPERTIES CLEAN_DIRECT_OUTPUT 1)


install(TARGETS globus_gridftp_server_lfs DESTINATION lib)
