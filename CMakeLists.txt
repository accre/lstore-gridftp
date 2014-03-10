cmake_minimum_required(VERSION 2.8)
# make a project
project(gridftp-lfs C CXX)

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
find_package(APR-ACCRE REQUIRED)
find_package(APRUtil-ACCRE REQUIRED)
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
SET(LIBS ${LIBS} ${LIO_LIBRARY} pthread m dl rt)

set(GRIDFTP_OBJS
    src/gridftp_lfs.c
    src/gridftp_lfs_recv.c
    src/gridftp_lfs_send.c
    src/gridftp_lfs_stat.c
    src/gridftp_lfs_buffers.c
    src/gridftp_lfs_cksm.c
    src/statsd-client.c
)

ADD_LIBRARY( globus_gridftp_server_lfs SHARED ${GRIDFTP_OBJS})
TARGET_LINK_LIBRARIES( globus_gridftp_server_lfs ${LIBS} )
set_target_properties(globus_gridftp_server_lfs PROPERTIES SOVERSION "1.0.0")
install(TARGETS globus_gridftp_server_lfs
            DESTINATION lib)
install(TARGETS globus_gridftp_server_lfs DESTINATION lib)

# packaging definitions
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "GridFTP integration with LFS")
SET(CPACK_PACKAGE_VENDOR "Andrew Melo <andrew.m.melo@vanderbilt.edu>")
SET(CPACK_GENERATOR "RPM")
#SET(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/ReadMe.txt")
#SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/Copyright.txt")
SET(CPACK_PACKAGE_VERSION_MAJOR "1")
SET(CPACK_PACKAGE_VERSION_MINOR "0")
SET(CPACK_PACKAGE_VERSION_PATCH "0")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
SET(CPACK_RPM_PACKAGE_REQUIRES "openssl >= 1.0.1f, zlib >= 1.2.8, apr >= 1.5.0, apr-util >= 1.5.3, accre-toolbox >= 1.1.0, accre-gop >= 1.1.0, ibp-client >= 1.0.0, czmq >= 1.4.1, lio >= 1.0.0 ")
#SET(CPACK_STRIP_FILES "bin/MyExecutable")
#SET(CPACK_SOURCE_STRIP_FILES "")
#SET(CPACK_PACKAGE_EXECUTABLES "MyExecutable" "My Executable")
INCLUDE(CPack)
