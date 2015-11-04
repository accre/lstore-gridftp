cmake_minimum_required(VERSION 2.8)
if(NOT (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} LESS 3.0))
	# only CMAKE 3.0 and greater supports this (NOT ... LESS because CMAKE does not have a GREATER_OR_EQUAL_TO conditional)
	# Not needed for older versions because older versions obviously use the old policy without specially requesting it
	cmake_policy(SET CMP0048 OLD)
	# ^^^ use the old VERSION variable behavior
endif()
# Name this project
set(LSTORE_PROJECT_NAME "gridftp")
project(${LSTORE_PROJECT_NAME} C CXX)

# Include modules 
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(CheckIncludeFile)

# Detect compiler flags.
check_include_file(attr/xattr.h HAVE_ATTR_XATTR_H)
check_include_file(sys/xattr.h HAVE_SYS_XATTR_H)
configure_file(${CMAKE_SOURCE_DIR}/config.h.in
               ${CMAKE_SOURCE_DIR}/config.h)

# Find dependencies.
find_package(Jerasure REQUIRED)
find_package(ToolBox REQUIRED)
find_package(GOP REQUIRED)
find_package(IBP REQUIRED)
find_package(ZMQ REQUIRED)
find_package(CZMQ REQUIRED)
find_package(FUSE REQUIRED)
find_package(LIO REQUIRED)
find_package(Globus REQUIRED)

include_directories(   
    ${JERASURE_INCLUDE_DIR} ${TOOLBOX_INCLUDE_DIR} ${GOP_INCLUDE_DIR}
    ${IBP_INCLUDE_DIR} ${FUSE_INCLUDE_DIR} ${CZMQ_INCLUDE_DIR}
    ${GLOBUS_INCLUDE_DIR} ${LIO_INCLUDE_DIR}
)

list(APPEND LIBS
    ${IBP_LIBRARY} ${GOP_LIBRARY} ${CZMQ_LIBRARY} ${TOOLBOX_LIBRARY}
    ${JERASURE_LIBRARY} ${ZMQ_LIBRARY} ${FUSE_LIBRARIES} ${GLOBUS_LIBRARY}
    ${LIO_LIBRARY}
)

set(LSTORE_PROJECT_OBJS
    src/gridftp_lfs.c src/gridftp_lfs_recv.c src/gridftp_lfs_send.c
    src/gridftp_lfs_stat.c src/statsd-client.c src/gridftp_lfs_base.c
    src/gridftp_lfs_util.c src/gridftp_lfs_command.c src/gridftp_lfs_checksum.c
    src/gridftp_lfs_config.c
)

set(LSTORE_LIBRARY_NAME globus_gridftp_server_lfs)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror-implicit-function-declaration")
# Common functionality is stored here
include(cmake/LStoreCommon.cmake)

