# -*- cmake -*-

# - Find Globus libraries and includes
#
# This module defines
#    GLOBUS_INCLUDE_DIR - where to find header files
#    GLOBUS_LIBRARIES - the libraries needed to use GLOBUS.
#    GLOBUS_FOUND - If false didn't find Globus

# Find the include path
find_path(globus_inc_dir globus/globus_gridftp_server.h)

#if (globus_inc)
#   find_path(globus_inc_dir globus_gridftp_server.h ${globus_inc} ${globus_inc}/globus)
#endif (globus_inc)

find_path(globus_inc_config globus/globus_config.h
		PATHS /usr/lib64/globus/include/ 
		      /usr/lib/globus/include/)
message(STATUS "got config ${globus_inc} ${globus_inc_dir} ${globus_inc_config}")
#find_library(GLOBUS_LIBRARY NAMES globus)

#if (GLOBUS_LIBRARY AND GLOBUS_INCLUDE_DIR)
if (globus_inc_dir AND globus_inc_config)
  SET(GLOBUS_FOUND "YES")
    SET(GLOBUS_INCLUDE_DIR ${globus_inc_dir} ${globus_inc_config} ${globus_inc_config}/globus)
endif (globus_inc_dir AND globus_inc_config)
#endif (GLOBUS_LIBRARY AND GLOBUS_INCLUDE_DIR)


if (GLOBUS_FOUND)
   message(STATUS "Found Globus: ${GLOBUS_INCLUDE_DIR}")
else (GLOBUS_FOUND)
   message(STATUS "Could not find Globus library")
endif (GLOBUS_FOUND)


MARK_AS_ADVANCED(
  GLOBUS_LIBRARY
  GLOBUS_INCLUDE_DIR
  GLOBUS_FOUND
)

