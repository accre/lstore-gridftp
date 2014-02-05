# -*- cmake -*-

# - Find Globus libraries and includes
#
# This module defines
#    Globus_INCLUDE_DIR - where to find header files
#    Globus_LIBRARIES - the libraries needed to use Globus.
#    Globus_FOUND - If false didn't find Globus

# Find the include path
find_path(globus_inc globus/globus_gridftp_server.h)

if (globus_inc)
   find_path(Globus_INCLUDE_DIR globus_gridftp_server.h ${globus_inc} ${globus_inc}/globus)
endif (globus_inc)

#find_library(Globus_LIBRARY NAMES globus)

#if (Globus_LIBRARY AND Globus_INCLUDE_DIR)
if (Globus_INCLUDE_DIR)
    SET(Globus_FOUND "YES")
endif (Globus_INCLUDE_DIR)
#endif (Globus_LIBRARY AND Globus_INCLUDE_DIR)


if (Globus_FOUND)
   message(STATUS "Found Globus: ${Globus_INCLUDE_DIR} ${globus_inc}")
else (Globus_FOUND)
   message(STATUS "Could not find Globus library")
endif (Globus_FOUND)


MARK_AS_ADVANCED(
  Globus_LIBRARY
  Globus_INCLUDE_DIR
  Globus_FOUND
)

