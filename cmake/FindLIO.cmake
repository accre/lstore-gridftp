# -*- cmake -*-

# - Find LIO libraries and includes
#
# This module defines
#    LIO_INCLUDE_DIR - where to find header files
#    LIO_LIBRARIES - the libraries needed to use LIO.
#    LIO_FOUND - If false didn't find LIO

# Find the include path
find_path(lio_inc lio/lio.h)

if (lio_inc)
   find_path(LIO_INCLUDE_DIR lio.h ${lio_inc}/lio)
endif (lio_inc)

find_library(LIO_LIBRARY NAMES lio)

if (LIO_LIBRARY AND LIO_INCLUDE_DIR)
    SET(LIO_FOUND "YES")
endif (LIO_LIBRARY AND LIO_INCLUDE_DIR)


if (LIO_FOUND)
   message(STATUS "Found LIO: ${LIO_LIBRARY} ${LIO_INCLUDE_DIR}")
else (LIO_FOUND)
   message(STATUS "Could not find LIO library")
endif (LIO_FOUND)


MARK_AS_ADVANCED(
  LIO_LIBRARY
  LIO_INCLUDE_DIR
  LIO_FOUND
)

