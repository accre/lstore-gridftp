
lib_LTLIBRARIES = libglobus_gridftp_server_lfs.la

JNIHDIR=@JNIHDIR@
INCLUDES= -I$(JNIHDIR) -I$(JNIHDIR)/linux @INCLUDE@

#libglobus_gridftp_server_lfs_la_SOURCES = globus_gridftp_server_lfs.c
libglobus_gridftp_server_lfs_la_LDFLAGS = -lcrypto -lz
libglobus_gridftp_server_lfs_la_SOURCES = \
    gridftp_lfs.h \
    gridftp_lfs_error.h \
    gridftp_lfs.c \
    gridftp_lfs_recv.c \
    gridftp_lfs_send.c \
    gridftp_lfs_stat.c \
    gridftp_lfs_buffers.c \
    gridftp_lfs_cksm.c

