#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_INIT([gridftp-lfs], [0.0.1], [andrew.m.melo@vanderbilt.edu])

AM_INIT_AUTOMAKE([gridftp-lfs], [0.0.1])

AC_CONFIG_SRCDIR([src/gridftp_lfs.c])
#AC_CONFIG_HEADER([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

#AC_ARG_WITH(logdir, [  -with-logdir=LOG        Log directory location], [logdir=${withval}], [logdir=/var/log])

#AS_IF([ test "x${JAVA_HOME}" != x ], , [JAVA_HOME=/usr/java/latest])


#AC_ARG_WITH(java, [  --with-java=JAVA_HOME   Location of java], [JAVA_HOME=${withval}])
#AS_IF([ test -e ${JAVA_HOME}/include ], [JNIHDIR=${JAVA_HOME}/include], )
#AC_CHECK_FILE(${JNIHDIR}/jni.h, ,[AC_MSG_ERROR(Can't find jni.h in ${JNIHDIR})])

#AS_IF([ test -e ${JAVA_HOME}/jre/lib/amd64 ], LDFLAGS=["$LDFLAGS -L${JAVA_HOME}/jre/lib/amd64 -L${JAVA_HOME}/jre/lib/amd64/server"])
#AS_IF([ test -e ${JAVA_HOME}/jre/lib/i386 ], LDFLAGS=["$LDFLAGS -L${JAVA_HOME}/jre/lib/i386 -L${JAVA_HOME}/jre/lib/i386/server"])

# EPEL5 defaults
AC_CHECK_FILE(/usr/include/globus, INCLUDE=["$INCLUDE -I/usr/include/globus"])
AC_CHECK_FILE(/usr/lib64/globus/include, INCLUDE=["$INCLUDE -I/usr/lib64/globus/include"])
AC_CHECK_FILE(/usr/lib/globus/include, INCLUDE=["$INCLUDE -I/usr/lib/globus/include"])

AC_ARG_WITH(globus, [  --with-globus=GLOBUS_LOCATION Location of globus], [GLOBUSHOME=${withval}], [GLOBUSLOCATION=$GLOBUS_LOCATION])
AC_CHECK_FILE(${GLOBUSLOCATION}, ,[GLOBUSLOCATION=/opt/globus])
AC_CHECK_FILE(${GLOBUSLOCATION}/include/gcc64, INCLUDE=["$INCLUDE -I${GLOBUSLOCATION}/include/gcc64"])
AC_CHECK_FILE(${GLOBUSLOCATION}/include/gcc32, INCLUDE=["$INCLUDE -I${GLOBUSLOCATION}/include/gcc32"])

# Pull LIO
AC_ARG_WITH(lio, [  --with-lio= Location of LIO installation], [LIOHOME=${withval}], [LIOHOME=$LIO_HOME])
AC_CHECK_FILE(${LIOHOME}/include/lio/lio.h, INCLUDE=["$INCLUDE -I${LIOHOME}/include"],)
AC_CHECK_FILE(${LIOHOME}/include/lio/lio.h, INCLUDE=["$INCLUDE -I${LIOHOME}/include/lio"],)
AC_CHECK_FILE(${LIOHOME}/include/ibp/ibp.h, INCLUDE=["$INCLUDE -I${LIOHOME}/include/ibp"],)
AC_CHECK_FILE(${LIOHOME}/include/gop/gop_config.h, INCLUDE=["$INCLUDE -I${LIOHOME}/include/gop"],)
AC_CHECK_FILE(${LIOHOME}/include/toolbox/toolbox_config.h, INCLUDE=["$INCLUDE -I${LIOHOME}/include/toolbox"],)
# Try and find APR
AC_CHECK_FILE(${LIOHOME}/include/apr-1/apr_thread_pool.h, INCLUDE=["$INCLUDE -I${LIOHOME}/include/apr-1"])
AC_CHECK_FILE(/usr/include/apr-1/apr_thread_pool.h, INCLUDE=["$INCLUDE -I/usr/include/apr-1"])
AC_CHECK_FILE(/usr/local/include/apr-1/apr_thread_pool.h, INCLUDE=["$INCLUDE -I/usr/local/include/apr-1"])

AC_CHECK_FILE(${LIOHOME}/lib/liblio.so, LDFLAGS=["$LDFLAGS -L${LIOHOME}/lib"],)

# Checks for libraries.
AC_CHECK_LIB([z], [inflateInit_], , [AC_MSG_ERROR(Couldn't find zlib)])
AC_CHECK_LIB([crypto], [CRYPTO_malloc], ,[AC_MSG_ERROR(Couldn't find libcrypto)])
AC_CHECK_LIB([dl], [dlclose], ,[AC_MSG_ERROR(Couldn't find dl)])
AC_CHECK_LIB([xml2], [xmlNewNode], ,[AC_MSG_ERROR(Couldn't find xml2)])
AC_CHECK_LIB([ssl], [SSL_SESSION_new], ,[AC_MSG_ERROR(Couldn't find OpenSSL)])
#AC_CHECK_LIB([APR], [], ,[AC_MSG_ERROR(Couldn't find )], [-lapr-1])
AC_CHECK_LIB([apr-1], [apr_hash_clear], ,[AC_MSG_ERROR(Couldn't find APR-Util )] )
AC_CHECK_LIB([aprutil-1], [apr_thread_pool_create], ,[AC_MSG_ERROR(Couldn't find APR-Util )])
#AC_CHECK_LIB([ZMQ], [], ,[AC_MSG_ERROR(Couldn't find )], [-lzmq])
AC_CHECK_LIB([czmq], [zmq_msg_data], ,[AC_MSG_ERROR(Couldn't find CZMQ)] )
AC_CHECK_LIB([fuse], [fuse_get_context], ,[AC_MSG_ERROR(Couldn't find FUSE)] )
AC_CHECK_LIB([hwloc], [hwloc_topology_init], ,[AC_MSG_ERROR(Couldn't find hwloc)] )
AC_CHECK_LIB([jerasure], [jerasure_matrix_encode], ,[AC_MSG_ERROR(Couldn't find JErasure)] )
AC_CHECK_LIB([toolbox], [zigzag_encode], ,[AC_MSG_ERROR(Couldn't find ACCRE Toolbox)] )
#AC_CHECK_LIB([Opcodes], [], ,[AC_MSG_ERROR(Couldn't find )], [-lopcodes])

AC_CHECK_LIB([gop], [gop_timed_waitany], ,[AC_MSG_ERROR(Couldn't find GOP)] )
AC_CHECK_LIB([ibp], [new_ibp_copy_op], ,[AC_MSG_ERROR(Couldn't find IBP)] )
AC_CHECK_LIB([lio], [lfs_read], , [AC_MSG_ERROR(Could not find LIO)] )
#AC_CHECK_LIB([jsig], [signal], ,   [AC_MSG_ERROR(Could not find libjsig)], )

# Checks for header files.
AC_CHECK_HEADERS([unistd.h], ,[AC_MSG_ERROR(Could not find unistd.h header)])
#AC_CHECK_HEADERS([lio.h], ,[AC_MSG_ERROR(Could not find lio.h header)])
#AC_CHECK_HEADERS([globus_gridftp_server.h], ,[AC_MSG_ERROR(Could not find globus_gridftp_server.h header)])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_HEADER_STDC
AC_FUNC_MMAP
AC_FUNC_STRTOD
AC_CHECK_FUNCS([ftruncate gethostname memset munmap strdup strrchr])

if test "x${prefix}" == "xNONE" ; then
    prefix_resolved=${ac_default_prefix}
else
    eval "prefix_resolved=\"${prefix}\""
fi

if test "x${exec_prefix}" == "xNONE" ; then
    exec_prefix_resolved=${ac_default_prefix}
else
    eval "exec_prefix_resolved=\"${exec_prefix}\""
fi

if test "x${sysconfdir}" == "xNONE/etc" ; then
    sysconfdir_resolved=${ac_default_prefix}/etc
else
    eval "sysconfdir_resolved=\"${sysconfdir}\""
fi

if test "x${sbindir}" == "xNONE" ; then
    sbindir_resolved=${ac_default_prefix}/sbin
else
    eval "sbindir_resolved=\"${sbindir}\""
fi

if test "x${localstatedir}" == "xNONE" ; then
    localstatedir_resolved=${ac_default_prefix}/var
else
    eval "localstatedir_resolved=\"${localstatedir}\""
fi

if test "x${datadir}" == "xNONE" ; then
    datadir_resolved=${ac_default_prefix}/share
else
    eval "datadir_resolved=\"${datadir}\""
fi

#AC_SUBST(HADOOPHOME)
#AC_SUBST(JNIHDIR)
AC_SUBST(INCLUDE)
AC_SUBST(GLOBUSLOCATION)
AC_SUBST(logdir)
AC_SUBST(exec_prefix_resolved)
AC_SUBST(prefix_resolved)
AC_SUBST(sysconfdir_resolved)
AC_SUBST(datadir_resolved)
AC_SUBST(localstatedir_resolved)
AC_SUBST(sbindir_resolved)
AC_DEFINE(_FILE_OFFSET_BITS, 64)
AC_CONFIG_FILES([Makefile src/Makefile conf/Makefile scripts/Makefile conf/gridftp-inetd.conf scripts/xinetd/gridftp-lfs scripts/xinetd/gridftp-lfs-inetd scripts/gridftp-lfs-standalone scripts/init/gridftp-lfs])
AC_OUTPUT

