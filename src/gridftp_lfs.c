/**
 * All the "boilerplate" code necessary to make the GridFTP-LFS integration
 * function.
*/
#include <apr_signal.h>
#include <apr_wrapper.h>
#include <execinfo.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <syslog.h>

#include "gridftp_lfs.h"

/*
 *  Globals for this library.
 */
globus_version_t gridftp_lfs_local_version = {
    0, /* major version number */
    0, /* minor/bug version number */
    1,
    0 /* branch ID */
};

statsd_link * lfs_statsd_link = NULL;
char err_msg[MSG_SIZE];
int local_io_block_size = 0;
int local_io_count = 0;

/*
 *  Interface definitions for LFS
 */
static globus_gfs_storage_iface_t globus_l_gfs_lfs_dsi_iface = {
    GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING | GLOBUS_GFS_DSI_DESCRIPTOR_SENDER,
    lfs_start,
    lfs_destroy_gridftp,
    NULL, /* list */
    lfs_send,
    lfs_recv,
    lfs_trev, /* trev */
    NULL, /* active */
    NULL, /* passive */
    NULL, /* data destroy */
    lfs_command,
    lfs_stat_gridftp,
    NULL,
    NULL,
    NULL
};

/*
 *  Module definitions; hooks into the Globus module system.
 *  Initialized when library loads.
 */
GlobusExtensionDefineModule(globus_gridftp_server_lfs) = {
    "globus_gridftp_server_lfs",
    lfs_activate,
    lfs_deactivate,
    NULL,
    NULL,
    &gridftp_lfs_local_version
};

/*
 *  Called when the LFS module is activated.
 *  Need to initialize APR ourselves
 */
int lfs_activate(void) {
    globus_extension_registry_add(
                            GLOBUS_GFS_DSI_REGISTRY,
                            "lfs",
                            GlobusExtensionMyModule(globus_gridftp_server_lfs),
                            &globus_l_gfs_lfs_dsi_iface);

    // See if we're configured to write to statsd
    char * local_host = globus_malloc(256);
    if (local_host) {
        memset(local_host, 0, 256);
        if (gethostname(local_host, 255)) {
            strcpy(local_host, "UNKNOWN");
        }
    }

    char statsd_namespace_prefix [] = "lfs.gridftp.";
    char * statsd_namespace = globus_malloc(strlen(statsd_namespace_prefix)+
                                            strlen(local_host)+1);
    strcpy(statsd_namespace, statsd_namespace_prefix);
    char * source = local_host;
    char * dest;
    for (dest = statsd_namespace + strlen(statsd_namespace_prefix);
            *source != '\0';
            ++source, ++dest) {
        if (*source == '.') {
            *dest = '_';
        } else {
            *dest = *source;
        }
    }
    *dest = '\0';

    char * lfs_statsd_link_port = getenv("GRIDFTP_LFS_STATSD_PORT");
    char * lfs_statsd_link_host = getenv("GRIDFTP_LFS_STATSD_HOST");
    if (lfs_statsd_link_host) {
        int lfs_statsd_link_port_conv = 8125;
        if (lfs_statsd_link_port) {
            lfs_statsd_link_port_conv = atoi(lfs_statsd_link_port);
        }
        lfs_statsd_link = statsd_init_with_namespace(lfs_statsd_link_host,
                          lfs_statsd_link_port_conv,
                          statsd_namespace);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                               "Sending log data to statsd %s:%i, namespace %s\n",
                               lfs_statsd_link_host,
                               lfs_statsd_link_port_conv,
                               statsd_namespace);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                               "Not logging to statsd. Set $GRIDFTP_LFS_STATSD_HOST to enable\n");
        lfs_statsd_link = NULL;
    }
    globus_free(statsd_namespace);
    
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "LFS DSI activated.\n");
    STATSD_COUNT("activate",1);
    if (local_host) globus_free(local_host);
    return 0;
}

/*
 *  Called when the LFS module is deactivated.
 */
int lfs_deactivate(void)
{
    globus_extension_registry_remove(GLOBUS_GFS_DSI_REGISTRY, "lfs");
    STATSD_COUNT("deactivate",1);
    if (lfs_statsd_link != NULL) {
        statsd_finalize(lfs_statsd_link);
        lfs_statsd_link = NULL;
    }
    return 0;
}


