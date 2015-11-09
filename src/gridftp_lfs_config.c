#include <apr_signal.h>
#include <apr_wrapper.h>
#include <execinfo.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <syslog.h>

#include "gridftp_lfs.h"

lfs_handle_t * lfs_gridftp_load_config(globus_gfs_session_info_t * session_info,
                                       char ** errstr)
{
    lfs_handle_t * h;
    GlobusGFSName(lfs_gridftp_load_config);
    const char * error = NULL;
    const char * section = "gridftp";
    char * dsi_config;
    int load_limit = 100;

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Loading LFS config.\n");

    STATSD_COUNT("start",1);
    h = (lfs_handle_t *)globus_malloc(sizeof(lfs_handle_t));
    memset(h, 0, sizeof(lfs_handle_t));

    if (!h) {
        error = "Unable to allocate a new LFS handle.";
        goto cleanup;
    }

    // ** These are used to interface between globus and LIO to bypass the odd
    // threading model globus uses
    h->globus_lock = (globus_mutex_t *) globus_malloc(sizeof(globus_mutex_t));
    h->globus_cond = (globus_cond_t *) globus_malloc(sizeof(globus_cond_t));

    //
    // Initialize APR
    //
    apr_wrapper_start();
    apr_status_t pool_status = apr_pool_create(&(h->mpool), NULL);
    if (pool_status != APR_SUCCESS) {
        error = "Unable to allocate an APR threadpool for LFS.";
        goto cleanup;
    }

    apr_thread_mutex_create(&(h->lock), APR_THREAD_MUTEX_DEFAULT,
                            h->mpool);
    if (!(h->lock)) {
        error = "Unable to allocate a new mutex for LFS.";
        goto cleanup;
    }


    apr_thread_cond_create(&(h->cond), h->mpool);
    if (!(h->lock)) {
        error = "Unable to allocate a new condition for LFS.";
        goto cleanup;
    }

    //
    // Load configuration file
    //
    globus_gridftp_server_get_config_string(NULL, &dsi_config);
    inip_file_t *ifd;
    char * lfs_config_char = getenv("GRIDFTP_LFS_CONFIG");
    if (lfs_config_char != NULL) {
        if (h->lfs_config) free(h->lfs_config);
        h->lfs_config = strdup(lfs_config_char);
    } else {
        h->lfs_config = (dsi_config == NULL) ?
                                    strdup("/etc/lio/lio-gridftp.cfg") :
                                    strdup(dsi_config);
    }
    globus_free(dsi_config);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Loading LFS config=%s\n",
                           h->lfs_config);
    struct stat dummy;
    if (stat(h->lfs_config, &dummy)) {
        error = "Config file doesn't exist";
        goto cleanup;
    }
    ifd = inip_read(h->lfs_config);
    if (ifd == NULL) {
        error = "ERROR opening config file!";
        goto cleanup;
    }

    if (inip_get_integer(ifd, section, "allow_control_c", 0) == 1) {
        apr_signal(SIGINT, NULL);
        apr_signal_unblock(SIGINT);
    }


    //
    // Configure handle using ini
    //
    h->debug_level = inip_get_string(ifd, section, "log_level", "0");
    h->default_size = inip_get_integer(ifd, section, "default_size", 0);
    h->do_calc_adler32 = inip_get_integer(ifd, section, "do_calc_adler32",1);
    h->high_water_fraction = inip_get_double(ifd, section, "high_water_fraction", 0.75);
    h->load_limit = inip_get_integer(ifd, section, "load_limit", 20);
    h->log_autoremove = inip_get_integer(ifd, section, "log_autoremove", 0);
    h->low_water_fraction = inip_get_double(ifd, section, "low_water_fraction", 0.25);
    h->mount_point = inip_get_string(ifd, section, "mount_prefix", NULL);
    h->n_cksum_threads = inip_get_integer(ifd, section, "n_cksum_threads",4);
    h->send_stages = inip_get_integer(ifd, section, "send_stages", 4);
    h->total_buffer_size = inip_get_integer(ifd, section, "max_buffer_size", 100*1024*1024);

    if (! h->mount_point) {
        error = "No mount_point option was specified";
        goto cleanup;
    }
    h->mount_point_len = strlen(h->mount_point);

    if ((h->low_water_fraction == 0) || (h->high_water_fraction == 0)) {
        error = "low_water_fraction and high_water_fraction cannot be zero";
        goto cleanup;
    }

    char *lprintf= inip_get_string(ifd, section, "log_fname_printf",
                                   "/lio/log/gridftp.log");
    h->log_filename = globus_malloc(4096);
    memset(h->log_filename, 0, 4096);
    snprintf(h->log_filename, 4096, lprintf, getpid());
    free(lprintf);
    inip_destroy(ifd);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "LFS mounted to: %s\n",
                           h->mount_point);


    //
    // Set non-ini handle options
    //
    size_t strlength = strlen(session_info->username)+1;
    strlength = strlength < 256 ? strlength  : 256;
    h->username = globus_malloc(sizeof(char)*strlength);
    if (h->username == NULL) {
        error = "Could not get username";
        goto cleanup;
    }
    strncpy(h->username, session_info->username, strlength);

    h->local_host = globus_malloc(256);
    if (h->local_host) {
        memset(h->local_host, 0, 256);
        if (gethostname(h->local_host, 255)) {
            strcpy(h->local_host, "UNKNOWN");
        }
    }

    //
    // Load environment variables
    //
    char * syslog_host_char = getenv("GRIDFTP_SYSLOG");
    if (syslog_host_char == NULL) {
        h->syslog_host = NULL;
    } else {
        h->syslog_host = strdup(syslog_host_char);
        h->remote_host = session_info->host_id;
        openlog("GRIDFTP", 0, LOG_LOCAL2);
        h->syslog_msg = (char *)globus_malloc(256);
        if (h->syslog_msg)
            snprintf(h->syslog_msg, 255, "%s %s %%s %%i %%i",
                     h->local_host, h->remote_host);
    }

    char * load_limit_char = getenv("GRIDFTP_LOAD_LIMIT");
    if (load_limit_char != NULL) {
        load_limit = atoi(load_limit_char);
        if (load_limit < 1)
            load_limit = 32;
    }

    char * mount_point_char = getenv("GRIDFTP_LFS_MOUNT_POINT");
    if (mount_point_char != NULL) {
        if (h->mount_point) free(h->mount_point);
        h->mount_point = strdup(mount_point_char);
    }

    char * debug_level_char = getenv("GRIDFTP_LFS_LOG_LEVEL");
    if (debug_level_char != NULL) {
        if (h->debug_level) free(h->debug_level);
        h->debug_level = strdup(debug_level_char);
    }

    return h;
cleanup:
    handle_errstr(errstr, strdup(error));
    return NULL;
}
