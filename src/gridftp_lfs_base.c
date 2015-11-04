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

int load_lfs(lfs_handle_t * h, char ** errstr)
{
    //
    // Start LFS
    //
    int argc = 7;
    char **argv = malloc(sizeof(char *)*argc);
    char * error;
    argv[0] = "lio_gridftp";
    argv[1] = "-c";
    argv[2] = h->lfs_config;
    argv[3] = "-log";
    argv[4] = h->log_filename;
    argv[5] = "-d";
    argv[6] = h->debug_level;
    if (h->debug_level == NULL) argc -= 2;

    char **argvp = argv;
    lio_init(&argc, &argvp);
    free(argv);
    free(argvp);

    if (!lio_gc) {
        error = "Unable to allocate a new LFS FileSystem.";
        goto cleanup;
    }
    h->fs = lio_gc;
    return 1;
cleanup:
    handle_errstr(errstr, error);   
    return 0;
}

// Stall if loadavg is too high
void check_load(int load_limit) {
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                           "Checking current load on the server.\n");

    // Stall stall stall!
    int fd = open("/proc/loadavg", O_RDONLY);
    int bufsize = 256, nbytes=-1;
    char buf[bufsize];
    char * buf_ptr;
    char * token;
    double load;
    int ctr = 0;
    while (fd >= 0) {
        if (ctr == 120)
            break;
        ctr += 1;
        nbytes = read(fd, buf, bufsize);
        if (nbytes < 0)
            break;
        buf[nbytes-1] = '\0';
        buf_ptr = buf;
        token = strsep(&buf_ptr, " ");
        load = strtod(token, NULL);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Detected system load %.2f.\n",
                               load);
        if ((load >= load_limit) && (load < 4000)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                                   "Preventing gridftp transfer startup due to system load of %.2f.\n", load);
            sleep(5);
        } else {
            break;
        }
        close(fd);
        fd = open("/proc/loadavg", O_RDONLY);
    }
}

// Called when a user connects to the server
void lfs_start(globus_gfs_operation_t op,
               globus_gfs_session_info_t * session_info)
{
    lfs_handle_t * lfs_handle;
    globus_gfs_finished_info_t finished_info;
    GlobusGFSName(lfs_gridftp_load_config);
    char * errstr;

    memset(&finished_info, 0, sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = GLOBUS_SUCCESS;
    finished_info.info.session.username = session_info->username;
    finished_info.info.session.home_dir = "/";

    lfs_handle = lfs_gridftp_load_config(session_info, &errstr);
    if (!lfs_handle) {
        goto cleanup;
    }
    finished_info.info.session.session_arg = lfs_handle;
    check_load(lfs_handle->load_limit);

    if (!load_lfs(lfs_handle, &errstr)) {
        goto cleanup;
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Connected to LFS.\n");
    globus_gridftp_server_operation_finished(
                                            op, GLOBUS_SUCCESS, &finished_info);
    return;
cleanup:
    finished_info.result = GLOBUS_FAILURE;
    finished_info.msg = errstr;
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Error in lfs_start: %s\n", errstr);
    globus_gridftp_server_operation_finished(
                                        op, GLOBUS_FAILURE, &finished_info);
}

// Called when a user disconnects from the server
void lfs_destroy_gridftp(void * user_arg)
{
    lfs_handle_t *       lfs_handle;
    lfs_handle = (lfs_handle_t *) user_arg;
    STATSD_COUNT("destroy",1);
    if (lfs_handle) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                                "Destroying the LFS connection.\n");
        if (lfs_handle->fs) {
            lfs_handle->fs = NULL;
            lio_shutdown();
            // ** Let the wrapper know we don't need APR anymore either.
            apr_wrapper_stop();
            if (lfs_handle->log_autoremove) unlink(lfs_handle->log_filename);
        }

        if (lfs_handle->globus_lock)
            globus_free(lfs_handle->globus_lock);
        if (lfs_handle->globus_cond)
            globus_free(lfs_handle->globus_cond);
        if (lfs_handle->username)
            globus_free(lfs_handle->username);
        if (lfs_handle->local_host)
            globus_free(lfs_handle->local_host);
        if (lfs_handle->log_filename)
            globus_free(lfs_handle->log_filename);
        if (lfs_handle->syslog_msg)
            globus_free(lfs_handle->syslog_msg);
        if (lfs_handle->mount_point)
            free(lfs_handle->mount_point);
        if (lfs_handle->lfs_config)
            free(lfs_handle->lfs_config);

        globus_free(lfs_handle);
    }
    closelog();
}

// Handle asynchronous event notifications
void lfs_trev(globus_gfs_event_info_t * event_info, void * user_arg)
{

    lfs_handle_t * lfs_handle;
    GlobusGFSName(globus_l_gfs_lfs_trev);

    lfs_handle = (lfs_handle_t *) user_arg;
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Recieved a transfer event.\n");

    switch (event_info->type) {
    case GLOBUS_GFS_EVENT_TRANSFER_ABORT:
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                               "Got an abort request to the LFS client.\n");
        STATSD_COUNT("trev_abort",1);
        set_done(lfs_handle, GLOBUS_FAILURE);
        break;
    default:
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                               "Got some other transfer event %d.\n", event_info->type);
    }
}


