
/**
 * All the "boilerplate" code necessary to make the GridFTP-LFS integration
 * function.
*/
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <syslog.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <signal.h>
#include <execinfo.h>

#include "gridftp_lfs.h"
#include "apr_signal.h"
#include "apr_wrapper.h"

// ** This is for debugging bpurposes only
lfs_handle_t *global_lfs_handle;

/*
 *  Globals for this library.
 */
globus_version_t gridftp_lfs_local_version =
{
    0, /* major version number */
    0, /* minor/bug version number */
    1,
    0 /* branch ID */
};

statsd_link * lfs_statsd_link = NULL;
char err_msg[MSG_SIZE];
int local_io_block_size = 0;
int local_io_count = 0;

static void lfs_trev(globus_gfs_event_info_t *, void *);
inline void set_done(lfs_handle_t *, globus_result_t);
static int  lfs_activate(void);
static int  lfs_deactivate(void);
static void lfs_command(globus_gfs_operation_t, globus_gfs_command_info_t *, void *);
static void lfs_start(globus_gfs_operation_t, globus_gfs_session_info_t *);

void
lfs_destroy_gridftp(
    void *                              user_arg);

void
lfs_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info);

/*
 *  Interface definitions for LFS
 */
static globus_gfs_storage_iface_t       globus_l_gfs_lfs_dsi_iface =
{
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
    NULL
};

/*
 *  Module definitions; hooks into the Globus module system.
 *  Initialized when library loads.
 */
GlobusExtensionDefineModule(globus_gridftp_server_lfs) =
{
    "globus_gridftp_server_lfs",
    lfs_activate,
    lfs_deactivate,
    NULL,
    NULL,
    &gridftp_lfs_local_version
};

// Custom SEGV handler due to the presence of Java handlers.
// TODO: Needed? Probably not, AMM
void
segv_handler (int sig)
{
  STATSD_COUNT("segv_received",1);
  printf ("SEGV triggered in native code.\n");
  const int max_trace = 32;
  void *trace[max_trace];
  char **messages = (char **)NULL;
  int i, trace_size = 0;

  trace_size = backtrace(trace, max_trace);
  messages = backtrace_symbols(trace, trace_size);
  for (i=0; i<trace_size; ++i) {
	printf("[bt] %s\n", messages[i]);
  }
  raise (SIGQUIT);
  signal (SIGSEGV, SIG_DFL);
  raise (SIGSEGV);
}
/*
 *  Check to see if cores can be produced by gridftp; if not, turn them on.
 */
void
gridftp_check_core()
{
    int err;
    struct rlimit rlim;

    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    err = setrlimit(RLIMIT_CORE, &rlim);
    if (err) {
        snprintf(err_msg, MSG_SIZE, "Cannot set rlimits due to %s.\n", strerror(err));
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
    }

    int isDumpable = prctl(PR_GET_DUMPABLE);

    if (!isDumpable) {
        err = prctl(PR_SET_DUMPABLE, 1);
    }
    if (err) {
        snprintf(err_msg, MSG_SIZE, "Cannot set dumpable: %s.\n", strerror(errno));
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
    }

    // Reset signal handler:
    sig_t sigerr = signal (SIGSEGV, segv_handler);
    if (sigerr == SIG_ERR) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to set core handler.\n");
    }
}

/*
 *  Called when the LFS module is activated.
 *  Need to initialize APR ourselves
 */
int
lfs_activate(void)
{
    globus_extension_registry_add(
        GLOBUS_GFS_DSI_REGISTRY,
        "lfs",
        GlobusExtensionMyModule(globus_gridftp_server_lfs),
        &globus_l_gfs_lfs_dsi_iface);

    // start up statsd
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

    // See if we're configured to write to statsd
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
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Sending log data to statsd %s:%i, namespace %s\n",
                                lfs_statsd_link_host,
                                lfs_statsd_link_port_conv,
                                statsd_namespace);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Not logging to statsd. Set $GRIDFTP_LFS_STATSD_HOST to enable\n");
        lfs_statsd_link = NULL;
    }
    //printf("Beginning plugin\n");
    globus_free(statsd_namespace);
    STATSD_COUNT("activate",1);
    //printf("LFS <--> Gridftp plugin activated\n");
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "LFS DSI activated.\n");

    if (local_host) globus_free(local_host);
    return 0;
}

// *************************************************************************
//  is_lfs_path - DEtermines if the file is an LFS or a normal POSIX file based on the path
// *************************************************************************

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}
bool is_lfs_path(const lfs_handle_t * lfs_handle, const char * path)
{
    ADVANCE_SLASHES(path);
    int retval = strncmp(path, lfs_handle->mount_point, lfs_handle->mount_point_len);
    //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Checking LFS path with %s %s (%i)\n",  path, lfs_handle->mount_point, retval);
    //printf("Checking LFS path with %s %s (%i)\n", path, lfs_handle->mount_point, retval);
    return retval == 0;
}

// *************************************************************************
//  lfs_queue_init - Initialize a worker stack
// *************************************************************************

void lfs_queue_init(lfs_queue_t *s, apr_pool_t *mpool)
{
   apr_thread_mutex_create(&(s->lock), APR_THREAD_MUTEX_DEFAULT, mpool);
   apr_thread_cond_create(&(s->cond), mpool);
   s->stack = new_stack();
}

// *************************************************************************
//  lfs_queue_teardown - Frees everything in a worker stack except the struct itself
// *************************************************************************

void lfs_queue_teardown(lfs_queue_t *s)
{
   apr_thread_mutex_destroy(s->lock);
   apr_thread_cond_destroy(s->cond);
   free_stack(s->stack, 0);
}

// **************************************************************
//  lfs_get_checksum - REtreives the files checksum from the LIO backend
// **************************************************************

globus_result_t lfs_get_checksum(lfs_handle_t *lfs_handle, const char * pathname, const char * requested_cksm, char**cksum_value) {
    globus_result_t rc = GLOBUS_SUCCESS;

    GlobusGFSName(lfs_get_checksum);

    int retval, v_size;
    v_size = 2047;
    char * outbuf = (char *) globus_malloc(2048);
    *cksum_value = outbuf;
    retval = lio_get_attr(lfs_handle->fs, lfs_handle->fs->creds, pathname, NULL, (char *)requested_cksm, (void **)cksum_value, &v_size);
    retval = (OP_STATE_SUCCESS == retval) ? 0 : EREMOTEIO;
    if (retval < 0) {
        return -retval;
    }

    if (*cksum_value == NULL) {
        GenericError(lfs_handle, "Failed to retrieve checksum", rc);
    }

    if (rc == GLOBUS_SUCCESS) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Got checksum (%s:%s) for %s.\n", requested_cksm, *cksum_value, pathname);
    }

    return rc;
}

/*
 *  Called when the LFS module is deactivated.
 *  Completely boilerplate
 */
int
lfs_deactivate(void)
{
    globus_extension_registry_remove(
        GLOBUS_GFS_DSI_REGISTRY, "lfs");
    STATSD_COUNT("deactivate",1);
    if (lfs_statsd_link != NULL) {
        statsd_finalize(lfs_statsd_link);
        lfs_statsd_link = NULL;
    }
    return 0;
}

static
void
lfs_trev(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg
)
{

    lfs_handle_t *       lfs_handle;
    GlobusGFSName(globus_l_gfs_lfs_trev);

    lfs_handle = (lfs_handle_t *) user_arg;
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Recieved a transfer event.\n");

    switch (event_info->type) {
        case GLOBUS_GFS_EVENT_TRANSFER_ABORT:
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Got an abort request to the LFS client.\n");
            STATSD_COUNT("trev_abort",1);
            set_done(lfs_handle, GLOBUS_FAILURE);
            break;
        default:
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Got some other transfer event %d.\n", event_info->type);
    }
}

/*************************************************************************
 *  command
 *  -------
 *  This interface function is called when the client sends a 'command'.
 *  commands are such things as mkdir, remdir, delete.  The complete
 *  enumeration is below.
 *
 *  To determine which command is being requested look at:
 *      cmd_info->command
 *
 *      GLOBUS_GFS_CMD_MKD = 1,
 *      GLOBUS_GFS_CMD_RMD,
 *      GLOBUS_GFS_CMD_DELE,
 *      GLOBUS_GFS_CMD_RNTO,
 *      GLOBUS_GFS_CMD_RNFR,
 *      GLOBUS_GFS_CMD_CKSM,
 *      GLOBUS_GFS_CMD_SITE_CHMOD,
 *      GLOBUS_GFS_CMD_SITE_DSI
 ************************************************************************/
static void
lfs_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         cmd_info,
    void *                              user_arg)
{
    globus_result_t                    result;
    lfs_handle_t *                     lfs_handle;
    char *                             PathName;
    char *                             PathName_munged;
    GlobusGFSName(lfs_command);

    char * return_value = GLOBUS_NULL;

    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Entering lfs_command\n");
    lfs_handle = (lfs_handle_t *) user_arg;
    int retval;
    // Get hadoop path name (ie subtract mount point)
    PathName=cmd_info->pathname;
    PathName_munged = cmd_info->pathname;
    while (PathName_munged[0] == '/' && PathName_munged[1] == '/')
    {
        PathName_munged++;
    }
    if (strncmp(PathName_munged, lfs_handle->mount_point, lfs_handle->mount_point_len)==0) {
        PathName_munged += lfs_handle->mount_point_len;
    }
    while (PathName_munged[0] == '/' && PathName_munged[1] == '/')
    {
        PathName_munged++;
    }

    GlobusGFSErrorSystemError("command", ENOSYS);
    switch (cmd_info->command) {
    case GLOBUS_GFS_CMD_MKD:
{
        STATSD_COUNT("mkdir",1);
        errno = 0;
        // if (lfsCreateDirectory(lfs_handle->fs, PathName) == -1) {
        // probably need to config a default umask
        if (is_lfs_path(lfs_handle, PathName)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Making LFS directory: %s\n", PathName_munged);
            retval = gop_sync_exec(gop_lio_create_object(lfs_handle->fs, lfs_handle->fs->creds, PathName_munged, OS_OBJECT_DIR, NULL, NULL));
            retval = (OP_STATE_SUCCESS == retval) ? 0 : EREMOTEIO;
            errno = -retval;
        } else {
            retval = mkdir(PathName, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        }
        if (retval < 0) {
            if (errno) {
                result = GlobusGFSErrorSystemError("mkdir", errno);
            } else {
                GenericError(lfs_handle, "Unable to create directory (reason unknown)", result);
            }
        } else {
            result = GLOBUS_SUCCESS;
        }
}
        break;
    case GLOBUS_GFS_CMD_RMD:
        break;
    case GLOBUS_GFS_CMD_DELE:
{
        STATSD_COUNT("delete",1);
        errno = 0;
        if (is_lfs_path(lfs_handle, PathName)) {
            retval = gop_sync_exec(gop_lio_remove_object(lfs_handle->fs, lfs_handle->fs->creds, PathName_munged, NULL, 0));
            retval = (OP_STATE_SUCCESS == retval) ? 0 : -EREMOTEIO;
        } else {
            retval = unlink(PathName);
        }
        if (retval != 0) {
            if (errno) {
                result = GlobusGFSErrorSystemError("unlink", errno);
            } else {
                GenericError(lfs_handle, "Unable to delete file (reason unknown)", result);
            }
        } else {
            result = GLOBUS_SUCCESS;
        }
}
        break;
    case GLOBUS_GFS_CMD_RNTO:
        break;
    case GLOBUS_GFS_CMD_RNFR:
        break;
    case GLOBUS_GFS_CMD_CKSM:
{
        STATSD_COUNT("get_checksum",1);
        char * value = NULL;
        if (!is_lfs_path(lfs_handle, PathName)) {
            break;
        }

        if (strcmp("ADLER32", cmd_info->cksm_alg) == 0) {
            if ((result = lfs_get_checksum(lfs_handle, PathName_munged, "user.gridftp.adler32", &value)) != GLOBUS_SUCCESS) {
               break;
           }
        }

        if (value == NULL) {
            GenericError(lfs_handle, "Unable to retrieve check", result);
            break;
        }
        return_value = value;
}
        break;
    case GLOBUS_GFS_CMD_SITE_CHMOD:
        break;
    case GLOBUS_GFS_CMD_SITE_DSI:
        break;
    case GLOBUS_GFS_CMD_SITE_RDEL:
        break;
    case GLOBUS_GFS_CMD_SITE_AUTHZ_ASSERT:
        break;
    case GLOBUS_GFS_CMD_SITE_SETNETSTACK:
        break;
    case GLOBUS_GFS_CMD_SITE_SETDISKSTACK:
        break;
    case GLOBUS_GFS_CMD_SITE_CLIENTINFO:
        break;
    case GLOBUS_GFS_CMD_SITE_CHGRP:
        break;
    case GLOBUS_GFS_CMD_SITE_UTIME:
        break;
    case GLOBUS_GFS_CMD_SITE_SYMLINKFROM:
        break;
    case GLOBUS_GFS_CMD_SITE_SYMLINK:
        break;
    case GLOBUS_GFS_CMD_DCSC:
        break;
    default:
        break;
    }

    globus_gridftp_server_finished_command(op, result, return_value);

    if (return_value) {
        free(return_value);
    }
}

/*************************************************************************
 *  start
 *  -----
 *  This function is called when a new session is initialized, ie a user
 *  connectes to the server.  This hook gives the dsi an oppertunity to
 *  set internal state that will be threaded through to all other
 *  function calls associated with this session.
 *  int                                 port;
    char *                              host;
 *
 *  finished_info.info.session.session_arg should be set to an DSI
 *  defined data structure.  This pointer will be passed as the void *
 *  user_arg parameter to all other interface functions.
 *
 *  NOTE: at nice wrapper function should exist that hides the details
 *        of the finished_info structure, but it currently does not.
 *        The DSI developer should jsut follow this template for now
 ************************************************************************/
void
lfs_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info)
{
    lfs_handle_t*       lfs_handle;
    globus_gfs_finished_info_t          finished_info;
    GlobusGFSName(lfs_start);
    globus_result_t rc;
    const char *section = "gridftp";
    char *dsi_config;
    char *debug_level = NULL;
    int allow_control_c = 0;
    int load_limit = 100;

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Entering lfs_start.\n");
    globus_gridftp_server_get_config_string (NULL, &dsi_config);

    if (dsi_config) {
       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "DSI config=%s\n", dsi_config);
    } else {
       globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "DSI config MISSING!\n");
    }

    STATSD_COUNT("start",1);
    lfs_handle = (lfs_handle_t *)globus_malloc(sizeof(lfs_handle_t));
    memset(lfs_handle, 0, sizeof(lfs_handle_t));

    global_lfs_handle = lfs_handle;

    memset(&finished_info, 0, sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = GLOBUS_SUCCESS;
    finished_info.info.session.session_arg = lfs_handle;
    finished_info.info.session.username = session_info->username;
    finished_info.info.session.home_dir = "/";

    //printf("Loading lfs_start\n");
    if (!lfs_handle) {
        MemoryError(lfs_handle, "Unable to allocate a new LFS handle.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    // ** These are used to interface between globus and LIO to bypass the odd threading model globus uses
    lfs_handle->globus_lock = (globus_mutex_t *)globus_malloc(sizeof(globus_mutex_t));
    lfs_handle->globus_cond = (globus_cond_t *)globus_malloc(sizeof(globus_cond_t));

    apr_wrapper_start();  // ** Go ahead and start up APR.  I'll need to stop it at the end also.
    apr_status_t pool_status = apr_pool_create(&(lfs_handle->mpool), NULL);
    if (pool_status != APR_SUCCESS) {
        MemoryError(lfs_handle, "Unable to allocate an APR threadpool for LFS.", rc);
        finished_info.result = pool_status;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    apr_thread_mutex_create(&(lfs_handle->lock), APR_THREAD_MUTEX_DEFAULT, lfs_handle->mpool);
    if (!(lfs_handle->lock)) {
        MemoryError(lfs_handle, "Unable to allocate a new mutex for LFS.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }
    apr_thread_cond_create(&(lfs_handle->cond), lfs_handle->mpool);
    if (!(lfs_handle->lock)) {
        MemoryError(lfs_handle, "Unable to allocate a new condition for LFS.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    // ** Load and parse the config
    inip_file_t *ifd;
    lfs_handle->lfs_config = (dsi_config == NULL) ? strdup("/etc/lio/lio-gridftp.cfg") : strdup(dsi_config);
    globus_free(dsi_config);

    // ** This will override the gridftp config if env is set
    char * lfs_config_char = getenv("GRIDFTP_LFS_CONFIG");
    if (lfs_config_char != NULL) {
        if (lfs_handle->lfs_config) free(lfs_handle->lfs_config);
        lfs_handle->lfs_config = strdup(lfs_config_char);
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Loading LFS config=%s\n", lfs_handle->lfs_config);
    struct stat dummy;
    if (stat(lfs_handle->lfs_config, &dummy)) {
        SystemError(lfs_handle, "Config file doesn't exist", rc);
        finished_info.result = errno;
        globus_gridftp_server_operation_finished(op, errno, &finished_info);
        return;
    }
    ifd = inip_read(lfs_handle->lfs_config);
    lfs_handle->mount_point = inip_get_string(ifd, section, "mount_prefix", "Oops!");
    debug_level = inip_get_string(ifd, section, "log_level", NULL);
    lfs_handle->send_stages = inip_get_integer(ifd, section, "send_stages", 4);
    lfs_handle->total_buffer_size = inip_get_integer(ifd, section, "max_buffer_size", 100*1024*1024);
    // set by gridftp....    lfs_handle->buffer_size = inip_get_integer(ifd, section, "buffer_size", 128*1024);
    lfs_handle->n_buffers = 0;  // ** Calculated and set by the R/W operation
    lfs_handle->n_cksum_threads = inip_get_integer(ifd, section, "n_cksum_threads", 4);
    lfs_handle->do_calc_adler32 = inip_get_integer(ifd, section, "do_calc_adler32", 1);
    load_limit = inip_get_integer(ifd, section, "load_limit", 20);
    lfs_handle->log_autoremove = inip_get_integer(ifd, section, "log_autoremove", 0);
    lfs_handle->default_size = inip_get_integer(ifd, section, "default_size", 0);
    lfs_handle->low_water_fraction = inip_get_double(ifd, section, "low_water_fraction", 0.25);
    lfs_handle->high_water_fraction = inip_get_double(ifd, section, "high_water_fraction", 0.75);
    lfs_handle->low_water_flush = 0;  // ** These are set by the recv command
    lfs_handle->high_water_flush = 0;
    allow_control_c = inip_get_integer(ifd, section, "allow_control_c", 0);
    if ((lfs_handle->low_water_fraction == 0) || 
            (lfs_handle->high_water_fraction == 0)) {
        GenericError(lfs_handle, "Both low_water_fraction and high_water_fraction cannot be zero", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
    }
    char *lprintf= inip_get_string(ifd, section, "log_fname_printf", "/lio/log/gridftp.log");
    lfs_handle->log_filename = globus_malloc(4096);
    memset(lfs_handle->log_filename, 0, 4096);
    snprintf(lfs_handle->log_filename, 4096, lprintf, getpid());
    free(lprintf);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "mount_prefix=%s\n", lfs_handle->mount_point);


    // Copy the username from the session_info to the LFS handle.
    size_t strlength = strlen(session_info->username)+1;
    strlength = strlength < 256 ? strlength  : 256;
    lfs_handle->username = globus_malloc(sizeof(char)*strlength);
    if (lfs_handle->username == NULL) {
        finished_info.result = GLOBUS_FAILURE;
        globus_gridftp_server_operation_finished(
            op, GLOBUS_FAILURE, &finished_info);
        return;
    }
    strncpy(lfs_handle->username, session_info->username, strlength);
    // TODO: Update this for lfs-specific options

    inip_destroy(ifd);


    // Get our hostname
    lfs_handle->local_host = globus_malloc(256);
    if (lfs_handle->local_host) {
        memset(lfs_handle->local_host, 0, 256);
        if (gethostname(lfs_handle->local_host, 255)) {
            strcpy(lfs_handle->local_host, "UNKNOWN");
        }
    }

    // Pull syslog configuration from environment.
    char * syslog_host_char = getenv("GRIDFTP_SYSLOG");
    if (syslog_host_char == NULL) {
        lfs_handle->syslog_host = NULL;
    } else {
        lfs_handle->syslog_host = stdrup(syslog_host_char);
        lfs_handle->remote_host = session_info->host_id;
        openlog("GRIDFTP", 0, LOG_LOCAL2);
        lfs_handle->syslog_msg = (char *)globus_malloc(256);
        if (lfs_handle->syslog_msg)
            snprintf(lfs_handle->syslog_msg, 255, "%s %s %%s %%i %%i", lfs_handle->local_host, lfs_handle->remote_host);
    }

    // Override config file
    char * load_limit_char = getenv("GRIDFTP_LOAD_LIMIT");
    if (load_limit_char != NULL) {
        load_limit = atoi(load_limit_char);
        if (load_limit < 1)
            load_limit = 20;
    }


    // Override config file
    char * mount_point_char = getenv("GRIDFTP_LFS_MOUNT_POINT");
    if (mount_point_char != NULL) {
        if (lfs_handle->mount_point) free(lfs_handle->mount_point);
        lfs_handle->mount_point = strdup(mount_point_char);
    }

    // ** See if we override the configuration debug level
    char * debug_level_char = getenv("GRIDFTP_LFS_DEBUG_LEVEL");
    if (debug_level_char) {
       if (debug_level) free(debug_level);
       debug_level = strdup(debug_level_char);
    }

    // fire up the mount point
    int argc = 7;
    char **argv = malloc(sizeof(char *)*argc);
    argv[0] = "lio_gridftp";
    argv[1] = "-c";    argv[2] = lfs_handle->lfs_config;
    argv[3] = "-log";  argv[4] = lfs_handle->log_filename;
    argv[5] = "-d";    argv[6] = debug_level;
    if (debug_level == NULL) argc -= 2;

    char **argvp = argv;
    lio_init(&argc, &argvp);
    free(argv);
    free(argvp);
    if (debug_level) free(debug_level);

    if (!lio_gc) {
        MemoryError(lfs_handle, "Unable to allocate a new LFS FileSystem.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }
    lfs_handle->fs = lio_gc;

    if (allow_control_c == 1) {  // ** Want to enable ^C for debugging
       apr_signal(SIGINT, NULL);
       apr_signal_unblock(SIGINT);
    }

    lfs_handle->mount_point_len = strlen(lfs_handle->mount_point);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Checking current load on the server.\n");
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
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Detected system load %.2f.\n", load);
        if ((load >= load_limit) && (load < 4000)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Preventing gridftp transfer startup due to system load of %.2f.\n", load);
            sleep(5);
        } else {
            break;
        }
        close(fd);
        fd = open("/proc/loadavg", O_RDONLY);
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "Connected to LFS.\n");

    if (!lfs_handle->fs) {
        finished_info.result = GLOBUS_FAILURE;
        globus_gridftp_server_operation_finished(
            op, GLOBUS_FAILURE, &finished_info);
        return;
    }

    // Handle core limits
    gridftp_check_core();

    globus_gridftp_server_operation_finished(
        op, GLOBUS_SUCCESS, &finished_info);
}

/************************************************************************
 *  destroy
 *  -------
 *  This is called when a session ends, ie client quits or disconnects.
 ************************************************************************/
void
lfs_destroy_gridftp(
    void *                              user_arg)
{
    lfs_handle_t *       lfs_handle;
    lfs_handle = (lfs_handle_t *) user_arg;
    STATSD_COUNT("destroy",1);
    //printf("Destroying gridftp\n");
    if (lfs_handle) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Destroying the LFS connection.\n");
        //printf("The handle is %p\n", (void*)lfs_handle);
        if (lfs_handle->fs) {
            lfs_handle->fs = NULL;
            lio_shutdown();
            apr_wrapper_stop();  // ** Let the wrapper know we don't need APR anymore either.

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

/*************************************************************************
 *  is_done
 *  -------
 *  Check to see if a lfs_handle is already done.
 ************************************************************************/
inline globus_bool_t
is_done(
    lfs_handle_t *lfs_handle)
{
    return lfs_handle->done > 0;
}

/*************************************************************************
 *  is_close_done
 *  -------------
 *  Check to see if a lfs_handle is already close-done.
 ************************************************************************/
inline globus_bool_t
is_close_done(
    lfs_handle_t *lfs_handle)
{
    return lfs_handle->done == 2;
}

/*************************************************************************
 *  set_done
 *  --------
 *  Set the handle as done for a given reason.
 *  If the handle is already done with an error, this is a no-op.
 *  If the handle is in a success state and gets a failure, we record it.
 ************************************************************************/
inline void
set_done(
    lfs_handle_t *lfs_handle, globus_result_t rc)
{
    // Ignore already-done handles.
    if (is_done(lfs_handle) && (lfs_handle->done_status != GLOBUS_SUCCESS)) {
        return;
    }
    lfs_handle->done = 1;
    lfs_handle->done_status = rc;
}


