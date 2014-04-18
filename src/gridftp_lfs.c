
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
    return 0;
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

    lfs_handle = (globus_l_gfs_lfs_handle_t *) user_arg;
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
    globus_l_gfs_lfs_handle_t *       lfs_handle;
    char *                             PathName;
    char *                             PathName_munged;
    GlobusGFSName(lfs_command);

    char * return_value = GLOBUS_NULL;

    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Entering lfs_command\n");
    lfs_handle = (globus_l_gfs_lfs_handle_t *) user_arg;
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
            retval = lfs_mkdir(PathName_munged, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
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
            retval = lfs_unlink_real(PathName_munged, lfs_handle->fs);
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
        if ((result = lfs_get_checksum(lfs_handle, cmd_info->pathname, cmd_info->cksm_alg, &value)) != GLOBUS_SUCCESS) {
            break;
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
 *  function calls associated with this session. int                                 port;
    char *                              host;
    int                                 replicas; And an oppertunity to
 *  reject the user.
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
    int max_file_buffer_count = 1500;
    int load_limit = 50;
    int replicas;
    int port;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Entering lfs_start.\n");
    STATSD_COUNT("start",1);
    lfs_handle = (lfs_handle_t *)globus_malloc(sizeof(lfs_handle_t));
    memset(lfs_handle, 0, sizeof(lfs_handle_t));

    memset(&finished_info, 0, sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = GLOBUS_SUCCESS;
    finished_info.info.session.session_arg = lfs_handle;
    finished_info.info.session.username = session_info->username;
    finished_info.info.session.home_dir = "/";

    //printf("Loading lfs_start\n");
    int max_buffer_count = 200;
    if (!lfs_handle) {
        MemoryError(lfs_handle, "Unable to allocate a new LFS handle.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    lfs_handle->mutex = (globus_mutex_t *)globus_malloc(sizeof(globus_mutex_t));
    lfs_handle->offset_mutex = (globus_mutex_t *)globus_malloc(sizeof(globus_mutex_t));
    lfs_handle->buffer_mutex = (globus_mutex_t *)globus_malloc(sizeof(globus_mutex_t));
    lfs_handle->offset_cond = (globus_cond_t *)globus_malloc(sizeof(globus_cond_t));
    lfs_handle->queued_cond = (globus_cond_t *)globus_malloc(sizeof(globus_cond_t));
    lfs_handle->dequeued_cond = (globus_cond_t *)globus_malloc(sizeof(globus_cond_t));
    if (!(lfs_handle->mutex)) {
        MemoryError(lfs_handle, "Unable to allocate a new mutex for LFS.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }
    if (globus_mutex_init(lfs_handle->mutex, GLOBUS_NULL)) {
        SystemError(lfs_handle, "Unable to initialize mutex", rc);
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    if (globus_mutex_init(lfs_handle->offset_mutex, GLOBUS_NULL)) {
        SystemError(lfs_handle, "Unable to initialize mutex", rc);
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    if (globus_cond_init(lfs_handle->offset_cond, (globus_condattr_t *) GLOBUS_NULL)) {
        SystemError(lfs_handle, "Unable to initialize cond", rc);
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    if (globus_cond_init(lfs_handle->queued_cond, (globus_condattr_t *) GLOBUS_NULL)) {
        SystemError(lfs_handle, "Unable to initialize cond", rc);
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    if (globus_cond_init(lfs_handle->dequeued_cond, (globus_condattr_t *) GLOBUS_NULL)) {
        SystemError(lfs_handle, "Unable to initialize cond", rc);
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    if (globus_mutex_init(lfs_handle->buffer_mutex, GLOBUS_NULL)) {
        SystemError(lfs_handle, "Unable to initialize mutex", rc);
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }

    lfs_handle->io_block_size = 0;
    lfs_handle->io_count = 0;

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
    // TODO update this to pull from environment
    lfs_handle->preferred_write_size = 1024 * 1024 * 10; // what to prefer to send to LFS
    lfs_handle->write_size_buffers = 2; // how many of these chunks should we keep around
    lfs_handle->stall_buffer_count = 120; // @ 256kB per buffer, this is 30MB
    lfs_handle->concurrent_writes = 10;
    lfs_handle->max_queued_bytes = 100 * 1024 * 1024; // how much to store on the backend (100MB)
    // Pull configuration from environment.
    // TODO: Update this for lfs-specific options
    lfs_handle->replicas = 3;
    lfs_handle->host = "hadoop-name";
    lfs_handle->mount_point = "/lio/lfs";
    lfs_handle->port = 9000;
    lfs_handle->lfs_config = "/etc/lio/lio-fuse.cfg";
    char * replicas_char = getenv("GRIDFTP_LFS_REPLICAS");
    char * namenode = getenv("GRIDFTP_LFS_NAMENODE");
    char * port_char = getenv("GRIDFTP_LFS_PORT");
    char * mount_point_char = getenv("GRIDFTP_LFS_MOUNT_POINT");
    char * load_limit_char = getenv("GRIDFTP_LOAD_LIMIT");
    char * lfs_config_char = getenv("GRIDFTP_LFS_CONFIG");

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
        lfs_handle->syslog_host = syslog_host_char;
        lfs_handle->remote_host = session_info->host_id;
        openlog("GRIDFTP", 0, LOG_LOCAL2);
        lfs_handle->syslog_msg = (char *)globus_malloc(256);
        if (lfs_handle->syslog_msg)
            snprintf(lfs_handle->syslog_msg, 255, "%s %s %%s %%i %%i", lfs_handle->local_host, lfs_handle->remote_host);
    }

    // Determine the maximum number of buffers; default to 200.
    char * max_buffer_char = getenv("GRIDFTP_BUFFER_COUNT");
    if (max_buffer_char != NULL) {
        max_buffer_count = atoi(max_buffer_char);
        if ((max_buffer_count < 5)  || (max_buffer_count > 1000))
            max_buffer_count = 200;
    }
    lfs_handle->max_buffer_count = max_buffer_count;
    snprintf(err_msg, MSG_SIZE, "Max memory buffer count: %i.\n", lfs_handle->max_buffer_count);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);

    char * max_file_buffer_char = getenv("GRIDFTP_FILE_BUFFER_COUNT");
    if (max_file_buffer_char != NULL) {
        max_file_buffer_count = atoi(max_file_buffer_char);
        if ((max_file_buffer_count < max_buffer_count)  || (max_buffer_count > 50000))
            max_file_buffer_count = 3*max_buffer_count;
    }
    lfs_handle->max_file_buffer_count = max_file_buffer_count;
    snprintf(err_msg, MSG_SIZE, "Max file buffer count: %i.\n", lfs_handle->max_file_buffer_count);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);

    if (load_limit_char != NULL) {
        load_limit = atoi(load_limit_char);
        if (load_limit < 1)
            load_limit = 20;
    }

    if (mount_point_char != NULL) {
        lfs_handle->mount_point = mount_point_char;
    }

    if (lfs_config_char != NULL) {
        lfs_handle->lfs_config = lfs_config_char;
    }

    // store the filename for the logs
    lfs_handle->log_filename = globus_malloc(256);
    if (lfs_handle->log_filename) {
        memset(lfs_handle->log_filename, 0, 256);
        snprintf(lfs_handle->log_filename, 255, "/lio/log/gridftp-%i", getpid());
    }

    // fire up the mount point
    char * argv[] = {
        "gridftp-dummy-plugin",
        "-o",
        "big_writes,use_ino,kernel_cache",
        "-c",
        lfs_handle->lfs_config,
        "-d",
        "1",
        "-log",
        lfs_handle->log_filename
    };
    struct stat dummy;
    if (stat(lfs_handle->lfs_config,& dummy)) {
        SystemError(lfs_handle, "Config file doesn't exist", lfs_handle->lfs_config);
        finished_info.result = errno;
        globus_gridftp_server_operation_finished(op, errno, &finished_info);
        return;
    }
    lio_fuse_t *lfs = (struct lio_fuse_t *)lfs_init_real( NULL, 9, argv, lfs_handle->mount_point);
    if (!lfs) {
        MemoryError(lfs_handle, "Unable to allocate a new LFS FileSystem.", rc);
        finished_info.result = rc;
        globus_gridftp_server_operation_finished(op, rc, &finished_info);
        return;
    }
    lfs_handle->fs = (struct lio_fuse_t *) lfs;
    lfs_handle->mount_point_len = strlen(lfs_handle->mount_point);

    if (replicas_char != NULL) {
        replicas = atoi(replicas_char);
        if ((replicas > 1) && (replicas < 20))
            lfs_handle->replicas = replicas;
    }
    if (namenode != NULL)
        lfs_handle->host = namenode;
    if (port_char != NULL) {
        port = atoi(port_char);
        if ((port >= 1) && (port <= 65535))
            lfs_handle->port = port;
    }
    lfs_handle->using_file_buffer = 0;

    lfs_handle->cksm_root = "/cksums";

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
        if ((load >= load_limit) && (load < 1000)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Preventing gridftp transfer startup due to system load of %.2f.\n", load);
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
    // Parse the checksum request information
    const char * checksums_char = getenv("GRIDFTP_LFS_CHECKSUMS");
    if (checksums_char) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
            "Checksum algorithms in use: %s.\n", checksums_char);
        lfs_parse_checksum_types(lfs_handle, checksums_char);
    } else {
        lfs_handle->cksm_types =  LFS_CKSM_TYPE_ADLER32 | LFS_CKSM_TYPE_CKSUM;
    }
    lfs_handle->tmp_file_pattern = (char *)NULL;

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
    lfs_handle = (globus_l_gfs_lfs_handle_t *) user_arg;
    STATSD_COUNT("destroy",1);
    //printf("Destroying gridftp\n");
    if (lfs_handle) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Destroying the LFS connection.\n");
        //printf("The handle is %p\n", (void*)lfs_handle);
        if (lfs_handle->fs) {
            lfs_destroy((void *) lfs_handle->fs);
            lfs_handle->fs = NULL;
        }
        if (lfs_handle->username)
            globus_free(lfs_handle->username);
        if (lfs_handle->local_host)
            globus_free(lfs_handle->local_host);
        if (lfs_handle->log_filename)
            globus_free(lfs_handle->log_filename);
        if (lfs_handle->syslog_msg)
            globus_free(lfs_handle->syslog_msg);
            remove_file_buffer(lfs_handle);
        
        if (lfs_handle->mutex) {
            globus_mutex_destroy(lfs_handle->mutex);
            globus_free(lfs_handle->mutex);
        }
        if (lfs_handle->offset_mutex) {
            globus_mutex_destroy(lfs_handle->offset_mutex);
            globus_free(lfs_handle->offset_mutex);
        }
        if (lfs_handle->offset_cond) {
            globus_cond_destroy(lfs_handle->offset_cond);
            globus_free(lfs_handle->offset_cond);
        }
        if (lfs_handle->queued_cond) {
            globus_cond_destroy(lfs_handle->queued_cond);
            globus_free(lfs_handle->queued_cond);
        }
        if (lfs_handle->dequeued_cond) {
            globus_cond_destroy(lfs_handle->dequeued_cond);
            globus_free(lfs_handle->dequeued_cond);
        }
        if (lfs_handle->buffer_mutex) {
            globus_mutex_destroy(lfs_handle->buffer_mutex);
            globus_free(lfs_handle->buffer_mutex);
        }
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

/*************************************************************************
 *  set_close_done
 *  --------------
 *  Set the handle as close-done for a given reason.
 *  If the handle is already close-done, this is a no-op.
 *  If the handle was done successfully, but the close was not a success,
 *  then record it.
 ************************************************************************/
inline void
set_close_done(
    lfs_handle_t *lfs_handle, globus_result_t rc)
{
    // Ignore already-done handles.
    if (is_close_done(lfs_handle)) {
        return;
    }
    lfs_handle->done = 2;
    if ((lfs_handle->done_status == GLOBUS_SUCCESS) && (rc != GLOBUS_SUCCESS)) {
        lfs_handle->done_status = rc;
    }
}

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}
bool is_lfs_path(const globus_l_gfs_lfs_handle_t * lfs_handle, const char * path) {
    ADVANCE_SLASHES(path);
    int retval = strncmp(path, lfs_handle->mount_point, lfs_handle->mount_point_len);
    //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Checking LFS path with %s %s (%i)\n",  path, lfs_handle->mount_point, retval);
    //printf("Checking LFS path with %s %s (%i)\n", path, lfs_handle->mount_point, retval);
    return retval == 0;
}
