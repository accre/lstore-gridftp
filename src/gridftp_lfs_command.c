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
void lfs_command(globus_gfs_operation_t  op,
                 globus_gfs_command_info_t * cmd_info,
                 void * user_arg)
{
    globus_result_t result;
    lfs_handle_t * lfs_handle;
    char * PathName;
    char * PathName_munged;
    GlobusGFSName(lfs_command);

    char * return_value = GLOBUS_NULL;

    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Entering lfs_command\n");
    lfs_handle = (lfs_handle_t *) user_arg;
    int retval;
    // Get hadoop path name (ie subtract mount point)
    PathName=cmd_info->pathname;
    PathName_munged = cmd_info->pathname;
    while (PathName_munged[0] == '/' && PathName_munged[1] == '/') {
        PathName_munged++;
    }
    if (strncmp(PathName_munged, lfs_handle->mount_point,
                lfs_handle->mount_point_len)==0) {
        PathName_munged += lfs_handle->mount_point_len;
    }
    while (PathName_munged[0] == '/' && PathName_munged[1] == '/') {
        PathName_munged++;
    }

    result = GlobusGFSErrorSystemError("command", ENOSYS); /* default error for undefined commands */
    switch (cmd_info->command) {
    case GLOBUS_GFS_CMD_MKD: {
        STATSD_COUNT("mkdir",1);
        errno = 0;
        // if (lfsCreateDirectory(lfs_handle->fs, PathName) == -1) {
        // probably need to config a default umask
        if (is_lfs_path(lfs_handle, PathName)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Making LFS directory: %s\n",
                                   PathName_munged);
            retval = gop_sync_exec(gop_lio_create_object(lfs_handle->fs,
                                   lfs_handle->fs->creds, PathName_munged,
                                   OS_OBJECT_DIR, NULL, NULL));
            retval = (OP_STATE_SUCCESS == retval) ? 0 : EREMOTEIO;
            errno = -retval;
        } else {
            retval = mkdir(PathName, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
        }
        if (retval < 0) {
            if (errno) {
                result = GlobusGFSErrorSystemError("mkdir", errno);
            } else {
                GenericError(lfs_handle,
                                "Unable to create directory (reason unknown)",
                                result);
            }
        } else {
            result = GLOBUS_SUCCESS;
        }
    }
    break;
    case GLOBUS_GFS_CMD_RMD:
        break;
    case GLOBUS_GFS_CMD_DELE: {
        STATSD_COUNT("delete",1);
        errno = 0;
        if (is_lfs_path(lfs_handle, PathName)) {
            retval = gop_sync_exec(gop_lio_remove_object(lfs_handle->fs,
                                   lfs_handle->fs->creds, PathName_munged, NULL, 0));
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
    case GLOBUS_GFS_CMD_CKSM: {
        STATSD_COUNT("get_checksum",1);
        char * value = NULL;
        if (!is_lfs_path(lfs_handle, PathName)) {
            break;
        }

        if (strcmp("ADLER32", cmd_info->cksm_alg) == 0) {
            if ((result = lfs_get_checksum(lfs_handle, PathName_munged,
                                           "user.gridftp.adler32", &value)) != GLOBUS_SUCCESS) {
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

