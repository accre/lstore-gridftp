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

// **************************************************************
//  lfs_get_checksum - REtreives the files checksum from the LIO backend
// **************************************************************
globus_result_t lfs_get_checksum(lfs_handle_t *lfs_handle,
                                 const char * pathname,
                                 const char * requested_cksm,
                                 char ** cksum_value)
{
    globus_result_t rc = GLOBUS_SUCCESS;

    GlobusGFSName(lfs_get_checksum);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Requesting checksum for %s\n", pathname);
    int retval, v_size;
    v_size = 2047;
    char * outbuf = (char *) globus_malloc(2048);
    *cksum_value = outbuf;
    retval = lio_get_attr(lfs_handle->fs, lfs_handle->fs->creds, pathname, NULL,
                          (char *)requested_cksm, (void **)cksum_value, &v_size);
    retval = (OP_STATE_SUCCESS == retval) ? 0 : EREMOTEIO;
    if (retval < 0) {
        return -retval;
    }

    if (*cksum_value == NULL) {
        GenericError(lfs_handle, "Failed to retrieve checksum", rc);
    }

    if (rc == GLOBUS_SUCCESS) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Got checksum (%s:%s) for %s.\n",
                               requested_cksm, *cksum_value, pathname);
    }

    return rc;
}


