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


// *************************************************************************
//  is_lfs_path - Determines if the file is an LFS or a normal POSIX file based on the path
// *************************************************************************
#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}
bool is_lfs_path(const lfs_handle_t * lfs_handle, const char * path)
{
    ADVANCE_SLASHES(path);
    int retval = strncmp(path, lfs_handle->mount_point,
                         lfs_handle->mount_point_len);
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

/*************************************************************************
 *  is_done
 *  -------
 *  Check to see if a lfs_handle is already done.
 ************************************************************************/
inline globus_bool_t is_done(lfs_handle_t *lfs_handle)
{
    return lfs_handle->done > 0;
}

/*************************************************************************
 *  is_close_done
 *  -------------
 *  Check to see if a lfs_handle is already close-done.
 ************************************************************************/
inline globus_bool_t is_close_done(lfs_handle_t *lfs_handle)
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
inline void set_done(lfs_handle_t *lfs_handle, globus_result_t rc)
{
    // Ignore already-done handles.
    if (is_done(lfs_handle) && (lfs_handle->done_status != GLOBUS_SUCCESS)) {
        return;
    }
    lfs_handle->done = 1;
    lfs_handle->done_status = rc;
}

// Helper function to keep errstr propagated. Follows the following semantics,
// which were cribbed from leveldb:
//
// errstr can have one of the following three cases:
//   * (*errstr == NULL) - malloc() a copy of error.
//   * (*errstr != NULL) - free() errstr, and malloc() a copy of error
//   * errstr == NULL - do nothing
//
// It is the callee's responsibility to free() *errstr.
void handle_errstr(char ** errstr, char * error)
{
    if (errstr == NULL) {
        return;
    } else if (*errstr == NULL) {
        free(*errstr);
    }
    *errstr = strdup(error);
}
