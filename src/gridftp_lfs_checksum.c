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

// *************************************************************************
//  human_readable_adler32 - Converts the adler32 number into a human readable
//  format
// *************************************************************************

void human_readable_adler32(char *adler32_human, uLong adler32)
{
    unsigned int i;
    unsigned char * adler32_char = (unsigned char*)&adler32;
    char * adler32_ptr = (char *)adler32_human;
    for (i = 0; i < 4; i++) {
        sprintf(adler32_ptr, "%02x", adler32_char[sizeof(ulong)-4-1-i]);
        adler32_ptr++;
        adler32_ptr++;
    }
    adler32_ptr = '\0';
}

// *************************************************************************
// lfs_cksum_thread - Thread task for doing adler32 calculations on incoming data blocks
// *************************************************************************

void *lfs_cksum_thread(__attribute__((unused)) apr_thread_t *th, void *data)
{
    lfs_handle_t *lfs_handle = (lfs_handle_t *)data;
    Stack_t *stack = lfs_handle->cksum_stack.stack;
    apr_thread_cond_t *cond = lfs_handle->cksum_stack.cond;
    apr_thread_mutex_t *lock = lfs_handle->cksum_stack.lock;
    lfs_queue_t *writer = &(lfs_handle->backend_stack);
    Stack_ele_t *ele;
    lfs_buffer_t *buf;
    int finished;

    finished = 0;
    while (finished == 0) {
        // ** Get the next block to process
        apr_thread_mutex_lock(lock);
        while ((ele = pop_link(stack)) == NULL) {
            if (ele == NULL) {
                apr_thread_cond_wait(cond, lock);  // ** Nothing to do so wait
                continue;  // ** Try again
            }
        }
        apr_thread_mutex_unlock(lock);

        // ** Make sure it's valid data and not an exit sentinel
        buf = get_stack_ele_data(ele);
        log_printf(1, "processing.  ptr=%p\n", buf);
        if (buf == NULL) {  // ** This tells us to kick out
            finished = 1;
            free(ele);
            break;
        }

        // ** If we made it here we have a block to process
        if ((buf->nbytes > 0) && (lfs_handle->do_calc_adler32 == 1)) {
            buf->adler32 = adler32(0L, Z_NULL, 0);
            buf->adler32 = adler32(buf->adler32, (const Bytef *)buf->buffer, buf->nbytes);
        } else {
            buf->adler32 = 0;
        }

        // ** Now pass it on to the writer thread
        apr_thread_mutex_lock(writer->lock);
        push_link(writer->stack, ele);
        apr_thread_cond_signal(writer->cond);
        apr_thread_mutex_unlock(writer->lock);
    }
    apr_thread_mutex_unlock(lock);

    // ** Notify them I'm finished
    apr_thread_mutex_lock(lfs_handle->lock);
    lfs_handle->n_cksum_threads--;
    apr_thread_cond_signal(lfs_handle->cond);
    apr_thread_mutex_unlock(lfs_handle->lock);

    return(NULL);
}

