
#include "gridftp_lfs.h"
#include <time.h>
#include <syslog.h>
//#include <stat.h>
// Forward declarations of local functions

typedef struct lfs_read_s {
    lfs_handle_t *lfs_handle;
    globus_size_t idx;
} lfs_read_t;

static void
lfs_finish_read_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg);

static void
lfs_perform_read_cb(
    void *  lfs_read_handle);

static void
lfs_dispatch_read(
    globus_l_gfs_lfs_handle_t *      lfs_handle);

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}

/*************************************************************************
 *  close_and_clean
 *  --------------
 *  Close the LFS file and clean up the write-related resources in the
 *  handle.
 *************************************************************************/
static globus_result_t
close_and_clean(lfs_handle_t *lfs_handle, globus_result_t rc) {

    GlobusGFSName(close_and_clean);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "Trying to close file in LFS; zero outstanding blocks.\n");
    if (is_close_done(lfs_handle)) {
        return lfs_handle->done_status;
    }

    int retval;
    if (is_lfs_path(lfs_handle, lfs_handle->pathname)) {
        if ((retval = lfs_release_real(lfs_handle->pathname_munged, lfs_handle->fd, lfs_handle->fs)) != 0)
        {
            rc  = retval;
            GenericError(lfs_handle, "Failed to close file in LFS.", rc);
            lfs_handle->fd = NULL;
        }
    } else {
        if ((retval = close(lfs_handle->fd_posix)) != 0)
        {
            rc = retval;
            GenericError(lfs_handle, "Failed to close file in POSIX.", rc);
            lfs_handle->fd_posix = 0;
        }
    }

    if (lfs_handle->buffer)
        globus_free(lfs_handle->buffer);
    if (lfs_handle->used)
        globus_free(lfs_handle->used);
    if (lfs_handle->log_filename) {
        unlink(lfs_handle->log_filename);
        globus_free(lfs_handle->log_filename);
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "transmit %d blocks of size %d bytes\n",
        lfs_handle->io_count, lfs_handle->io_block_size);

    set_close_done(lfs_handle, rc);
    return rc;
}

/*************************************************************************
 *  send
 *  ----
 *  This interface function is called when the client requests to receive
 *  a file from the server.
 *
 *  To send a file to the client the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_write();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
void
lfs_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_l_gfs_lfs_handle_t *       lfs_handle;
    GlobusGFSName(globus_l_gfs_lfs_send);
    globus_result_t                     rc = GLOBUS_SUCCESS;


    lfs_handle = (globus_l_gfs_lfs_handle_t *) user_arg;
    globus_mutex_lock(lfs_handle->mutex);
    lfs_handle->pathname = transfer_info->pathname;
    lfs_handle->pathname_munged = transfer_info->pathname;
    if (is_lfs_path(lfs_handle, lfs_handle->pathname_munged)) {
        ADVANCE_SLASHES(lfs_handle->pathname_munged)
        if (strncmp(lfs_handle->pathname_munged, lfs_handle->mount_point, lfs_handle->mount_point_len)==0) {
            lfs_handle->pathname_munged += lfs_handle->mount_point_len;
        }
        ADVANCE_SLASHES(lfs_handle->pathname_munged)
    }
    lfs_handle->op = op;
    lfs_handle->outstanding = 0;
    lfs_handle->done = 0;
    lfs_handle->done_status = GLOBUS_SUCCESS;
    lfs_handle->buffer_count = 0;
    lfs_handle->buffer = NULL;
    lfs_handle->offsets = NULL;
    lfs_handle->nbytes = NULL;
    lfs_handle->used = NULL;

    globus_gridftp_server_get_block_size(op, &lfs_handle->block_size);

    globus_gridftp_server_get_read_range(lfs_handle->op,
                                         &lfs_handle->offset,
                                         &lfs_handle->op_length);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
        "Operation starting at %d, length %d\n", lfs_handle->offset,
        lfs_handle->op_length);

    globus_gridftp_server_begin_transfer(lfs_handle->op, 0, lfs_handle);
    if (is_lfs_path(lfs_handle, lfs_handle->pathname)) {
        struct stat fileInfo;
        int retval = lfs_stat_real(lfs_handle->pathname_munged, &fileInfo, lfs_handle->fs);
        int hasStat = 1;
        if (retval == -ENOENT) {
            SystemError(lfs_handle, "opening file for read, doesn't exist", rc);
            errno = ENOENT;
            hasStat = 0;
            goto cleanup;
        }
        if (S_ISDIR(fileInfo.st_mode)) {
            GenericError(lfs_handle, "The file you are trying to read is a directory", rc);
            goto cleanup;
        }

        //lfs_handle->fd = lfsOpenFile(lfs_handle->fs, lfs_handle->pathname, O_RDONLY, 0, 1, 0);
        lfs_handle->fd = (struct fuse_file_info*)globus_malloc(sizeof(struct fuse_file_info));
        if (lfs_handle->fd == NULL)
        {
            MemoryError(lfs_handle, "Memory allocation error.", rc);
            goto cleanup;
        }
        memset(lfs_handle->fd, 0, sizeof(struct fuse_file_info));
        lfs_handle->fd->direct_io = 0;
        lfs_handle->fd->flags = O_RDONLY;
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Opening from LFS: %s\n", lfs_handle->pathname_munged);
        retval = lfs_open_real(lfs_handle->pathname_munged, lfs_handle->fd, lfs_handle->fs);
        if (retval != 0) {
            if (0) { //errno == EINTERNAL) {
                SystemError(lfs_handle,
                    "opening file due to an internal LFS error; "
                    "could be a misconfiguration or bad installation at the site.",
                    rc);
            } else if (errno == EACCES) {
                SystemError(lfs_handle, "opening file; permission error in LFS.", rc);
            } else {
                SystemError(lfs_handle, "opening file; failed to open file due to unknown error in LFS.", rc);
            }
            goto cleanup;
        }
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Opening from filesystem: %s\n", lfs_handle->pathname);
        lfs_handle->fd_posix = open(lfs_handle->pathname, O_RDONLY);
    }

    //if (lfsSeek(lfs_handle->fs, lfs_handle->fd, lfs_handle->offset) == -1) {
    //    GenericError(lfs_handle, "seek() fail", rc);
    //}

    lfs_dispatch_read(lfs_handle);

cleanup:

    if (rc != GLOBUS_SUCCESS) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to initialize read setup\n");
        set_done(lfs_handle, rc);
        globus_gridftp_server_finished_transfer(op, rc);
    }

    globus_mutex_unlock(lfs_handle->mutex);

}

// Allow injection of garbage errors, allowing us to test error-handling
//#define FAKE_ERROR
#ifdef FAKE_ERROR
int block_count = 0;
#endif

static void
lfs_finish_read_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    GlobusGFSName(lfs_handle_read_cb);
    globus_l_gfs_lfs_handle_t *      lfs_handle;
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_ssize_t idx = -1;

    lfs_handle = (globus_l_gfs_lfs_handle_t *) user_arg;
    globus_mutex_lock(lfs_handle->mutex);

#ifdef FAKE_ERROR
    block_count ++;
    if (block_count == 30) {
        GenericError(lfs_handle, "Got bored, threw an error.", rc);
        goto cleanup;
    }
#endif

    // Various short-circuit routines
    if (is_done(lfs_handle) && (lfs_handle->done_status != GLOBUS_SUCCESS)) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Error prior to callback.\n");
        rc = lfs_handle->done_status;
        goto cleanup;
    }
    if (result != GLOBUS_SUCCESS) {
        rc = result;
        goto cleanup;
    }
    if (nbytes == 0) {
        rc = result;
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Read of size zero.\n");
        goto cleanup;
    }

    // Determine the idx of the buffer.
    idx = find_buffer(lfs_handle, buffer);
    if (idx < 0) {
        GenericError(lfs_handle, "Unknown read operation", rc)
        goto cleanup;
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Finishing read op from buffer %d.\n", idx);

    // Do statistics
    if (lfs_handle->syslog_host != NULL) {
            syslog(LOG_INFO, lfs_handle->syslog_msg, "READ", nbytes, lfs_handle->io_count);
    }
    if (nbytes != lfs_handle->io_block_size) {
        if (0 != lfs_handle->io_block_size) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "send %d blocks of size %d bytes\n",
                                      lfs_handle->io_count, lfs_handle->io_block_size);
        }
        lfs_handle->io_block_size = nbytes;
        lfs_handle->io_count=1;
    } else {
        lfs_handle->io_count++;
    }

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        set_done(lfs_handle, rc);
    }

    disgard_buffer(lfs_handle, idx);

    lfs_handle->outstanding--;
    if (!is_done(lfs_handle)) {
        lfs_dispatch_read(lfs_handle);
    } else if (lfs_handle->outstanding == 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Transfer has finished!\n");
        rc = close_and_clean(lfs_handle, rc);
        globus_gridftp_server_finished_transfer(lfs_handle->op, rc);

    } else if (rc != GLOBUS_SUCCESS) {
        // Don't close the file because the other transfers will want to finish up.
        // However, do set the failure status.
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
            "We failed to finish the transfer, but there are %i outstanding reads left over.\n",
            lfs_handle->outstanding);
        globus_gridftp_server_finished_transfer(op, rc);
    } else {
        // Nothing to do if we are done and there was no error, but outstanding transfers exist.
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
            "Transfer finished successfully; %i outstanding reads left over.\n", lfs_handle->outstanding);
        // Note we do NOT call globus_gridftp_server_finished_transfer yet!
    }
    globus_mutex_unlock(lfs_handle->mutex);

}

static void
lfs_perform_read_cb(
    void *                              user_arg)
{
    GlobusGFSName(lfs_perform_read_cb);
    lfs_read_t *read_op = (lfs_read_t*) user_arg;
    lfs_handle_t *lfs_handle = read_op->lfs_handle;
    globus_size_t idx = read_op->idx;
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Starting read for buffer %u.\n", idx);
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_size_t read_length, remaining_read;
    globus_off_t offset, cur_offset;
    globus_ssize_t nbytes;

    offset = lfs_handle->offsets[idx];
    read_length = lfs_handle->nbytes[idx];
    globus_byte_t *buffer_pos = lfs_handle->buffer + idx*lfs_handle->block_size;
    globus_byte_t *cur_buffer_pos = buffer_pos;

    // Check to see if we can short-circuit
    globus_bool_t short_circuit = GLOBUS_FALSE;
    globus_mutex_lock(lfs_handle->mutex);
    if (is_done(lfs_handle) && (lfs_handle->done_status != GLOBUS_SUCCESS)) {
        short_circuit = GLOBUS_TRUE;
    }
    globus_mutex_unlock(lfs_handle->mutex);
    if (short_circuit) {
        goto cleanup;
    }

    if (lfs_handle->syslog_host != NULL) {
        syslog(LOG_INFO, lfs_handle->syslog_msg, "READ", read_length, lfs_handle->io_count);
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
        "lfs_perform_read_cb for %u@%lu.\n", read_length, offset);

    remaining_read = read_length;
    cur_offset = offset;
    int current_retries = 0;
    int max_retries = 10;
    while ((remaining_read != 0) && (current_retries <= max_retries)) {
        STATSD_TIMER_START(read_loop_timer);
        if (is_lfs_path(lfs_handle, lfs_handle->pathname)) {
            nbytes = lfs_read(lfs_handle->pathname, cur_buffer_pos, remaining_read, cur_offset, lfs_handle->fd);
            if (nbytes == 0) {    /* eof */
                // No error
                globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "lfs_perform_read_cb EOF.\n");
                globus_mutex_lock(lfs_handle->mutex);
                set_done(lfs_handle, GLOBUS_SUCCESS);
                globus_mutex_unlock(lfs_handle->mutex);
                break;
            } else if (nbytes == -1) {
                SystemError(lfs_handle, "reading from LFS", rc)
                goto cleanup;
            } else if (nbytes <= -2) {
                SystemError(lfs_handle, "reading from LFS(2):", rc)
                goto cleanup;
            }
            STATSD_TIMER_END("read_time", read_loop_timer);
            STATSD_COUNT("lfs_bytes_read",nbytes);
        } else {
            nbytes = pread(lfs_handle->fd_posix, cur_buffer_pos, remaining_read, cur_offset);
            if (nbytes == 0) {    /* eof */
                // No error
                globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "lfs_perform_read_cb EOF.\n");
                globus_mutex_lock(lfs_handle->mutex);
                set_done(lfs_handle, GLOBUS_SUCCESS);
                globus_mutex_unlock(lfs_handle->mutex);
                break;
            } else if (nbytes < 0) {
                STATSD_COUNT("posix_read_failure",1);
                if (current_retries >= max_retries) {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to read from POSIX. Errno: %i Retry: Terminal\n",errno);
                    SystemError(lfs_handle, "reading from posix", rc)
                    goto cleanup;
                } else {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to read from POSIX. Errno: %i Retry: %i\n",errno, current_retries);
                    sleep(15);
                    int newfd = open(lfs_handle->pathname, O_RDONLY);
                    if (newfd != -1) {
                        close(lfs_handle->fd_posix);
                        lfs_handle->fd_posix = newfd;
                    }
                    current_retries++;
                    nbytes = 0;
                }
            } else {
                STATSD_TIMER_END("posix_read_time", read_loop_timer);
                STATSD_COUNT("posix_bytes_read",nbytes);
            }
        }
        remaining_read -= nbytes;
        cur_buffer_pos += nbytes;
        cur_offset += nbytes;
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Read length: %d; remaining: %d retries: %i\n", read_length, remaining_read, current_retries);
    if (read_length != remaining_read) {
        // If we read anything at all, write it out to the client.
        // When the write to the network is finished, lfs_finish_read_cb will be called.
        rc = globus_gridftp_server_register_write(lfs_handle->op,
            buffer_pos,
            read_length - remaining_read,
            offset,
            -1, // Stripe index
            lfs_finish_read_cb,
            lfs_handle);
        if (rc != GLOBUS_SUCCESS) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to create callback\n");
            goto cleanup;
        }
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Zero-length read; call finish_read_cb directly.\n");
        lfs_finish_read_cb(lfs_handle->op, rc, NULL, 0, (void*)lfs_handle);
    }

cleanup:

    free(read_op);

    if (short_circuit || (rc != GLOBUS_SUCCESS)) {
        globus_mutex_lock(lfs_handle->mutex);
        set_done(lfs_handle, rc);
        globus_mutex_unlock(lfs_handle->mutex);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Short-circuit read.\n");
        // Call finish_read_op directly.
        lfs_finish_read_cb(lfs_handle->op, rc, buffer_pos,
            read_length, (void*)lfs_handle);
    }
}

// Must be called with lfs_handle->mutex LOCKED!
static void
lfs_dispatch_read(
    globus_l_gfs_lfs_handle_t *      lfs_handle)
{
    globus_size_t read_length, idx;
    globus_result_t rc = GLOBUS_SUCCESS;
    lfs_read_t *lfs_read_handle;

    GlobusGFSName(lfs_dispatch_read);

    if (is_lfs_path(lfs_handle, lfs_handle->pathname)) {
        globus_gridftp_server_get_optimal_concurrency(lfs_handle->op,
                                                  &lfs_handle->optimal_count);
    } else {
        lfs_handle->optimal_count = 1;
    }
    //lfs_handle->optimal_count = (lfs_handle->preferred_write_size * 4) / lfs_handle->block_size;
    // Verify we have sufficient buffer space.
    if ((rc = allocate_buffers(lfs_handle, lfs_handle->optimal_count)) != GLOBUS_SUCCESS) {
        goto cleanup;
    }

    while ((lfs_handle->outstanding < lfs_handle->optimal_count) && !is_done(lfs_handle)) {
        // Determine the size of this read operation.
        read_length = lfs_handle->block_size;
        if ((lfs_handle->op_length != -1)
                && (lfs_handle->op_length < (globus_ssize_t)lfs_handle->block_size)) {
            read_length = lfs_handle->op_length;
        }

        // Short-circuit the case where we are done
        if (read_length == 0) {
            set_done(lfs_handle, GLOBUS_SUCCESS);
            break;
        }

        // Determine a buffer for this read to use.
        if ((idx = find_empty_buffer(lfs_handle)) < 0) {
            GenericError(lfs_handle, "Ran out of buffer space", rc)
            break;
        }

        // Record the offset and buffer length
        lfs_handle->nbytes[idx] = read_length;
        lfs_handle->offsets[idx] = lfs_handle->offset;

        if ((lfs_read_handle = globus_malloc(sizeof(lfs_read_t*))) == NULL) {
            MemoryError(lfs_handle, "Unable to allocate read handle", rc)
            break;
        }
        lfs_read_handle->idx = idx;
        lfs_read_handle->lfs_handle = lfs_handle;

        rc = globus_callback_register_oneshot(
            NULL,
            NULL,
            lfs_perform_read_cb,
            lfs_read_handle);

        if (rc != GLOBUS_SUCCESS) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to create callback\n");
            break;
        }
        lfs_handle->outstanding++;
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Issued read from buffer %u (outstanding=%u).\n", idx, lfs_handle->outstanding);

        lfs_handle->offset += read_length;
        if (lfs_handle->op_length != -1) {
            lfs_handle->op_length -= read_length;
        }
    }

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        set_done(lfs_handle, rc);
        globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
    }

}

