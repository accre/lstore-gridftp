#include "gridftp_lfs.h"

#include "type_malloc.h"
#include "stack.h"
#include "apr_wrapper.h"

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}

void lfs_initialize_read(lfs_handle_t *lfs_handle);
int lfs_destroy_read(lfs_handle_t * lfs_handle);

//
// lfs_send - called by gridftp to begin sending a file to another server
//
void lfs_send(globus_gfs_operation_t op,
              globus_gfs_transfer_info_t * transfer_info,
              void * user_arg)
{
    lfs_handle_t *  lfs_handle;
    GlobusGFSName(globus_l_gfs_lfs_send);
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_size_t block_size;
    int retval;

    lfs_handle = (lfs_handle_t *) user_arg;
    lfs_handle->pathname = transfer_info->pathname;
    lfs_handle->pathname_munged = transfer_info->pathname;
    lfs_handle->is_lio = is_lfs_path(lfs_handle, lfs_handle->pathname);
    if (lfs_handle->is_lio) {
        ADVANCE_SLASHES(lfs_handle->pathname_munged)
        if (strncmp(lfs_handle->pathname_munged, lfs_handle->mount_point,
                    lfs_handle->mount_point_len)==0) {
            lfs_handle->pathname_munged += lfs_handle->mount_point_len;
        }
        ADVANCE_SLASHES(lfs_handle->pathname_munged)
    }
    lfs_handle->op = op;
    lfs_handle->done = 0;
    lfs_handle->done_status = GLOBUS_SUCCESS;

    globus_gridftp_server_get_block_size(op, &block_size);
    lfs_handle->gridftp_buffer_size = block_size;

    globus_gridftp_server_get_read_range(lfs_handle->op,
                                         &lfs_handle->offset,
                                         &lfs_handle->op_length);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
                           "Operation starting at %d, length %d\n", lfs_handle->offset,
                           lfs_handle->op_length);

    globus_gridftp_server_begin_transfer(lfs_handle->op, 0, lfs_handle);

    if (lfs_handle->is_lio) {
        retval = lio_exists(lfs_handle->fs, lfs_handle->fs->creds,
                            lfs_handle->pathname_munged);
        if (retval == 0) {
            SystemError(lfs_handle, "opening file for read, doesn't exist", rc);
            errno = ENOENT;
            goto cleanup;
        }
        if (retval & OS_OBJECT_DIR) {
            GenericError(lfs_handle, "The file you are trying to read is a directory", rc);
            goto cleanup;
        }

        lfs_handle->fd = NULL;
        retval = gop_sync_exec(gop_lio_open_object(lfs_handle->fs,
                                                    lfs_handle->fs->creds,
                                                    lfs_handle->pathname_munged,
                                                    lio_fopen_flags("r"), NULL,
                                                    &(lfs_handle->fd), 60));

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Opening from LFS: %s\n",
                               lfs_handle->pathname_munged);
        if (lfs_handle->syslog_host != NULL) {
            syslog(LOG_INFO, "lfs_open: ret: %i path: %s", retval,
                   lfs_handle->pathname_munged);
        }
        if (retval != OP_STATE_SUCCESS) {
            if (0) { //errno == EINTERNAL) {
                SystemError(lfs_handle,
                            "opening file due to an internal LFS error; "
                            "could be a misconfiguration or bad installation at the site.",
                            rc);
            } else if (errno == EACCES) {
                SystemError(lfs_handle, "opening file; permission error in LFS.", rc);
            } else {
                SystemError(lfs_handle,
                            "opening file; failed to open file due to unknown error in LFS.", rc);
            }
            goto cleanup;
        }

        //** See if we need to fetch the size
        if (lfs_handle->op_length == -1) lfs_handle->op_length = lio_size(
                        lfs_handle->fd);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Opening from filesystem: %s\n",
                               lfs_handle->pathname);
        lfs_handle->fd_posix = open(lfs_handle->pathname, O_RDONLY);
        if (lfs_handle->fd_posix == -1) {
            rc = -1;
            SystemError(lfs_handle, "failed to open POSIX file.", rc);
            log_printf(1, "failed to open POSIX file: fname=%s", lfs_handle->pathname);
            goto cleanup;
        }
        //** See if we need to fetch the size
        if (lfs_handle->op_length == -1) lfs_handle->op_length = lseek(
                        lfs_handle->fd_posix, 0, SEEK_END);
    }

    lfs_initialize_read(lfs_handle);

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                "Failed to initialize read setup\n");
        set_done(lfs_handle, rc);
        globus_gridftp_server_finished_transfer(op, rc);
    }
}

//
// lfs_finished_read_cb - called when globus no longer needs a buffer
//
static void lfs_finished_read_cb(__attribute__((unused)) globus_gfs_operation_t op,
                                 __attribute__((unused)) globus_result_t result,
                                 __attribute__((unused)) globus_byte_t * buffer,
                                    globus_size_t nbytes,
                                    void * user_arg)
{
    GlobusGFSName(lfs_handle_read_cb);
    Stack_ele_t *ele = (Stack_ele_t *)user_arg;
    lfs_buffer_t *buf = (lfs_buffer_t *)get_stack_ele_data(ele);
    globus_result_t rc = buf->eof;
    lfs_handle_t *lfs_handle = buf->lfs_handle;
    ex_off_t offset = buf->offset;

    log_printf(1, "fname=%s nbytes=" XOT " eof=%d\n", lfs_handle->pathname, nbytes,
               rc);

    // ** Notify the backend that we are ready for more
    apr_thread_mutex_lock(lfs_handle->backend_stack.lock);
    push_link(lfs_handle->backend_stack.stack, ele);


    if (rc != GLOBUS_SUCCESS) {
        apr_thread_mutex_lock(lfs_handle->lock);
        lfs_handle->done_status = rc;
        apr_thread_mutex_unlock(lfs_handle->lock);
    }

    apr_thread_cond_broadcast(lfs_handle->backend_stack.cond);
    apr_thread_mutex_unlock(lfs_handle->backend_stack.lock);

    log_printf(1, "offset=" XOT " last=" XOT "\n", offset,
               lfs_handle->last_block_offset);

    if ((nbytes != (unsigned) lfs_handle->buffer_size)
            || (lfs_handle->last_block_offset == offset) || (rc != GLOBUS_SUCCESS)) {
        log_printf(1, "Triggering shutdown.  rc=%d GLOBUS_SUCCESS=%d\n", rc,
                   GLOBUS_SUCCESS);
        // ** This can trigger a GridFTP segfault but it looks to be a gridftp
        // problem not LIO.
        globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
        lfs_destroy_read(lfs_handle);
    }
}


// *************************************************************************
//   lfs_destroy_read - Tears down up all the LFS bits for reading a file
// *************************************************************************

int lfs_destroy_read(lfs_handle_t *lfs_handle)
{
    globus_result_t retval;
    apr_status_t value;

    GlobusGFSName(lfs_destroy_read);

    apr_thread_join(&value, lfs_handle->backend_thread);

    retval = GLOBUS_SUCCESS;

    // ** Now we can safely close everything
    if (lfs_handle->is_lio) {
        retval = gop_sync_exec(gop_lio_close_object(lfs_handle->fd));
        retval = (OP_STATE_SUCCESS == retval) ? 0 : EIO;
        if (retval != 0) {
            STATSD_COUNT("lfs_write_close_failure", 1);
            GenericError(lfs_handle, "Failed to close file in LFS.", retval);
            lfs_handle->fd = NULL;
        }
        if ((lfs_handle->syslog_host != NULL)) {
            syslog(LOG_INFO, "lfs_close: ret: %i path: %s", retval,
                   lfs_handle->pathname_munged);
        }
    } else {
        if ((retval = close(lfs_handle->fd_posix)) != 0) {
            GenericError(lfs_handle, "Failed to close file in POSIX.", retval);
            lfs_handle->fd_posix = 0;
        }
    }

    lfs_queue_teardown(&(lfs_handle->backend_stack));
    free(lfs_handle->data_buffer);
    free(lfs_handle->buffers);
    apr_pool_destroy(lfs_handle->mpool);

    return(retval);
}
// *************************************************************************
// lfs_read_thread - Thread task for reading data fro mthe backend
// *************************************************************************

void *lfs_read_thread(__attribute__((unused)) apr_thread_t *th, void *data)
{
    lfs_handle_t *lfs_handle = (lfs_handle_t *)data;
    Stack_t *stack = lfs_handle->backend_stack.stack;
    apr_thread_cond_t *cond = lfs_handle->backend_stack.cond;
    apr_thread_mutex_t *lock = lfs_handle->backend_stack.lock;
    apr_time_t read_timer;
    Stack_ele_t *ele;
    lfs_buffer_t *buf;
    ex_off_t nbytes, nread, nleft, total_left, offset;
    int i, rc, oops, finished;

    GlobusGFSName(lfs_read_thread);

    // ** Set up the initial position
    total_left = lfs_handle->op_length;
    offset = lfs_handle->offset;
    finished = 0;

    log_printf(1, "offset=" XOT " nleft=" XOT "\n", offset, total_left);
    oops = GLOBUS_SUCCESS;

    while ((finished == 0) && (total_left > 0)) {
        // ** Get the next block to process
        apr_thread_mutex_lock(lock);
        while ((ele = pop_link(stack)) == NULL) {
            if (ele == NULL) {
                apr_thread_cond_wait(cond, lock);  // ** Nothing to do so wait
                continue;  // ** Try again
            }
        }
        apr_thread_mutex_unlock(lock);

        //ele = pop_link(stack);

        // ** Make sure it's valid data and not an exit sentinel
        buf = get_stack_ele_data(ele);
        if (buf == NULL) {  // ** This tells us to kick out
            finished = 1;
            continue;
        }

        // ** If we made it here it's time to get the next block
        buf->eof = GLOBUS_SUCCESS;
        nbytes = (total_left > lfs_handle->buffer_size) ? lfs_handle->buffer_size :
                 total_left;
        if (lfs_handle->is_lio == 1) {
            log_printf(5, "offset=" XOT " nbytes=" XOT "\n", offset, nbytes);
            STATSD_TIMER_RESET(read_timer);
            nread = lio_read(lfs_handle->fd, buf->buffer, nbytes, offset, NULL);
            STATSD_TIMER_POST("read_time", read_timer);
            STATSD_COUNT("lfs_bytes_read",nread);

        } else {
            nleft = nbytes;
            nread = 0;
            STATSD_TIMER_RESET(read_timer);
            while ((nread = pread(lfs_handle->fd_posix, buf->buffer + nread, nleft,
                                  offset + nread)) != -1) {
                nleft -= nread;
                if (nleft == 0) break;  // ** Finished so kick out
            }
            nread = nbytes - nleft;
            STATSD_TIMER_POST("read_time", read_timer);
            STATSD_COUNT("posix_bytes_read",nread);
        }

        buf->offset = offset;
        buf->nbytes = nbytes;

        // ** Got a problem so kick out with an error
        if (nbytes != nread) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                                   "Failed to read! offset=" XOT " nbytes=" XOT\
                                   " nread=" XOT "\n", offset, nbytes,
                                   nread);
            SystemError(lfs_handle, "reading from posix", rc);
            buf->nbytes = 0;
            buf->offset = 0;
            // ** This can trigger an error in GridFTP but it's not a bug in
            // the plugin!
            buf->eof = GLOBUS_FAILURE;
            nbytes = offset = 0;
            finished = 1;
            oops = EREMOTEIO;

        }

        rc = globus_gridftp_server_register_write(lfs_handle->op,
                (globus_byte_t *)buf->buffer, nbytes, offset, -1, lfs_finished_read_cb, ele);
        log_printf(5, "register_write offset=" XOT " nbytes=" XOT " eof=%d rc=%d\n",
                   buf->offset, buf->nbytes, buf->eof, rc);
        if (rc != GLOBUS_SUCCESS) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to create callback\n");
            finished = 1;

            // ** Add the current element back on the stack cause we are kicking out
            apr_thread_mutex_lock(lock);
            push_link(stack, ele);
            apr_thread_mutex_unlock(lock);
        }

        total_left -= nbytes;
        offset += nbytes;
    }

    // ** Send the sentinel that we are done.


    // ** Wind down the transfers
    for (i=0; i<lfs_handle->n_buffers; i++) {
        apr_thread_mutex_lock(lock);
        while ((ele = pop_link(stack)) == NULL) {
            apr_thread_cond_wait(cond, lock);  // ** Nothing to do so wait
        }
        apr_thread_mutex_unlock(lock);
        buf = get_stack_ele_data(ele);
        log_printf(5, "wind down i=%d buf=%p\n", i, buf);
        flush_log();

        log_printf(5, "wind down i=%d offset=" XOT " nbytes=" XOT " eof=%d\n", i,
                   buf->offset, buf->nbytes, buf->eof);

        free(ele);
    }

    // ** IF we we made it without issues look and see if GridFTP had a problem
    if (oops == GLOBUS_SUCCESS) oops = lfs_handle->done_status;

    // ** Notify the server we're finished
//  globus_gridftp_server_finished_transfer(lfs_handle->op, oops);
    return(NULL);
}

// *************************************************************************
//   lfs_initialize_read - Sets up all the LFS bits for reading a file
// *************************************************************************

void lfs_initialize_read(lfs_handle_t *lfs_handle)
{
    int i;
    Stack_t *stack;
    lfs_buffer_t *buf;
    ex_off_t bsize;

    // **  Initialize the backend stack
    lfs_queue_init(&(lfs_handle->backend_stack), lfs_handle->mpool);
    bsize = lfs_handle->total_buffer_size / lfs_handle->send_stages;
    // ** This gives us an estimate for the number of "blocks"
    bsize /= lfs_handle->gridftp_buffer_size;
    if (bsize <= 0) bsize = 1;
    // ** Now get it back in bytes using the integer divide rounding from above
    bsize *= lfs_handle->gridftp_buffer_size;
    lfs_handle->n_buffers = lfs_handle->send_stages;
    lfs_handle->total_buffer_size = bsize * lfs_handle->n_buffers;
    lfs_handle->last_block_offset = lfs_handle->op_length / bsize;
    i = lfs_handle->op_length % bsize;
    lfs_handle->buffer_size = bsize;
    log_printf(5, "nblocks=" XOT " op_length=" XOT " bsize=" XOT " rem=%d\n",
               lfs_handle->last_block_offset, lfs_handle->op_length, bsize, i);
    log_printf(5, "nbufs=%d gbsize=" XOT " bsize= " XOT "\n", lfs_handle->n_buffers,
               lfs_handle->gridftp_buffer_size, lfs_handle->buffer_size, i);
    if (i == 0) lfs_handle->last_block_offset--;
    lfs_handle->last_block_offset *= bsize;

    atomic_set(lfs_handle->inflight_count, lfs_handle->n_buffers);

    // ** Make the buffers and submit the initial set of tasks
    type_malloc(lfs_handle->data_buffer, char,
                lfs_handle->buffer_size*lfs_handle->n_buffers);
    type_malloc_clear(lfs_handle->buffers, lfs_buffer_t, lfs_handle->n_buffers);
    stack = lfs_handle->backend_stack.stack;
    for (i=0; i<lfs_handle->n_buffers; i++) {
        buf = &(lfs_handle->buffers[i]);
        buf->buffer = &(lfs_handle->data_buffer[i*lfs_handle->buffer_size]);
        buf->lfs_handle = lfs_handle;
        push(stack, buf);
    }

    // ** Launch the backend thread
    thread_create_assert(&(lfs_handle->backend_thread), NULL, lfs_read_thread,
                         (void *)lfs_handle, lfs_handle->mpool);
}


