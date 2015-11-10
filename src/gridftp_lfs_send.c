#include "gridftp_lfs.h"

#include "type_malloc.h"
#include "stack.h"
#include "apr_wrapper.h"

// Forward declarations
void lfs_read_thread_initialize(lfs_handle_t *lfs_handle);
int lfs_read_thread_destroy(lfs_handle_t * lfs_handle);
bool lfs_read_file_open(lfs_handle_t * lfs_handle, char ** errstr);
Stack_ele_t * lfs_read_get_block(lfs_handle_t * lfs_handle,
                                    Stack_t * stack,
                                    apr_thread_mutex_t * lock,
                                    apr_thread_cond_t * cond);
ex_off_t lfs_read_perform_read(lfs_handle_t * lfs_handle,
                                lfs_buffer_t * buf,
                                ex_off_t nbytes,
                                ex_off_t offset);
globus_result_t lfs_read_handle_error(lfs_buffer_t * buf,
                                        ex_off_t offset,
                                        ex_off_t nbytes,
                                        ex_off_t nread);

//
// lfs_send - called by gridftp to begin sending a file to another server
//
void lfs_send(globus_gfs_operation_t op,
              globus_gfs_transfer_info_t * transfer_info,
              void * user_arg)
{
    GlobusGFSName(globus_l_gfs_lfs_send);
    globus_result_t rc = GLOBUS_SUCCESS;
    char * errstr;

    // Set up handle
    lfs_handle_t * lfs_handle = (lfs_handle_t *) user_arg;
    lfs_handle->pathname = transfer_info->pathname;
    lfs_handle->op = op;
    lfs_handle->backend_done = 0;
    lfs_handle->done = 0;
    lfs_handle->done_status = GLOBUS_SUCCESS;
	lfs_handle->pathname_munged = transfer_info->pathname;
    lfs_handle->is_lio = is_lfs_path(lfs_handle, lfs_handle->pathname);
    if (lfs_handle->is_lio) {
        munge_lfs_path(lfs_handle, &lfs_handle->pathname_munged);
    }
    globus_gridftp_server_get_block_size(op, (globus_size_t *)
                                                &lfs_handle->gridftp_buffer_size);
    globus_gridftp_server_get_read_range(lfs_handle->op,
                                         &lfs_handle->offset,
                                         &lfs_handle->op_length);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
                           "Operation starting at %d, length %d\n", lfs_handle->offset,
                           lfs_handle->op_length);
    if (lfs_read_file_open(lfs_handle, &errstr)) {
        goto cleanup;
    }
    globus_gridftp_server_begin_transfer(op, GLOBUS_SUCCESS, lfs_handle);
    lfs_read_thread_initialize(lfs_handle);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Beginning to send file.\n");
    return;

cleanup:
    rc = GlobusGFSErrorGeneric(errstr);
    set_done(lfs_handle, rc);
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to open file\n");
    globus_gridftp_server_finished_transfer(op, rc);
}

//
// lfs_finished_read_cb - Callback from globus to say a buffer is unused
//
static void lfs_finished_read_cb(__attribute__((unused)) globus_gfs_operation_t op,
                                 __attribute__((unused)) globus_result_t result,
                                 __attribute__((unused)) globus_byte_t * buffer,
                                    globus_size_t nbytes,
                                    void * user_arg)
{
    GlobusGFSName(lfs_handle_read_cb);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Enter read callback\n");
    Stack_ele_t *ele = (Stack_ele_t *)user_arg;
    lfs_buffer_t *buf = (lfs_buffer_t *)get_stack_ele_data(ele);
    if (!buf) {
        goto teardown;
    }
    globus_result_t rc = buf->eof;
    lfs_handle_t *lfs_handle = buf->lfs_handle;
    
    ex_off_t offset = buf->offset;

    log_printf(1, "fname=%s nbytes=" XOT " eof=%d\n", lfs_handle->pathname, nbytes,
               rc);

    // ** Notify the backend that we are ready for more
    apr_thread_mutex_lock(lfs_handle->backend_stack.lock);
    push_link(lfs_handle->backend_stack.stack, ele);
    apr_thread_cond_broadcast(lfs_handle->backend_stack.cond);
    apr_thread_mutex_unlock(lfs_handle->backend_stack.lock);

    log_printf(1, "offset=" XOT " last=" XOT "\n", offset,
               lfs_handle->last_block_offset);

    if ((nbytes != (unsigned) lfs_handle->buffer_size) ||
            (lfs_handle->last_block_offset == offset) ||
            (rc != GLOBUS_SUCCESS)) {
        // Make sure to propagate the error properly
        apr_thread_mutex_lock(lfs_handle->lock);
        if (lfs_handle->done_status != GLOBUS_SUCCESS) {
            // If done_status is already an error, we want to preseve it
            set_done(lfs_handle, lfs_handle->done_status);
        } else {
            // Otherwise, set it to the error code we just got
            set_done(lfs_handle, rc);
        }
        apr_thread_mutex_unlock(lfs_handle->lock);
        log_printf(1, "Triggering shutdown.  rc=%d GLOBUS_SUCCESS=%d\n",
                        lfs_handle->done_status,
                        GLOBUS_SUCCESS);
    }
teardown:
    apr_thread_mutex_lock(lfs_handle->lock);
    if ((lfs_handle->done != 2) && (lfs_handle->backend_done == 1)) {
        lfs_handle->done = 2;
        //** Release the lock because lfs_read_thread_destroy may use it
        apr_thread_mutex_unlock(lfs_handle->lock);
        lfs_read_thread_destroy(lfs_handle);
        apr_thread_mutex_lock(lfs_handle->lock);  //** And get it back
        globus_gridftp_server_finished_transfer(op, lfs_handle->done_status);
    } else if (lfs_handle->done != 2) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Waiting on backend to die\n");
    }
    apr_thread_mutex_unlock(lfs_handle->lock);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Exit read callback\n");
}

//
// lfs_read_thread - Thread task for reading data fro mthe backend
//
void *lfs_read_thread(__attribute__((unused)) apr_thread_t *th, void *data)
{
    lfs_handle_t *lfs_handle = (lfs_handle_t *)data;
    Stack_t *stack = lfs_handle->backend_stack.stack;
    apr_thread_cond_t *cond = lfs_handle->backend_stack.cond;
    apr_thread_mutex_t *lock = lfs_handle->backend_stack.lock;
    Stack_ele_t *ele;
    lfs_buffer_t *buf;
    ex_off_t nbytes, nread, total_left, offset;
    int i, finished;
    globus_result_t rc = GLOBUS_SUCCESS;

    GlobusGFSName(lfs_read_thread);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Within reader thread.\n");
    // ** Set up the initial position
    total_left = lfs_handle->op_length;
    offset = lfs_handle->offset;
    finished = 0;

    log_printf(1, "offset=" XOT " nleft=" XOT "\n", offset, total_left);

    while ((finished == 0) && (total_left > 0)) {
        // ** Get the next block to process
        if ((ele = lfs_read_get_block(lfs_handle, stack, lock, cond)) == NULL) {
            // Nothing left on the queue, time to bomb.
            finished = 1;
            continue;
        } else {
            buf = get_stack_ele_data(ele);
        }
        // ** If we made it here it's time to get the next block
        buf->eof = GLOBUS_SUCCESS;
        nbytes = (total_left > lfs_handle->buffer_size) ?
                                                    lfs_handle->buffer_size :
                                                    total_left;
        nread = lfs_read_perform_read(lfs_handle, buf, nbytes, offset);
        buf->offset = offset;
        buf->nbytes = nbytes;

        // ** Got a problem so kick out with an error
        if (nbytes != nread) {
            rc = lfs_read_handle_error(buf, offset, nbytes, nread);
            nbytes = offset = 0;
            finished = 1;
        }

        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Register callback\n");
        rc = globus_gridftp_server_register_write(lfs_handle->op,
                (globus_byte_t *)buf->buffer, nbytes, offset, -1, lfs_finished_read_cb, ele);
        log_printf(5, "register_write offset=" XOT " nbytes=" XOT " eof=%d rc=%d\n",
                   buf->offset, buf->nbytes, buf->eof, rc);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Done register callback\n");
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
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "End write loop\n");

    // ** Wind down the transfers
    if (0) {
    for (i=0; i<lfs_handle->n_buffers && (finished == 0); i++) {
        apr_thread_mutex_lock(lock);
        while ((ele = pop_link(stack)) == NULL) {
            //apr_thread_cond_wait(cond, lock);  // ** Nothing to do so wait
        }
        apr_thread_mutex_unlock(lock);
        buf = get_stack_ele_data(ele);
        log_printf(5, "wind down i=%d buf=%p\n", i, buf);
        flush_log();

        log_printf(5, "wind down i=%d offset=" XOT " nbytes=" XOT " eof=%d\n", i,
                   buf->offset, buf->nbytes, buf->eof);

        free(ele);
    }
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Done winddown\n");
    globus_gridftp_server_register_write(lfs_handle->op,
                    NULL, 0, 0, -1, lfs_finished_read_cb, NULL);

    // ** IF we we made it without issues look and see if GridFTP had a problem
    apr_thread_mutex_lock(lfs_handle->lock);
    if ((lfs_handle->done_status == GLOBUS_SUCCESS) &&
            (rc != GLOBUS_SUCCESS)) {
        lfs_handle->done_status = rc;    
    }
    lfs_handle->backend_done = 1;
    apr_thread_cond_broadcast(lfs_handle->cond);
    apr_thread_mutex_unlock(lfs_handle->lock);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Done read thread\n");
    //lfs_finished_read_cb(NULL, 0 , NULL, 0, NULL);
    return(NULL);
}

//
// lfs_read_thread_initialize - Prepares and starts backend thread
//
void lfs_read_thread_initialize(lfs_handle_t *lfs_handle)
{
    int i;
    Stack_t *stack;
    lfs_buffer_t *buf;
    ex_off_t bsize;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Initialize read thread\n");

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

//
// lfs_read_thread_destroy - Stops and tears down background reader thread
//
int lfs_read_thread_destroy(lfs_handle_t *lfs_handle)
{
    GlobusGFSName(lfs_read_thread_destroy);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Destroy read thread\n");

    apr_status_t value;
    apr_thread_join(&value, lfs_handle->backend_thread);
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_result_t retval = GLOBUS_SUCCESS;
    char * errstr = NULL;

    // ** Now we can safely close everything
    if (lfs_handle->is_lio) {
        retval = gop_sync_exec(gop_lio_close_object(lfs_handle->fd));
        retval = (OP_STATE_SUCCESS == retval) ? 0 : EIO;
        if (retval != 0) {
            errstr = strdup("Failed to close file in LFS");
            lfs_handle->fd = NULL;
        }
        if ((lfs_handle->syslog_host != NULL)) {
            syslog(LOG_INFO, "lfs_close: ret: %i path: %s", retval,
                   lfs_handle->pathname_munged);
        }
    } else {
        if ((retval = close(lfs_handle->fd_posix)) != 0) {
            errstr = strdup("Failed to close file in POSIX");
            lfs_handle->fd_posix = 0;
        }
    }

    if (errstr != NULL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "%s\n", errstr);
        rc = GlobusGFSErrorGeneric(errstr);
        apr_thread_mutex_lock(lfs_handle->lock);
        if (lfs_handle->done_status == GLOBUS_SUCCESS) {
            lfs_handle->done_status = rc;
        }
        apr_thread_mutex_unlock(lfs_handle->lock);
    }
    lfs_queue_teardown(&(lfs_handle->backend_stack));
    free(lfs_handle->data_buffer);
    free(lfs_handle->buffers);
    apr_pool_destroy(lfs_handle->mpool);

    return(retval);
}

//
// lfs_read_file_open - opens a file from either lfs or the filesystem
//
bool lfs_read_file_open(lfs_handle_t * lfs_handle, char ** errstr) {
    int retval;
    if (lfs_handle->is_lio) {
        retval = lio_exists(lfs_handle->fs, lfs_handle->fs->creds,
                            lfs_handle->pathname_munged);
        if (retval == 0) {
            *errstr = strdup("File does not exist");
            goto cleanup;
        }
        if (retval & OS_OBJECT_DIR) {
            *errstr = strdup("The desired path is a directory");
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
            if (errno == EACCES) {
                *errstr = strdup("Permission denied in open");
            } else {
                *errstr = strdup("Unknown LFS error in open");
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
            *errstr = strdup("Could not open POSIX file");
            goto cleanup;
        }
        //** See if we need to fetch the size
        if (lfs_handle->op_length == -1) {
            lfs_handle->op_length = lseek(lfs_handle->fd_posix, 0, SEEK_END);
        }
    }
    return 0;
cleanup:
    return 1;
}

Stack_ele_t * lfs_read_get_block(lfs_handle_t * lfs_handle,
                                    Stack_t * stack,
                                    apr_thread_mutex_t * lock,
                                    apr_thread_cond_t * cond)
{
    Stack_ele_t *ele;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Waiting for block\n");
    apr_thread_mutex_lock(lock);
    while ((ele = pop_link(stack)) == NULL) {
        apr_thread_mutex_unlock(lfs_handle->lock);
        if (lfs_handle->done != 0) {
            // Time to exit
            apr_thread_mutex_unlock(lfs_handle->lock);
            return NULL;
        }
        apr_thread_mutex_unlock(lfs_handle->lock);

        if (ele == NULL) {
            apr_thread_cond_wait(cond, lock);  // ** Nothing to do so wait
            continue;  // ** Try again
        }
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Done waiting for block\n");
    apr_thread_mutex_unlock(lock);
    return ele;
}   

ex_off_t lfs_read_perform_read(lfs_handle_t * lfs_handle,
                                lfs_buffer_t * buf,
                                ex_off_t nbytes,
                                ex_off_t offset)
{
    ex_off_t nleft, nread;
    apr_time_t read_timer;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Writing block\n");
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
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Done writing block\n");
    return nread;
}
globus_result_t lfs_read_handle_error(lfs_buffer_t * buf,
                                        ex_off_t offset,
                                        ex_off_t nbytes,
                                        ex_off_t nread) {
    GlobusGFSName(lfs_read_handle_error);
    globus_result_t rc = GlobusGFSErrorGeneric("Could not read");
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                                   "Failed to read! offset=" XOT " nbytes=" XOT\
                                   " nread=" XOT "\n", offset, nbytes,
                                   nread);
    buf->nbytes = 0;
    buf->offset = 0;
    buf->eof = rc;
    return rc;
}

