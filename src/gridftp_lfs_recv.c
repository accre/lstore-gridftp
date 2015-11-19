#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <math.h>
#include "gridftp_lfs.h"
#include "lio.h"
#include "interval_skiplist.h"
#include "type_malloc.h"
#include "list.h"
#include "ex3_compare.h"
#include "stack.h"
#include "apr_wrapper.h"

// Forward declarations of local functions
static void
lfs_handle_write_op(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    globus_off_t                        offset,
    globus_bool_t                       eof,
    void *                              user_arg);

globus_result_t lfs_write_close(lfs_handle_t * lfs_handle);
static globus_result_t lfs_write_finish_transfer(lfs_handle_t *lfs_handle);
bool lfs_prepare_handle(lfs_handle_t *lfs_handle, globus_gfs_operation_t op, globus_gfs_transfer_info_t * transfer_info, char **errstr);
void lfs_initialize_writers(lfs_handle_t *lfs_handle);
void *lfs_write_thread(__attribute__((unused)) apr_thread_t * th, void *data);
globus_result_t lfs_init_gridftp_stack(lfs_handle_t * lfs_handle);
bool lfs_write_file_open(lfs_handle_t * lfs_handle, globus_gfs_transfer_info_t *, char ** errstr);
void change_and_check(lfs_handle_t * lfs_handle, int backend, int checksum,
                        int gridftp, int buffered, int inflight_count); 
void lfs_maybe_flush_buffers(lfs_handle_t * lfs_handle, int finished, int force_flush, list_t * sorted_buffers,
                             lfs_cluster_t * cluster, interval_skiplist_t * written_intervals,
                             ex_off_t * cluster_weights, int * cluster_order, ex_iovec_t * ex_iovec,
                             iovec_t * iovec, int * n_holding); 
//
//  lfs_recv - Called when the client requests that a file be transfered to the
//  server.
//
void lfs_recv(globus_gfs_operation_t op,
              globus_gfs_transfer_info_t * transfer_info,
              void * user_arg)
{
    GlobusGFSName(lfs_recv);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Receiving a file: %s\n",
                           transfer_info->pathname);

    char * errstr = NULL;
    lfs_handle_t * lfs_handle = (lfs_handle_t *) user_arg;
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_gridftp_server_begin_transfer(op, GLOBUS_SUCCESS, lfs_handle);

    if (!lfs_prepare_handle(lfs_handle, op, transfer_info, &errstr)) {
        goto cleanup;
    }
    if (!lfs_write_file_open(lfs_handle, transfer_info, &errstr)) {
        goto cleanup;
    }
    lfs_initialize_writers(lfs_handle);
    return;

cleanup:
    rc = GlobusGFSErrorGeneric(errstr);
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to recv file: %s\n", errstr);
    globus_gridftp_server_finished_transfer(op, rc);
    return;
}

//
// lfs_handle_write_op - Called when globus has data to write
//
// Pops off gridftp counter, pushes onto checksum counter
//
static void lfs_handle_write_op(globus_gfs_operation_t op,
                                globus_result_t result,
                                globus_byte_t * buffer,
                                globus_size_t nbytes,
                                globus_off_t offset,
                                globus_bool_t eof,
                                void * user_arg)
{
    GlobusGFSName(lfs_handle_write_op);
    Stack_ele_t *ele = (Stack_ele_t *)user_arg;
    lfs_buffer_t *buf = (lfs_buffer_t *)get_stack_ele_data(ele);
    lfs_handle_t *lfs_handle = buf->lfs_handle;

    if (result != GLOBUS_SUCCESS) {
        set_done(lfs_handle, result);
        return;
    } else if (eof) {
        set_done(lfs_handle, GLOBUS_SUCCESS);
    }

    // ** Update the buffer
    assert((globus_byte_t *)buf == buffer);
    buf->offset = offset;
    buf->nbytes = nbytes;
    buf->eof = eof;
    globus_gridftp_server_update_bytes_written(op, offset, nbytes);

    // Push buffer from gridftp to checksum
    apr_thread_mutex_lock(lfs_handle->cksum_stack.lock);
    push_link(lfs_handle->cksum_stack.stack, ele);
    apr_thread_cond_signal(lfs_handle->cksum_stack.cond);
    apr_thread_mutex_unlock(lfs_handle->cksum_stack.lock);
    change_and_check(lfs_handle, 0, 1, -1, 0, 0);
}

//
// lfs_write_thread - Thread task for doing aggregation and dumping to the backend
//
// Once the loop runs, pops off backend counter, pushes onto buffered counter
void *lfs_write_thread(__attribute__((unused)) apr_thread_t * th, void *data)
{
    GlobusGFSName(lfs_write_thread);
    lfs_handle_t *lfs_handle = (lfs_handle_t *)data;
    apr_thread_cond_t *cond = lfs_handle->backend_stack.cond;
    apr_thread_mutex_t *lock = lfs_handle->backend_stack.lock;
    Stack_ele_t *ele;
    lfs_buffer_t *buf;
    int finished, i, *cluster_order, n_holding, force_flush;
    ex_off_t *cluster_weights;
    int rc, eof;
    rc = GLOBUS_SUCCESS;
    lfs_interval_t *interval;
    lfs_interval_t **iptr;
    list_t *sorted_buffers;
    lfs_cluster_t *cluster;
    interval_skiplist_t *written_intervals;
    interval_skiplist_iter_t it;
    ex_off_t lo, hi, last_byte, last;
    ex_iovec_t *ex_iovec;
    iovec_t *iovec;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Beginning write thread.\n");

    // ** Make the local clustering structures
    type_malloc(ex_iovec, ex_iovec_t, lfs_handle->n_buffers);
    type_malloc(iovec, iovec_t, lfs_handle->n_buffers);
    type_malloc(cluster_weights, ex_off_t, lfs_handle->n_buffers);
    type_malloc(cluster_order, int, lfs_handle->n_buffers);
    type_malloc(cluster, lfs_cluster_t, lfs_handle->n_buffers);
    for (i=0; i<lfs_handle->n_buffers; i++) {
        init_stack(&(cluster[i].stack));
    }

    written_intervals = create_interval_skiplist(&skiplist_compare_ex_off, NULL,
                        NULL, free);
    n_holding = log2(lfs_handle->n_buffers);
    if (n_holding == 0) {
        n_holding = 10;
    }
    sorted_buffers = create_skiplist_full(n_holding, 0.5, 0,
                                          &skiplist_compare_ex_off, NULL, NULL, NULL);
    finished = 0;
    n_holding = 0;
    //of = 0;
    last_byte = 0;

    // ****** Fire off the initial set of tasks *****
    // ** The sleep() helps make sure we get most of the buffers registered.
    // ** Otherwise most will get rejected because the server isn't ready yet.
    sleep(1);
    lfs_init_gridftp_stack(lfs_handle);

    while (finished == 0) {
        // Pop next block off the backend
        apr_thread_mutex_lock(lock);
        while (!is_done(lfs_handle) && \
                    (ele = pop_link(lfs_handle->backend_stack.stack)) == NULL) {
            if (is_done(lfs_handle)) {
                finished = 1;
                break;
            }
            apr_thread_cond_wait(cond, lock);  // ** Nothing to do so wait
        }
        apr_thread_mutex_unlock(lock);
        if (finished == 1) {
            break;
        }

        // Now that we have a block, see if it has real data
        buf = get_stack_ele_data(ele);
        if (!buf) {
            break;
        }
        if (buf->nbytes > 0) {
            // Got a read, pop it into the buffers for eventual writing
            n_holding++;
            last = buf->offset + buf->nbytes;
            if (last > last_byte) last_byte = last;
            list_insert(sorted_buffers, &(buf->offset), ele);
            change_and_check(lfs_handle, -1, 0, 0, 1, 0);
        } else {
            // Got nothing back. Drop the element.
            free(ele);
            change_and_check(lfs_handle, -1, 0, 0, 0, -1);
            set_done(lfs_handle, rc);
        }
        if (buf->eof == 1) eof = 1;
        // ** Check if we need to force a buffer flush
        force_flush = 0;
        if (lfs_handle->inflight_count == n_holding) {
            force_flush = 1;
            if (eof == 1) {
                finished = 1;
                set_done(lfs_handle, rc);
            }
        }

        if (finished || force_flush) {
            lfs_maybe_flush_buffers(lfs_handle, finished, force_flush,
                    sorted_buffers, cluster, written_intervals,
                    cluster_weights, cluster_order, ex_iovec, iovec,
                    &n_holding);
            finished = (lfs_handle->inflight_count > 0) ? 0 : 1;
        }
        if (finished) {
            set_done(lfs_handle, rc);
        }
    }

    // ** Cleanup
    // ** Store the global adler32 in the handle
    rc = interval_skiplist_count(written_intervals);
    if (rc != 1) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                               "ERROR: Bad checksum!  Multiple intervals! n=%d\n", rc);
        set_done(lfs_handle, GlobusGFSErrorGeneric(strdup("checksum error")));
        lfs_handle->adler32_human[0] = 0;
    } else {
        lo = 0;
        hi = 1;
        it = iter_search_interval_skiplist(written_intervals, (skiplist_key_t *)&lo,
                                           (skiplist_key_t *)&hi);
        interval = next_interval_skiplist(&it);
        human_readable_adler32(lfs_handle->adler32_human, interval->adler32);
    }

    // Destroy all the work arrays
    free(ex_iovec);
    free(iovec);
    free(cluster_weights);
    free(cluster_order);
    free(cluster);

    // Make sure we wrote a contiguous set of bytes
    if (rc > 1) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Non-contiguous bytes written\n");
        type_malloc(iptr, lfs_interval_t *, interval_skiplist_count(written_intervals));
        it = iter_search_interval_skiplist(written_intervals,
                                           (skiplist_key_t *)NULL,
                                           (skiplist_key_t *)NULL);
        i = 0;
        while ((interval = next_interval_skiplist(&it)) != NULL) {
            iptr[i] = interval;
        }
        destroy_interval_skiplist(written_intervals);
        for (i=0; i<lo; i++) {
            free(iptr[i]);
        }
    } else {
        destroy_interval_skiplist(written_intervals);
        if (rc == 1) {
            free(interval);
        }
    }

    // Truncate to the proper size
    if (lfs_handle->is_lio) {
        gop_sync_exec(gop_lio_truncate(lfs_handle->fd, last_byte));
    }

    // Close up shop and exit
    list_destroy(sorted_buffers);
    rc = lfs_write_finish_transfer(lfs_handle);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"adler32=%s\n",
                           lfs_handle->adler32_human);

    apr_thread_mutex_lock(lfs_handle->lock);
    globus_result_t retval = lfs_handle->done_status;
    if (retval == GLOBUS_SUCCESS) {
        retval = rc;
    }

    globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
    return(NULL);
}


// *************************************************************************
//   lfs_initialize_writers - Sets up all the LFS bits for writing to a file
// *************************************************************************
// Ignore the result from thread_create_assert
#pragma GCC diagnostic warning "-Wunused-variable"
void lfs_initialize_writers(lfs_handle_t *lfs_handle)
{
    thread_create_assert(&(lfs_handle->backend_thread), NULL, lfs_write_thread,
                         (void *)lfs_handle, lfs_handle->mpool);
    int i;
    for (i=0; i<lfs_handle->n_cksum_threads; i++) {
        thread_create_assert(&(lfs_handle->cksum_thread[i]), NULL, lfs_cksum_thread,
                             (void *)lfs_handle, lfs_handle->mpool);
    }
}
#pragma GCC diagnostic error "-Wunused-variable"

void lfs_destroy_writers(lfs_handle_t *lfs_handle)
{
    int n_cksum, i;
    lfs_queue_t *q;
    Stack_t *stack;
    Stack_ele_t *ele;
    apr_status_t value;
    // ** Shutdown the cksum threads
    stack = new_stack();
    n_cksum = lfs_handle->n_cksum_threads;
    q = &(lfs_handle->cksum_stack);
    apr_thread_mutex_lock(q->lock);
    for (i=0; i<n_cksum; i++) {
        push(stack, NULL);
        ele = pop_link(stack);  // ** Create the dummy stack element to dump
        push_link(q->stack, ele);
    }
    apr_thread_cond_broadcast(q->cond);
    apr_thread_mutex_unlock(q->lock);
    free(stack);

    // ** Wait for them to complete
    apr_thread_mutex_lock(lfs_handle->lock);
    while (lfs_handle->n_cksum_threads > 0) {
        apr_thread_mutex_lock(q->lock);
        apr_thread_cond_broadcast(q->cond);
        apr_thread_mutex_unlock(q->lock);
        apr_thread_cond_wait(lfs_handle->cond, lfs_handle->lock);
    }
    apr_thread_mutex_unlock(lfs_handle->lock);

    // ** And reap them
    for (i=0; i<n_cksum; i++) {
        apr_thread_join(&value, lfs_handle->cksum_thread[i]);
    }
    free(lfs_handle->cksum_thread);

    // ** Now do the same for the writer thread. It triggers the exit so just reap it
    apr_thread_join(&value, lfs_handle->backend_thread);
}

//
// lfs_prepare_handle - initialize our lfs_handle_t
//

bool lfs_prepare_handle(lfs_handle_t *lfs_handle, globus_gfs_operation_t op, globus_gfs_transfer_info_t * transfer_info, char **errstr)
{
    STATSD_COUNT("prepare_handle",1);
    GlobusGFSName(prepare_handle);

    lfs_handle->op = op;
    lfs_handle->done_status = GLOBUS_SUCCESS;
    lfs_handle->backend_counter = 0;
    lfs_handle->checksum_counter = 0;
    lfs_handle->gridftp_counter = 0;
	lfs_handle->pathname = transfer_info->pathname;
	lfs_handle->pathname_munged = transfer_info->pathname;
    lfs_handle->is_lio = is_lfs_path(lfs_handle, lfs_handle->pathname);
    lfs_handle->expected_checksum = NULL;
    lfs_handle->done = GLOBUS_FALSE;
    lfs_handle->done_status = GLOBUS_SUCCESS;

    // Set buffers
    globus_size_t block_size;
    globus_gridftp_server_get_block_size(lfs_handle->op, &block_size);
    lfs_handle->buffer_size = (ex_off_t)block_size;
    lfs_handle->n_buffers = lfs_handle->total_buffer_size / lfs_handle->buffer_size;
    if (lfs_handle->n_buffers == 0) lfs_handle->n_buffers = 1;
    lfs_handle->low_water_flush = lfs_handle->n_buffers *
                                  lfs_handle->low_water_fraction;
    if (lfs_handle->low_water_flush == 0) lfs_handle->low_water_flush = 1;
    lfs_handle->high_water_flush = lfs_handle->n_buffers *
                                   lfs_handle->high_water_fraction;
    if (lfs_handle->high_water_flush == 0) lfs_handle->high_water_flush = 1;


    // Make queues
    lfs_queue_init(&(lfs_handle->cksum_stack), lfs_handle->mpool);
    lfs_queue_init(&(lfs_handle->backend_stack), lfs_handle->mpool);

    // ** Make the buffers.  The write thread submits the initial set of tasks
    type_malloc(lfs_handle->data_buffer, char,
                lfs_handle->buffer_size * lfs_handle->n_buffers);
    type_malloc_clear(lfs_handle->buffers, lfs_buffer_t, lfs_handle->n_buffers);
    type_malloc_clear(lfs_handle->cksum_thread, apr_thread_t *,
                                                lfs_handle->n_cksum_threads);
    munge_lfs_path(lfs_handle, &lfs_handle->pathname_munged);

    if (transfer_info->expected_checksum) {
        lfs_handle->expected_checksum = strdup(transfer_info->expected_checksum);
    }
    *errstr = *errstr;
    return 1;
}

//
//  lfs_write_finish_transfer - Called by gridftp to close the file
//
static globus_result_t lfs_write_finish_transfer(lfs_handle_t *lfs_handle)
{
    STATSD_COUNT("lfs_gridftp_finish_transfer",1);
    GlobusGFSName(lfs_write_finish_transfer);
    globus_result_t retval = GLOBUS_SUCCESS;
    lfs_destroy_writers(lfs_handle);
    lfs_queue_teardown(&(lfs_handle->cksum_stack));
    lfs_queue_teardown(&(lfs_handle->backend_stack));
    
    retval = lfs_write_close(lfs_handle);
    
    free(lfs_handle->data_buffer);
    free(lfs_handle->buffers);
    apr_pool_destroy(lfs_handle->mpool);

    return retval;
}

//
// lfs_init_gridftp_stack - Fires off the initial gridftp xfers.
//
globus_result_t lfs_init_gridftp_stack(lfs_handle_t * lfs_handle) {
    Stack_t * stack;
    Stack_ele_t * ele;
    int i;
    globus_result_t rc = GLOBUS_SUCCESS;
    lfs_buffer_t * buf;
    stack = new_stack();
    for (i=0; i<lfs_handle->n_buffers; i++) {
        buf = &(lfs_handle->buffers[i]);
        buf->buffer = &(lfs_handle->data_buffer[i*lfs_handle->buffer_size]);
        buf->lfs_handle = lfs_handle;
        push(stack, buf);
        ele = pop_link(stack);

        rc = globus_gridftp_server_register_read(lfs_handle->op,
                (globus_byte_t *)buf->buffer, lfs_handle->buffer_size, lfs_handle_write_op,
                (void *) ele);
        if (rc != GLOBUS_SUCCESS) {
            //set_done(lfs_handle, rc);
            free(ele);  // ** Just free the stack structure
        } else {
            change_and_check(lfs_handle, 0, 0, 1, 0, 1);
        }
    }
    free(stack);
    return rc;
}

//
// lfs_write_file_open - Opens a file for writing (either in LFS or via POSIX)
//
bool lfs_write_file_open(lfs_handle_t * lfs_handle, globus_gfs_transfer_info_t * transfer_info, char ** errstr) {
    int retval;
    lfs_handle->is_lio = is_lfs_path(lfs_handle, lfs_handle->pathname); 
    if (lfs_handle->is_lio) {
        lfs_handle->fd = NULL;
        retval = gop_sync_exec(gop_lio_open_object(lfs_handle->fs,
                               lfs_handle->fs->creds,
                               lfs_handle->pathname_munged,
                               lio_fopen_flags("w"), NULL,
                               &(lfs_handle->fd), 60));
        if (retval != OP_STATE_SUCCESS) {
            *errstr = strdup("Can't open file");
            goto cleanup;
        }

        retval = 0;
        if (lfs_handle->fd == NULL) {
            retval = lio_exists(lfs_handle->fs, lfs_handle->fs->creds,
                                lfs_handle->pathname_munged);

            if (retval & OS_OBJECT_DIR) {
                *errstr = strdup("Destination path is a directory");
                goto cleanup;
            }
        }

        if (lfs_handle->syslog_host != NULL) {
            syslog(LOG_INFO, "lfs_open: ret: %i path: %s", retval,
                   lfs_handle->pathname_munged);
        }

        if (transfer_info->alloc_size > 0) {
            // hopefully this is the size we want to have the file be later
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                                   "Extending to %i bytes via client request\n", transfer_info->alloc_size);
            gop_sync_exec(gop_lio_truncate(lfs_handle->fd, -transfer_info->alloc_size));
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, " ... complete\n",
                                   transfer_info->alloc_size);
        } else if (lfs_handle->default_size > 0) {
            gop_sync_exec(gop_lio_truncate(lfs_handle->fd, -lfs_handle->default_size));
        }
    } else {
        retval = open(lfs_handle->pathname,  O_WRONLY | O_CREAT,
                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );
        if (retval > 0) {
            lfs_handle->fd_posix = retval;
        } else {
            *errstr = strdup("opening file; POSIX error");
            goto cleanup;
        }
    }
    return 1;
cleanup:
    return 0;
}

globus_result_t lfs_write_close(lfs_handle_t * lfs_handle) {
    GlobusGFSName(lfs_write_close);
    globus_result_t retval = GLOBUS_SUCCESS;
    // ** Now we can safely close everything
    if (lfs_handle->is_lio) {
        retval = gop_sync_exec(gop_lio_close_object(lfs_handle->fd));
        if (retval != OP_STATE_SUCCESS) {
            STATSD_COUNT("lfs_write_close_failure", 1);
            retval = GlobusGFSErrorGeneric("Failed to close file in LFS");
            set_done(lfs_handle, retval);
            lfs_handle->fd = NULL;
        }
        if ((lfs_handle->syslog_host != NULL)) {
            syslog(LOG_INFO, "lfs_close: ret: %i path: %s", retval,
                   lfs_handle->pathname_munged);
        }

        // ** Also update the LFS adler32 attribute
        if (lfs_handle->do_calc_adler32 == 1) {
            retval = lio_set_attr(lfs_handle->fs, lfs_handle->fs->creds,
                                  lfs_handle->pathname_munged, NULL, "user.gridftp.adler32",
                                  lfs_handle->adler32_human, strlen((char *)lfs_handle->adler32_human));
            if (retval != OP_STATE_SUCCESS) {
                retval = GlobusGFSErrorGeneric("Could not set checksum");
                set_done(lfs_handle, retval);
            }
            if (lfs_handle->expected_checksum != NULL) {
                if (strcmp(lfs_handle->adler32_human, lfs_handle->expected_checksum) != 0) {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                                           "checksum mismatch! calculated=%s expected=%s\n", lfs_handle->adler32_human,
                                           lfs_handle->expected_checksum);
                    log_printf(1, "checksum mismatch! calculated=%s expected=%s\n",
                               lfs_handle->adler32_human, lfs_handle->expected_checksum);
                    retval = GlobusGFSErrorGeneric("Checksum mismatch");
                    set_done(lfs_handle, retval);
                }
            }
        }
    } else {
        if ((retval = close(lfs_handle->fd_posix)) != 0) {
            GenericError(lfs_handle, "Failed to close file in POSIX.", retval);
            lfs_handle->fd_posix = 0;
            retval = GlobusGFSErrorGeneric("Could not close file in POSIX");
            set_done(lfs_handle, retval);
        }
    }
    return retval;
}
void change_and_check(lfs_handle_t * lfs_handle, int backend, int checksum,
                        int gridftp, int buffered, int inflight_count) {
    apr_thread_mutex_lock(lfs_handle->lock);
    lfs_handle->backend_counter += backend;
    lfs_handle->checksum_counter += checksum;
    lfs_handle->gridftp_counter += gridftp;
    lfs_handle->buffered_counter += buffered;
    lfs_handle->inflight_count += inflight_count;
    assert(lfs_handle->backend_counter + lfs_handle->checksum_counter + lfs_handle->gridftp_counter + lfs_handle->buffered_counter >= 0);
    assert((lfs_handle->backend_counter + \
                            lfs_handle->checksum_counter + \
                            lfs_handle->gridftp_counter + \
                            lfs_handle->buffered_counter) == lfs_handle->inflight_count);
    apr_thread_mutex_unlock(lfs_handle->lock);
}

//
// lfs_maybe_flush_buffers - run to see if a long enough contiguous range of
//                           bytes are buffered. If so, they will be sent to
//                           the filesystem
//
// Pops off buffered counter, pushes onto gridftp counter
//
void lfs_maybe_flush_buffers(lfs_handle_t * lfs_handle, int finished, int force_flush, list_t * sorted_buffers,
                             lfs_cluster_t * cluster, interval_skiplist_t * written_intervals,
                             ex_off_t * cluster_weights, int * cluster_order, ex_iovec_t * ex_iovec,
                             iovec_t * iovec, int * n_holding) {
    GlobusGFSName(lfs_maybe_flush_buffers);
    ex_off_t low_water_mark = ((finished == 1) || (force_flush == 1)) ? 0 : lfs_handle->low_water_flush;
    ex_off_t nleft, lo, hi, np;
    lfs_cluster_t * c;
    int i;
    Stack_t * stack;
    Stack_ele_t *ele;
    int n, n_to_process, n_iov, n_ex, nbytes, n_start, n_clusters;
    globus_result_t rc = GLOBUS_SUCCESS;
    lfs_buffer_t * buf;
    lfs_interval_t * interval;
    lfs_interval_t *idroplo, *idrophi;
    interval_skiplist_iter_t it;
    apr_time_t write_timer;
    tbuffer_t tbuf;

    // ** If we make it here we need to flush
    // ** 1st we need to cluster the buffers
    lfs_cluster(sorted_buffers, cluster, &n_clusters);

    // ** Weight them based on the resulting contiguous written space
    lfs_cluster_weight(written_intervals, cluster, cluster_weights, n_clusters);

    // ** Now sort them based on the weights
    lfs_cluster_sort(cluster_order, cluster_weights, n_clusters);

    // ** Figure out where we crossover the low water mark
    nleft = list_key_count(sorted_buffers) - low_water_mark;
    for (i=0; ((i<n_clusters) && (nleft>0)); i++) {
        stack = &(cluster[cluster_order[i]].stack);
        n = stack_size(stack);
        nleft -= n;
    }
    n_to_process = i+1;

    // ** Now we know which clusters to flush.  We'll process them in the natural
    // ** order since it automatically makes the write operations in ascending order
    n_iov = n_ex = 0;
    nbytes = 0;
    for (i=0; i<n_clusters; i++) {
        if (cluster_order[i] > n_to_process) continue;  // ** Don't process this one

        // ** If we made it here the cluster is getting flushed
        c = &(cluster[i]);

        // ** Calculate the checksum for the cluster
        move_to_top(&(c->stack));
        buf = get_ele_data(&(c->stack));
        c->adler32 = buf->adler32;
        move_down(&(c->stack));
        while ((buf = get_ele_data(&(c->stack))) != NULL) {
            c->adler32 = adler32_combine(c->adler32, buf->adler32, buf->nbytes);
            move_down(&(c->stack));
        }

        type_malloc(interval, lfs_interval_t, 1);

        // ** Update the written interval table and accumulate the adler32 chksum
        idroplo = idrophi = NULL;
        lo = c->lo - 1;
        hi = c->lo;
        it = iter_search_interval_skiplist(written_intervals, (skiplist_key_t *)&lo,
                                            (skiplist_key_t *)&hi);
        idroplo = next_interval_skiplist(&it);
        if (idroplo) {
            interval->lo = idroplo->lo;
            interval->hi = c->hi;
            interval->adler32 = adler32_combine(idroplo->adler32, c->adler32, c->len);
        } else {
            interval->lo = c->lo;
            interval->hi = c->hi;
            interval->adler32 = c->adler32;
        }

        lo = c->hi;
        hi = c->hi + 1;
        it = iter_search_interval_skiplist(written_intervals, (skiplist_key_t *)&lo,
                                            (skiplist_key_t *)&hi);
        idrophi = next_interval_skiplist(&it);
        if (idrophi) {
            interval->hi = idrophi->hi;
            interval->adler32 = adler32_combine(interval->adler32, idrophi->adler32,
                                                idrophi->hi - idrophi->lo + 1);
        }

        // ** Remove the surrounding intervals
        if (idroplo) remove_interval_skiplist(written_intervals, &(idroplo->lo),
                                                    &(idroplo->hi), idroplo);
        if (idrophi) remove_interval_skiplist(written_intervals, &(idrophi->lo),
                                                    &(idrophi->hi), idrophi);
        insert_interval_skiplist(written_intervals, &(interval->lo), &(interval->hi),
                                    interval);  // ** This is the new bigger interval

        // ** Prepare the write stack and update the number of buffers left to process
        n = stack_size(&(c->stack));
        nleft -= n;

        // ** Create the write ops
        ex_iovec[n_ex].offset = c->lo;
        ex_iovec[n_ex].len = c->len;
        nbytes += c->len;
        n_ex++;
        move_to_top(&(c->stack));
        n_start = n_iov;
        while ((buf = get_ele_data(&(c->stack))) != NULL) {
            // ** and make the write op
            iovec[n_iov].iov_base = buf->buffer;
            iovec[n_iov].iov_len = buf->nbytes;
            n_iov++;
            move_down(&(c->stack));
        }

        if (lfs_handle->is_lio == 0) { // ** Normal file so it's easier to dump it here
            nleft = c->hi - c->lo + 1;
            STATSD_TIMER_RESET(write_timer);
            while (nleft > 0) {
                np = pwritev(lfs_handle->fd_posix, iovec + n_start, n_iov - n_start, c->lo);
                if (np < 0) {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                                            "Failed writing to posix file! err=%d off=" XOT " len= " XOT "\n", rc, c->lo,
                                            c->len);
                    set_done(lfs_handle, GlobusGFSErrorGeneric(strdup("Failed writing to posix")));
                    break;
                }
                nleft -= np;
            }
            STATSD_TIMER_POST("posix_write_time", write_timer);
            STATSD_COUNT("posix_bytes_written", c->hi - c->lo + 1);
        }
    }

    // ** And dump the data if it's lstore
    if (lfs_handle->is_lio == 1) {
        tbuffer_vec(&tbuf, nbytes, n_iov, iovec);
        STATSD_TIMER_RESET(write_timer);
        int b = lio_write_ex(lfs_handle->fd, n_ex, ex_iovec, &tbuf, 0, NULL);
        STATSD_TIMER_POST("write_time", write_timer);
        STATSD_COUNT("lfs_bytes_written",b);
        if (b != nbytes) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,
                                    "Failed writing to LFS file! err=%d\n", b);
            set_done(lfs_handle, GlobusGFSErrorGeneric(strdup("Failed writing to LStore")));
        }
    }

    // ** Now Cleanup for the next iteration
    for (i=0; i<n_clusters; i++) {
        c = &(cluster[i]);

        if (cluster_order[i] > n_to_process) { // ** Don't process this one
            while ((ele = pop_link(&(c->stack))) !=
                    NULL) {   // ** Dump it back on the stack for the next round
            }
            continue;  // ** Nothing else to do so move on to the next cluster
        }

        // ** If we made it here the cluster got flushed

        // ** Recycle the buffers
        while ((ele = pop_link(&(c->stack))) != NULL) {
            // ** Remove it from the sorted buffer list
            buf = get_stack_ele_data(ele);
            list_remove(sorted_buffers, &(buf->offset), ele);
            (*n_holding)--;
            // ** Put the buffer back on the gridftp read from network queue
            rc = globus_gridftp_server_register_read(lfs_handle->op,
                    (globus_byte_t *)buf->buffer, lfs_handle->buffer_size, lfs_handle_write_op,
                    (void *) ele);
            if (rc != GLOBUS_SUCCESS) {
                rc = GlobusGFSErrorGeneric("globus_gridftp_server_register_read() fail");
                set_done(lfs_handle, rc);
                free(ele);  // ** Just free the stack structure
                change_and_check(lfs_handle, 0, 0, 0, -1, -1);
            } else {
                change_and_check(lfs_handle, 0, 0, 1, -1, 0);
            }
        }
    }
}


