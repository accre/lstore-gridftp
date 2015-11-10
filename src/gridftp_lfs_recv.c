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
#include "adler32_opt.h"

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}


typedef struct {
  Stack_t stack;
  ex_off_t lo;
  ex_off_t hi;
  ex_off_t len;
  uLong adler32;
} lfs_cluster_t;

typedef struct {
  ex_off_t lo;
  ex_off_t hi;
  uLong adler32;
} lfs_interval_t;

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

static globus_result_t lfs_write_finish_transfer(lfs_handle_t *lfs_handle);

// *************************************************************************
//  human_readable_adler32 - Converts the adler32 number into a human readable format
// *************************************************************************

static void human_readable_adler32(char *adler32_human, uLong adler32) {
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
// lfs_cluster_sort - Sort the clusters in descending order.
//    This uses a simple insertion sort.
// *************************************************************************

void lfs_cluster_sort(int *cluster_order, ex_off_t *cluster_weight, int n_clusters)
{
  int i, j;
  ex_off_t weight;

for (i=0; i<n_clusters; i++) {
  log_printf(5, "START cluster=%d weight=" XOT "\n", i, cluster_weight[i]);
}

  cluster_order[0] = 0;
  for (i=1; i<n_clusters; i++) {
     cluster_order[i] = i;
     weight = cluster_weight[i];
     j = i;

     while ((j>0) && (cluster_weight[cluster_order[j-1]] < weight)) {
       cluster_order[j] = cluster_order[j-1];
       j--;
     }

     cluster_order[j] = i;
  }

for (i=0; i<n_clusters; i++) {
j=cluster_order[i];
  log_printf(5, "END sort=%d cluster=%d weight=" XOT "\n", i, j, cluster_weight[j]);
}
}

// *************************************************************************
// lfs_cluster - Cluster the given buffers
// *************************************************************************

void lfs_cluster_weight(interval_skiplist_t *written_intervals, lfs_cluster_t *cluster, ex_off_t *cluster_weight, int n_clusters)
{
  interval_skiplist_iter_t it;
  ex_off_t lo, hi;
  lfs_cluster_t *c;
  ex_off_t *interval, weight;
  int i;

  for (i=0; i<n_clusters; i++) {
     c = &(cluster[i]);
     lo = c->lo - 1;
     hi = c->hi + 1;
     it = iter_search_interval_skiplist(written_intervals, (skiplist_key_t *)&lo, (skiplist_key_t *)&hi);
     weight = c->hi - c->lo + 1;
     log_printf(5, "i=%d lo=" XOT " hi=" XOT " weight=" XOT "\n", i, c->lo, c->hi, weight);
     while ((interval = next_interval_skiplist(&it)) != NULL) {
        weight += interval[1] - interval[0] + 1;
     log_printf(5, "   i=%d ilo=" XOT " ihi=" XOT " weight=" XOT "\n", i, interval[0], interval[1], weight);
     }
     cluster_weight[i] = weight;
  }
}

// *************************************************************************
// lfs_cluster - Cluster the given buffers
// *************************************************************************

void lfs_cluster(list_t *sorted_buffers, lfs_cluster_t *cluster, int *n_clusters)
{
  int n;
  list_iter_t it;
  ex_off_t *off;
  ex_off_t next_off;
  Stack_ele_t *ele;
  lfs_cluster_t *c;
  lfs_buffer_t *buf, *prev_buf;

  n = 0;
  it = list_iter_search(sorted_buffers, NULL, 0);
  if (list_next(&it, (list_key_t **)&off, (list_data_t **)&ele) != 0) {
     *n_clusters = 0;
     return;
  }

  buf = get_stack_ele_data(ele);
  next_off = buf->offset + buf->nbytes;
  prev_buf = buf;
  c = &(cluster[n]);
  c->lo = buf->offset;
  push_link(&(c->stack), ele);
  move_to_bottom(&(c->stack));
  log_printf(5, "START offset=" XOT " next=" XOT "\n", buf->offset, next_off);
  while (list_next(&it, (list_key_t **)&off, (list_data_t **)&ele) == 0) {
     buf = get_stack_ele_data(ele);
     if (next_off != buf->offset) { // ** Got a new cluster
        c->hi = prev_buf->offset + prev_buf->nbytes - 1;
        c->len = c->hi - c->lo + 1;
        n++;
        c = &(cluster[n]);
        c->lo = buf->offset;
        move_to_bottom(&(c->stack));
     }

     next_off = buf->offset + buf->nbytes;
     log_printf(5, "offset=" XOT " next=" XOT " n_cluster=%d\n", buf->offset, next_off, n);
     prev_buf = buf;
     insert_link_below(&(c->stack), ele);
  }

  c->hi = prev_buf->offset + prev_buf->nbytes - 1;
  c->len = c->hi - c->lo + 1;
  n++;

  *n_clusters = n;
}


// *************************************************************************
// lfs_write_thread - Thread task for doing aggregation and dumping to the backend
// *************************************************************************

void *lfs_write_thread(apr_thread_t *th, void *data)
{
  lfs_handle_t *lfs_handle = (lfs_handle_t *)data;
  apr_thread_cond_t *cond = lfs_handle->backend_stack.cond;
  apr_thread_mutex_t *lock = lfs_handle->backend_stack.lock;
  Stack_ele_t *ele;
  lfs_buffer_t *buf;
  apr_time_t write_timer;
  int finished, n_holding, i, n_clusters, *cluster_order, n, n_to_process;
  ex_off_t *cluster_weights;
  int n_iov, n_ex, rc, n_start, eof;
  lfs_interval_t *idroplo, *idrophi;
  lfs_interval_t *interval;
  lfs_interval_t **iptr;
  list_t *sorted_buffers;
  lfs_cluster_t *cluster, *c;
  interval_skiplist_t *written_intervals;
  interval_skiplist_iter_t it;
  ex_off_t nbytes, low_water_mark, lo, hi, nleft, np, last_byte, last;
  ex_iovec_t *ex_iovec;
  iovec_t *iovec;
  tbuffer_t tbuf;
  Stack_t *stack;

  // ** Fire off the initial set of tasks
  stack = new_stack();
  atomic_set(lfs_handle->inflight_count, lfs_handle->n_buffers);
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
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"Failed to dispatch a write. Most likely the transfer is finished\n");
        log_printf(1, "Failed to dispatch a write. i=%d\n", i);
        free(ele);  // ** Just free the stack structure
        atomic_dec(lfs_handle->inflight_count);
     }
  }
  free(stack);

  // ** Make the local clustering structures
  type_malloc(ex_iovec, ex_iovec_t, lfs_handle->n_buffers);
  type_malloc(iovec, iovec_t, lfs_handle->n_buffers);
  type_malloc(cluster_weights, ex_off_t, lfs_handle->n_buffers);
  type_malloc(cluster_order, int, lfs_handle->n_buffers);
  type_malloc(cluster, lfs_cluster_t, lfs_handle->n_buffers);
  for (i=0; i<lfs_handle->n_buffers; i++) {
     init_stack(&(cluster[i].stack));
  }

  written_intervals = create_interval_skiplist(&skiplist_compare_ex_off, NULL, NULL, free);
  n_holding = log2(lfs_handle->n_buffers);
  if (n_holding == 0) n_holding = 10;
  sorted_buffers = create_skiplist_full(n_holding, 0.5, 0, &skiplist_compare_ex_off, NULL, NULL, NULL);
  finished = 0;
  n_holding = 0;
  eof = 0;
  last_byte = 0;

  while (finished == 0) {
     // ** Get the next block to process
     apr_thread_mutex_lock(lock);
     while ((ele = pop_link(lfs_handle->backend_stack.stack)) == NULL) {
log_printf(1, "inflight=%d n_holding=%d ele=%p\n", atomic_get(lfs_handle->inflight_count), n_holding, ele);
        apr_thread_cond_wait(cond, lock);  // ** Nothing to do so wait
        continue;  // ** Try again
     }
log_printf(1, "out of loop: inflight=%d n_holding=%d ele=%p\n", atomic_get(lfs_handle->inflight_count), n_holding, ele);
     apr_thread_mutex_unlock(lock);

     // ** Get the data
     buf = get_stack_ele_data(ele);
     log_printf(1, "processing.  ptr=%p offset=" XOT " nbytes=" XOT " eof=%d\n", buf, buf->offset, buf->nbytes, buf->eof);
     if (buf->nbytes > 0) {
        n_holding++;
log_printf(5, "inserting buf->off=" XOT " n_holding=%d\n", buf->offset, n_holding);
        last = buf->offset + buf->nbytes;
        if (last > last_byte) last_byte = last;
        list_insert(sorted_buffers, &(buf->offset), ele);
     } else {
        log_printf(1, "Empty buffer.  Dropping. inflight=%d\n", atomic_get(lfs_handle->inflight_count));
        free(ele);  // ** Just free the stack structure
        atomic_dec(lfs_handle->inflight_count);
     }
     if (buf->eof == 1) eof = 1;
     if ((atomic_get(lfs_handle->inflight_count) == n_holding) && (eof == 1)) finished = 1;

     // ** See if it's time to flush the buffers
     if ((n_holding < lfs_handle->high_water_flush) && (finished != 1)) continue;

     log_printf(1, "FLUSHING inflight=%d n_holding=%d eof=%d finished=%d\n", atomic_get(lfs_handle->inflight_count), n_holding, eof, finished);

     low_water_mark = (finished == 1) ? 0 : lfs_handle->low_water_flush;

     // ** If we make it here we need to flush
     // ** 1st we need to cluster the buffers
     lfs_cluster(sorted_buffers, cluster, &n_clusters);
     log_printf(1, "n_clusters=%d\n", n_clusters);

     // ** Weight them based on the resulting contiguous written space
     lfs_cluster_weight(written_intervals, cluster, cluster_weights, n_clusters);

     // ** Now sort them based on the weights
     lfs_cluster_sort(cluster_order, cluster_weights, n_clusters);

     // ** Figure out where we crossover the low water mark
     nleft = list_key_count(sorted_buffers) - low_water_mark;
     for (i=0; ((i<n_clusters) && (nleft>0)); i++) {
        stack = &(cluster[cluster_order[i]].stack);
        n = stack_size(stack);
        log_printf(1, "i=%d cluster=%d n=%d\n", i, cluster_order[i], n);
        nleft -= n;
     }
     n_to_process = i+1;

     log_printf(1, "cluster n_to_process=%d\n", n_to_process);

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
            c->adler32 = opt_adler32_combine(c->adler32, buf->adler32, buf->nbytes);
            move_down(&(c->stack));
        }

        type_malloc(interval, lfs_interval_t, 1);

        // ** Update the written interval table and accumulate the adler32 chksum
        idroplo = idrophi = NULL;
        lo = c->lo - 1;
        hi = c->lo;
        it = iter_search_interval_skiplist(written_intervals, (skiplist_key_t *)&lo, (skiplist_key_t *)&hi);
        idroplo = next_interval_skiplist(&it);
        if (idroplo) {
           interval->lo = idroplo->lo;
           interval->hi = c->hi;
           interval->adler32 = opt_adler32_combine(idroplo->adler32, c->adler32, c->len);
        } else {
           interval->lo = c->lo;
           interval->hi = c->hi;
           interval->adler32 = c->adler32;
        }

        lo = c->hi;
        hi = c->hi + 1;
        it = iter_search_interval_skiplist(written_intervals, (skiplist_key_t *)&lo, (skiplist_key_t *)&hi);
        idrophi = next_interval_skiplist(&it);
        if (idrophi) {
           interval->hi = idrophi->hi;
           interval->adler32 = opt_adler32_combine(interval->adler32, idrophi->adler32, idrophi->hi - idrophi->lo + 1);
        }

        // ** Remove the surrounding intervals
        if (idroplo) remove_interval_skiplist(written_intervals, &(idroplo->lo), &(idroplo->hi), idroplo);
        if (idrophi) remove_interval_skiplist(written_intervals, &(idrophi->lo), &(idrophi->hi), idrophi);
        insert_interval_skiplist(written_intervals, &(interval->lo), &(interval->hi), interval);  // ** This is the new bigger interval

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
                 globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"Failed writing to posix file! err=%d off=" XOT " len= " XOT "\n", rc, c->lo, c->len);
                 lfs_handle->done_status = GLOBUS_FAILURE;
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
        rc = lio_write_ex(lfs_handle->fd, n_ex, ex_iovec, &tbuf, 0, NULL);
        STATSD_TIMER_POST("write_time", write_timer);
        STATSD_COUNT("lfs_bytes_written",rc);

log_printf(5, "lio_write_ex=%d\n", rc);
//rc = 1;
        if (rc != nbytes) {
           globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"Failed writing to LFS file! err=%d\n", rc);
           lfs_handle->done_status = GLOBUS_FAILURE;
        }
     }

     // ** Now Cleanup for the next iteration
     for (i=0; i<n_clusters; i++) {
        c = &(cluster[i]);

        if (cluster_order[i] > n_to_process) { // ** Don't process this one
           while ((ele = pop_link(&(c->stack))) != NULL) {   // ** Dump it back on the stack for the next round
           }
           continue;  // ** Nothing else to do so move on to the next cluster
        }

        // ** If we made it here the cluster got flushed

        // ** Recycle the buffers
        while ((ele = pop_link(&(c->stack))) != NULL) {
           // ** Remove it from the sorted buffer list
           buf = get_stack_ele_data(ele);
           list_remove(sorted_buffers, &(buf->offset), ele);
           n_holding--;

log_printf(1, "removing offset=" XOT " nbytes=" XOT "\n", buf->offset, buf->nbytes);

           // ** Put the buffer back on the gridftp read from network queue
           rc = globus_gridftp_server_register_read(lfs_handle->op,
                  (globus_byte_t *)buf->buffer, lfs_handle->buffer_size, lfs_handle_write_op,
                  (void *) ele);
           if (rc != GLOBUS_SUCCESS) {
              globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"Failed to dispatch a write. Most likely the transfer is finished\n");
              log_printf(1, "Failed to dispatch a write. inflight=%d\n", atomic_get(lfs_handle->inflight_count));
              free(ele);  // ** Just free the stack structure
              atomic_dec(lfs_handle->inflight_count);
           }
        }
     }

     if (atomic_get(lfs_handle->inflight_count) > 0) finished = 0;
log_printf(1, "finished=%d inflight=%d n_holding=%d eof=%d sorted_size=%d\n", finished, atomic_get(lfs_handle->inflight_count), n_holding, eof, list_key_count(sorted_buffers));
  }

  // ** Cleanup
  // ** Store the global adler32 in the handle
  rc = interval_skiplist_count(written_intervals);
  if (rc != 1) {
     globus_gfs_log_message(GLOBUS_GFS_LOG_ERR,"ERROR: Bad checksum!  Multiple intervals! n=%d\n", rc);
     lfs_handle->adler32_human[0] = 0;
  } else {
     lo = 0; hi = 1;
     it = iter_search_interval_skiplist(written_intervals, (skiplist_key_t *)&lo, (skiplist_key_t *)&hi);
     interval = next_interval_skiplist(&it);
     human_readable_adler32(lfs_handle->adler32_human, interval->adler32);
  }

  // ** Destroy all the work arrays
  free(ex_iovec);
  free(iovec);
  free(cluster_weights);
  free(cluster_order);
  free(cluster);
log_printf(1, "n_intervals=%d done_status=%d\n", interval_skiplist_count(written_intervals), lfs_handle->done_status);
  if (rc > 1) {
     type_malloc(iptr, lfs_interval_t *, interval_skiplist_count(written_intervals));
     it = iter_search_interval_skiplist(written_intervals, (skiplist_key_t *)NULL, (skiplist_key_t *)NULL);
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
     if (rc == 1) free(interval);
  }

  list_destroy(sorted_buffers);

  // ** Truncate to the proper size
  gop_sync_exec(gop_lio_truncate(lfs_handle->fd, last_byte));

  // ** Clean up
  rc = lfs_write_finish_transfer(lfs_handle);
log_printf(1, "rc=%d last_byte=" XOT " done_status=%d GLOBUS_SUCCESS=%d adler32=%s\n", rc, last_byte, lfs_handle->done_status, GLOBUS_SUCCESS, lfs_handle->adler32_human);
  globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,"adler32=%s\n", lfs_handle->adler32_human);
  globus_gridftp_server_finished_transfer(lfs_handle->op, rc);

  return(NULL);
}


// *************************************************************************
// lfs_cksum_thread - Thread task for doing adler32 calculations on incoming data blocks
// *************************************************************************

void *lfs_cksum_thread(apr_thread_t *th, void *data)
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
        buf->adler32 = opt_adler32(0L, Z_NULL, 0);
        buf->adler32 = opt_adler32(buf->adler32, (const Bytef *)buf->buffer, buf->nbytes);
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

// *************************************************************************
//   lfs_initialize_writers - Sets up all the LFS bits for writing to a file
// *************************************************************************

void lfs_initialize_writers(lfs_handle_t *lfs_handle)
{
   int i;

   // ** Determine the number of buffers and low high water marks
   lfs_handle->n_buffers = lfs_handle->total_buffer_size / lfs_handle->buffer_size;
   if (lfs_handle->n_buffers == 0) lfs_handle->n_buffers = 1;
   lfs_handle->low_water_flush = lfs_handle->n_buffers * lfs_handle->low_water_fraction;
   if (lfs_handle->low_water_flush == 0) lfs_handle->low_water_flush = 1;
   lfs_handle->high_water_flush = lfs_handle->n_buffers * lfs_handle->high_water_fraction;
   if (lfs_handle->high_water_flush == 0) lfs_handle->high_water_flush = 1;


   // **  Initialize the workere stacks
   lfs_queue_init(&(lfs_handle->cksum_stack), lfs_handle->mpool);
   lfs_queue_init(&(lfs_handle->backend_stack), lfs_handle->mpool);

   // ** Make the buffers.  The write thread submits the initial set of tasks
   type_malloc(lfs_handle->data_buffer, char, lfs_handle->buffer_size*lfs_handle->n_buffers);
   type_malloc_clear(lfs_handle->buffers, lfs_buffer_t, lfs_handle->n_buffers);

   // ** Launch the worker threads
   type_malloc_clear(lfs_handle->cksum_thread, apr_thread_t *, lfs_handle->n_cksum_threads);
   thread_create_assert(&(lfs_handle->backend_thread), NULL, lfs_write_thread, (void *)lfs_handle, lfs_handle->mpool);
   for (i=0; i<lfs_handle->n_cksum_threads; i++) {
      thread_create_assert(&(lfs_handle->cksum_thread[i]), NULL, lfs_cksum_thread, (void *)lfs_handle, lfs_handle->mpool);
   }
}

/*************************************************************************
 *  lfs_gridftp_finish_transfer
 *  --------------
 *  Close the LFS file and updates the appropriate attributes
 *************************************************************************/
static globus_result_t
lfs_write_finish_transfer(lfs_handle_t *lfs_handle) {
    STATSD_COUNT("lfs_gridftp_finish_transfer",1);
    apr_status_t value;
    int n_cksum, i;
    lfs_queue_t *q;
    Stack_t *stack;
    Stack_ele_t *ele;
    globus_result_t retval;
    GlobusGFSName(close_and_clean);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Trying to close file in LFS; zero outstanding blocks.\n");

    // ** Shutdown the cksum threads
    stack = new_stack();
    n_cksum = lfs_handle->n_cksum_threads;
    q = &(lfs_handle->cksum_stack);
    apr_thread_mutex_lock(q->lock);
    for (i=0; i<n_cksum; i++) {
       push(stack, NULL); ele = pop_link(stack);  // ** Create the dummy stack element to dump
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

    lfs_queue_teardown(&(lfs_handle->cksum_stack));
    lfs_queue_teardown(&(lfs_handle->backend_stack));

    // ** Now we can safely close everything
    if (lfs_handle->is_lio) {
       retval = gop_sync_exec(gop_lio_close_object(lfs_handle->fd));
       retval = (OP_STATE_SUCCESS == retval) ? 0 : EIO;
        if (retval != 0) {
            STATSD_COUNT("lfs_write_close_failure", 1);
            GenericError(lfs_handle, "Failed to close file in LFS.", retval);
            lfs_handle->fd = NULL;
            lfs_handle->done_status = GLOBUS_FAILURE;
        }
        if ((lfs_handle->syslog_host != NULL)) {
            syslog(LOG_INFO, "lfs_close: ret: %i path: %s", retval, lfs_handle->pathname_munged);
        }

        // ** Also update the LFS adler32 attribute
        if (lfs_handle->do_calc_adler32 == 1) {
           retval = lio_set_attr(lfs_handle->fs, lfs_handle->fs->creds, lfs_handle->pathname_munged, NULL, "user.gridftp.adler32", lfs_handle->adler32_human, strlen((char *)lfs_handle->adler32_human));
           if (retval != OP_STATE_SUCCESS) lfs_handle->done_status = GLOBUS_FAILURE;
           if (lfs_handle->expected_checksum != NULL) {
               if (strcmp(lfs_handle->adler32_human, lfs_handle->expected_checksum) != 0) {
                  globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "checksum mismatch! calculated=%s expected=%s\n", lfs_handle->adler32_human, lfs_handle->expected_checksum);
                  log_printf(1, "checksum mismatch! calculated=%s expected=%s\n", lfs_handle->adler32_human, lfs_handle->expected_checksum);
                  lfs_handle->done_status = GLOBUS_FAILURE;
               }
           }
        }
    } else {
        if ((retval = close(lfs_handle->fd_posix)) != 0) {
            GenericError(lfs_handle, "Failed to close file in POSIX.", retval);
            lfs_handle->fd_posix = 0;
            lfs_handle->done_status = GLOBUS_FAILURE;
        }
    }

    free(lfs_handle->pathname_munged);
    free(lfs_handle->data_buffer);
    free(lfs_handle->buffers);
    apr_pool_destroy(lfs_handle->mpool);

    return lfs_handle->done_status;
}

/*************************************************************************
 * prepare_handle
 * --------------
 * Do all the prep work for preparing an lfs_handle to be opened
 *************************************************************************/
globus_result_t prepare_handle(lfs_handle_t *lfs_handle) {
    STATSD_COUNT("prepare_handle",1);
    GlobusGFSName(prepare_handle);
    globus_result_t rc;
    globus_size_t block_size;

    const char *path = lfs_handle->pathname;

    if (lfs_handle->is_lio) {
        ADVANCE_SLASHES(path);
        if (strncmp(path, lfs_handle->mount_point, lfs_handle->mount_point_len) == 0) {
            path += lfs_handle->mount_point_len;
        }
        ADVANCE_SLASHES(path);
        lfs_handle->is_lio = 1;
    }

    lfs_handle->pathname_munged = (char*)globus_malloc(strlen(path)+1);
    if (!lfs_handle->pathname_munged) {MemoryError(lfs_handle, "Unable to make a copy of the path name.", rc); return rc;}
    strcpy(lfs_handle->pathname_munged, path);

    lfs_handle->expected_checksum = NULL;

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "We are going to open file %s.\n", lfs_handle->pathname);
    lfs_handle->done = GLOBUS_FALSE;
    lfs_handle->done_status = GLOBUS_SUCCESS;

    globus_gridftp_server_get_block_size(lfs_handle->op, &block_size);
    lfs_handle->buffer_size = block_size;

    return GLOBUS_SUCCESS;
}


/*************************************************************************
 *  lfs_recv
 *  ---------
 *  This interface function is called when the client requests that a
 *  file be transfered to the server.
 *
 ************************************************************************/
void
lfs_recv(
        globus_gfs_operation_t              op,
        globus_gfs_transfer_info_t *        transfer_info,
        void *                              user_arg)
{
    lfs_handle_t *        lfs_handle;
    globus_result_t       rc = GLOBUS_SUCCESS;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Receiving a file: %s\n", transfer_info->pathname);
    GlobusGFSName(lfs_recv);


    lfs_handle = (lfs_handle_t *) user_arg;
    lfs_handle->op = op;
    lfs_handle->done_status = GLOBUS_SUCCESS;

    char * PathName=transfer_info->pathname;
    lfs_handle->pathname = PathName;
    lfs_handle->is_lio = is_lfs_path(lfs_handle, PathName);
    if (lfs_handle->is_lio) {
        lfs_handle->pathname_munged = PathName;
        while (lfs_handle->pathname_munged[0] == '/' && lfs_handle->pathname_munged[1] == '/')
        {
            lfs_handle->pathname_munged++;
        }
        if (strncmp(lfs_handle->pathname_munged, lfs_handle->mount_point, lfs_handle->mount_point_len)==0) {
            lfs_handle->pathname_munged += lfs_handle->mount_point_len;
        }
        while (lfs_handle->pathname_munged[0] == '/' && lfs_handle->pathname_munged[1] == '/')
        {
            lfs_handle->pathname_munged++;
        }
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Munging path. Input: %s Mount: %s Munged: %s\n", transfer_info->pathname, lfs_handle->mount_point, lfs_handle->pathname_munged);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Path not in LFS, opening regularly: %s\n", transfer_info->pathname);
    }

    if ((rc = prepare_handle(lfs_handle)) != GLOBUS_SUCCESS) goto cleanup;

    if (transfer_info->expected_checksum) {
        lfs_handle->expected_checksum =
            globus_libc_strdup(transfer_info->expected_checksum);
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Open file %s.\n",
            lfs_handle->pathname);
    int retval;
    if (lfs_handle->is_lio) {
        lfs_handle->fd = NULL;
        retval = gop_sync_exec(gop_lio_open_object(lfs_handle->fs, lfs_handle->fs->creds, lfs_handle->pathname_munged, lio_fopen_flags("w"), NULL, &(lfs_handle->fd), 60));
        if (retval != OP_STATE_SUCCESS) {
           globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "ERROR opening the file!\n");
           log_printf(1, "ERROR opening the file!\n");
           rc = GLOBUS_FAILURE;
           goto cleanup;
        }

        retval = 0;
        if (lfs_handle->fd == NULL) {
           retval = lio_exists(lfs_handle->fs, lfs_handle->fs->creds, lfs_handle->pathname_munged);

           if (retval & OS_OBJECT_DIR) {
               retval = EISDIR;
               rc = GLOBUS_FAILURE;
               GenericError(lfs_handle, "Destination path is a directory; cannot overwrite.", retval);
               goto cleanup;
           }
        }

        if (lfs_handle->syslog_host != NULL) {
            syslog(LOG_INFO, "lfs_open: ret: %i path: %s", retval, lfs_handle->pathname_munged);
        }

        if (transfer_info->alloc_size > 0) {
            // hopefully this is the size we want to have the file be later
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Extending to %i bytes via client request\n", transfer_info->alloc_size);
            gop_sync_exec(gop_lio_truncate(lfs_handle->fd, -transfer_info->alloc_size));
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, " ... complete\n", transfer_info->alloc_size);
        } else if (lfs_handle->default_size > 0) {
            log_printf(5, "Truncated to default size=" XOT "\n", lfs_handle->default_size);
            gop_sync_exec(gop_lio_truncate(lfs_handle->fd, -lfs_handle->default_size));
        }
    } else {
        retval = open(PathName,  O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );
        if (retval > 0) {
            lfs_handle->fd_posix = retval;
        } else {
            SystemError(lfs_handle, "opening file; POSIX error", rc);
            rc = GLOBUS_FAILURE;
            goto cleanup;
        }
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
            "Successfully opened file %s for user %s.\n", lfs_handle->pathname,
            lfs_handle->username);

    globus_gridftp_server_begin_transfer(lfs_handle->op, 0, lfs_handle);
    lfs_initialize_writers(lfs_handle);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Beginning to read file.\n");

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        lfs_handle->done_status = rc;
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Aborted read before transfer began\n");
        globus_gridftp_server_finished_transfer(op, lfs_handle->done_status);
    }
}

// Allow injection of garbage errors, allowing us to test error-handling
//#define FAKE_ERROR
#ifdef FAKE_ERROR
int block_count = 0;
#endif

/*************************************************************************
 * lfs_handle_write_op
 * --------------------
 * Callback for handling storage operations.
 *************************************************************************/
static
void
lfs_handle_write_op(
        globus_gfs_operation_t              op,
        globus_result_t                     result,
        globus_byte_t *                     buffer,
        globus_size_t                       nbytes,
        globus_off_t                        offset,
        globus_bool_t                       eof,
        void *                              user_arg)
{
    GlobusGFSName(lfs_handle_write_op);

    Stack_ele_t *ele = (Stack_ele_t *)user_arg;
    lfs_buffer_t *buf = (lfs_buffer_t *)get_stack_ele_data(ele);
    lfs_handle_t *lfs_handle = buf->lfs_handle;

    // ** Update the buffer
    buf->offset = offset;
    buf->nbytes = nbytes;
    buf->eof = eof;

    log_printf(5, "offset=" XOT " nbytes=" XOT " eof=%d\n", buf->offset, buf->nbytes, eof);

    globus_gridftp_server_update_bytes_written(op, offset, nbytes);

    apr_thread_mutex_lock(lfs_handle->cksum_stack.lock);
    push_link(lfs_handle->cksum_stack.stack, ele);
    apr_thread_cond_signal(lfs_handle->cksum_stack.cond);
    apr_thread_mutex_unlock(lfs_handle->cksum_stack.lock);
}


