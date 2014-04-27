
#include "gridftp_lfs.h"
#include <syslog.h>
#include <sys/mman.h>
#include <sys/types.h>

globus_result_t lfs_dump_buffer_queued(lfs_handle_t *lfs_handle, 
                                        globus_byte_t *buffer,
                                        globus_size_t nbytes,
                                        globus_off_t offset);

globus_result_t add_by_offset(lfs_queue_item_t ** head, lfs_queue_item_t * curr) {
    GlobusGFSName(add_by_offset);
    lfs_queue_item_t * prev = NULL;
    lfs_queue_item_t * target = (*head);
    curr->next = NULL;
    if (!(*head) || ((*head)->offset > curr->offset)) {
        curr->next = (*head);
        (*head) = curr;
    } else {
        prev = target;
        while (1) {
            if (target->offset > curr->offset) {
                break;
            }
            if (target->next == NULL) {
                // tack this at the end
                prev = target;
                target = NULL;
                break;
            } 
            prev = target;
            target = target->next;
        }
        curr->next = target;
        prev->next = curr;
    }
    globus_off_t testoff = (*head)->offset;
    target = (*head);
    while (target) {
        if (testoff > target->offset) {
            globus_result_t rc = GlobusGFSErrorGeneric("Failed to add to small buffer");
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Can't sort, %i > %i\n", testoff, target->offset);
            return rc;
        }
        testoff = target->offset;
        target = target->next;
    }
    return 0;
}

globus_size_t buffer_length(lfs_queue_item_t * head) {
    lfs_queue_item_t * current_element = head;
    globus_size_t count = 0;
    while (current_element) {
        count += 1;
        current_element = current_element->next;
    }
    return count;
}

globus_size_t lfs_used_buffer_count(globus_l_gfs_lfs_handle_t * lfs_handle) {
    return lfs_handle->small_queue_length;
}

/**
 *  Store the current output to a buffer.
 */
globus_result_t lfs_store_buffer(globus_l_gfs_lfs_handle_t * lfs_handle, globus_byte_t* buffer, globus_off_t offset, globus_size_t nbytes) {
    GlobusGFSName(lfs_store_buffer);
    globus_result_t rc = GLOBUS_SUCCESS;

    int i, cnt = lfs_handle->buffer_count;
    int actual_cnt;
    short wrote_something = 0;
    if (lfs_handle == NULL) {
        rc = GlobusGFSErrorGeneric("Storing buffer for un-allocated transfer");
        return rc;
    }

    unsigned int count = 0;
    lfs_queue_item_t * current_element;
    if (lfs_handle->small_queue_length != buffer_length(lfs_handle->small_queue_head)) {
        rc = GlobusGFSErrorGeneric("Dropped list elements");
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Can't count list element pre (expected: %i, actual: %i)\n",
                                    lfs_handle->small_queue_length, count);
        globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
        return rc;
    }

    // try to find some extra list bits in the free list
    if (lfs_handle->free_head != NULL) {
        current_element =  lfs_handle->free_head;
        lfs_handle->free_head = lfs_handle->free_head->next;
        lfs_handle->free_length -= 1;
    } else {
        current_element = globus_malloc(sizeof(lfs_queue_item_t));
        if (!current_element) {
            rc = GlobusGFSErrorGeneric("Memory allocation error.");
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error.");
            globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
            return rc;
        }
    }

    current_element->buffer = buffer;
    current_element->nbytes = nbytes;
    current_element->offset = offset;
    if (add_by_offset(&lfs_handle->small_queue_head, current_element) != 0) {
        rc = GlobusGFSErrorGeneric("I can't sort");
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Can't sort\n");
        globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
        return rc;
    }

    lfs_handle->small_queue_length += 1;
    if (lfs_handle->small_queue_length != buffer_length(lfs_handle->small_queue_head)) {
        rc = GlobusGFSErrorGeneric("Dropped list elements");
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Can't count list element post (expected: %i, actual: %i)\n",
                                    lfs_handle->small_queue_length, count);
        globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
        return rc;
    }
    //globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Have %i small queue elements\n",lfs_handle->small_queue_length);
    return rc;
}

/**
 * Scan through all the buffers we own, then write out all the consecutive ones to LFS.
 * batch it to 10meg writes
 */
globus_result_t
lfs_dump_buffers(lfs_handle_t *lfs_handle) {

    globus_off_t * offsets = lfs_handle->offsets;
    globus_size_t * nbytes = lfs_handle->nbytes;
    size_t i,j, wrote_something;
    size_t cnt = lfs_handle->buffer_count;
    GlobusGFSName(globus_l_gfs_lfs_dump_buffers);

    globus_result_t rc = GLOBUS_SUCCESS;

    globus_size_t target_amount = lfs_handle->preferred_write_size;
    globus_off_t offset_begin;
    size_t buffer_begin;
    lfs_queue_item_t *head, *curr;
    head = curr = lfs_handle->small_queue_head;
    if (!head) {
        return rc;
    }
    // See how far we can get in a contiguous block. For this, "head" means
    // "the beginning of the contiguous block" and "curr" means the
    // current location in the file
    globus_off_t head_offset, current_offset;
    head_offset = head->offset;
    current_offset = curr->offset;
    globus_size_t current_bytes = 0;
    if (head_offset != lfs_handle->offset) {
        //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Not at beginning of chain (%i != %i)\n", head_offset/lfs_handle->block_size, lfs_handle->offset/lfs_handle->block_size);
        return rc;
    }

    while (curr) {
        if (current_offset != curr->offset) {
            //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Unmatched offsets (%i != %i)\n", current_offset/lfs_handle->block_size, curr->offset/lfs_handle->block_size);
            break;
        }
        current_offset += curr->nbytes;
        current_bytes  += curr->nbytes;
        if (current_bytes < target_amount) {
            curr = curr->next;
            continue;
        }

        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Beginning to write small to big\n");
        // We've got enough bytes to flush out to the background thread
        globus_byte_t * tmp_buffer = globus_malloc(current_bytes*sizeof(globus_byte_t));
        if (!tmp_buffer) {
            rc = GlobusGFSErrorGeneric("Memory allocation error.");
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error.");
            globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
            return rc;
        }
        globus_byte_t * memcpy_ptr = tmp_buffer;
        lfs_queue_item_t * new_head = curr->next;
        while (head && (head != new_head)) {
            //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, 
            //                        "Small head is now %i (%i)\n",
            //                        new_head->offset/lfs_handle->block_size,
            //                        buffer_length(lfs_handle->small_queue_head));
            memcpy_ptr = tmp_buffer + (head->offset - head_offset);
            memcpy(memcpy_ptr, head->buffer, head->nbytes);
            globus_free(head->buffer);
            // Push the head forward towards curr
            head = head->next;
            lfs_handle->small_queue_length -= 1;
            lfs_handle->free_length += 1;
            //globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Have %i small queue elements (%i free) (%i actual) (%i free actual)\n",
            //                            lfs_handle->small_queue_length,
            //                            lfs_handle->free_length,
            //                            buffer_length(lfs_handle->small_queue_head),
            //                            buffer_length(lfs_handle->free_head)
            //                            );
        }
        //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, 
        //                            "Resetting small head offset to %i (%i)\n",
        //                            new_head->offset/lfs_handle->block_size,
        //                            buffer_length(new_head));

        // Reset the different lists
        lfs_handle->free_head = lfs_handle->small_queue_head;
        lfs_handle->small_queue_head = new_head;
        curr->next = NULL;

        globus_off_t old_offset = head_offset;
        if ((rc = lfs_dump_buffer_queued(lfs_handle, tmp_buffer, current_bytes, old_offset)) != GLOBUS_SUCCESS) {
            return rc;
        }
        lfs_handle->offset += current_bytes;
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Offset jumps from %i to %i\n",old_offset, lfs_handle->offset);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Offset blocks jumps from %i to %i\n",old_offset/lfs_handle->block_size, lfs_handle->offset/lfs_handle->block_size);
    }
    return rc;
}

globus_result_t
lfs_dump_buffers_unbatched(lfs_handle_t *lfs_handle) {

    globus_off_t * offsets = lfs_handle->offsets;
    globus_size_t * nbytes = lfs_handle->nbytes;
    size_t i, wrote_something;
    size_t cnt = lfs_handle->buffer_count;
    GlobusGFSName(globus_l_gfs_lfs_dump_buffers);

    globus_result_t rc = GLOBUS_SUCCESS;
    
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Dumping unbatched\n");
    wrote_something=1;
    // Loop through all our buffers; loop again if we write something.
    while (wrote_something == 1) {
        wrote_something=0;
        // For each of our buffers.
        lfs_queue_item_t * head = lfs_handle->small_queue_head;
        lfs_queue_item_t * prev = NULL;
        while (head) {
            if (head->offset == lfs_handle->offset) {
                // keep in mind further down that this function calls
                // globus_free on the input buffer
                if ((rc = lfs_dump_buffer_queued(lfs_handle, head->buffer, head->nbytes, lfs_handle->offset)) != GLOBUS_SUCCESS) {
                    return rc;
                }
                lfs_handle->offset += head->nbytes;
                if (head->nbytes > 0) {
                    wrote_something = 1;
                }
                

                // remove this item from the small queue list
                if (prev) {
                    prev->next = head->next;
                    prev = NULL;
                } else if (head == lfs_handle->small_queue_head) {
                    lfs_handle->small_queue_head == head->next;
                    prev = NULL;
                }

                // add this item to the free list
                lfs_queue_item_t * next = head->next;
                head->next = lfs_handle->free_head;
                lfs_handle->free_head = head;
                
                lfs_handle->small_queue_length -= 1;
                lfs_handle->free_length += 1;
                head = next;
            } else {
                prev = head;
                head = head->next;
            }
        }
    }
    return rc;
}
// enqueue a transfer for the backend to perform
globus_result_t lfs_dump_buffer_queued(lfs_handle_t *lfs_handle, globus_byte_t *buffer, globus_size_t nbytes, globus_off_t offset) {
    GlobusGFSName(lfs_dump_buffer_queued);
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_mutex_lock(lfs_handle->buffer_mutex);
    if ((!lfs_handle->queue_open) && (!lfs_handle->queue_head)) {
        SystemError(lfs_handle, "Trying to write to backing store while writers are closed\n", rc);
        globus_mutex_unlock(lfs_handle->buffer_mutex);
        return -1;
    }
    lfs_queue_item_t * curr = globus_malloc(sizeof(lfs_queue_item_t));
    if (!curr) {
        MemoryError(lfs_handle, "Allocating backing queue\n", rc);
        globus_mutex_unlock(lfs_handle->buffer_mutex);
        return rc;
    }
    curr->buffer = buffer;
    curr->nbytes = nbytes;
    curr->offset = offset;
    curr->next = NULL;
    lfs_queue_item_t * target = lfs_handle->queue_head;
    lfs_queue_item_t * prev = NULL;

    while (lfs_handle->queued_bytes >= lfs_handle->max_queued_bytes) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Stalling out enqueued write\n");
        globus_cond_wait(lfs_handle->dequeued_cond, lfs_handle->buffer_mutex);
    }

    if (add_by_offset(&lfs_handle->queue_head, curr)) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Failed to store element in queue\n");
        globus_cond_broadcast(lfs_handle->queued_cond);
        globus_mutex_unlock(lfs_handle->buffer_mutex);
        return -1;
    }
    lfs_handle->queue_length += 1;
    lfs_handle->queued_bytes += nbytes;
    rc = lfs_handle->background_status;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Enqueueing write: %u Stalled: %u\n",
                                                            lfs_handle->queue_length,
                                                            lfs_handle->starved_ops);
    globus_cond_signal(lfs_handle->queued_cond);
    globus_mutex_unlock(lfs_handle->buffer_mutex);
    return rc;
}

int lfs_dequeue_buffer(lfs_handle_t *lfs_handle, globus_byte_t **buffer, globus_size_t *nbytes, globus_off_t *offset) {
    globus_mutex_lock(lfs_handle->buffer_mutex);
    lfs_handle->starved_ops += 1;
    while (1) {
        if ((!lfs_handle->queue_open) && (!lfs_handle->queue_head)) {
            lfs_handle->starved_ops -= 1;
            globus_cond_signal(lfs_handle->dequeued_cond);
            globus_mutex_unlock(lfs_handle->buffer_mutex);
            return 0;
        } else if (lfs_handle->queue_head) {
            break;
        }
        globus_cond_wait(lfs_handle->queued_cond, lfs_handle->buffer_mutex);
    }
    lfs_handle->starved_ops -= 1;
    lfs_queue_item_t * curr = lfs_handle->queue_head;
    *buffer = curr->buffer;
    *nbytes = curr->nbytes;
    *offset = curr->offset;
    lfs_handle->queue_head = curr->next;
    lfs_handle->queued_bytes -= curr->nbytes;
    lfs_handle->queue_length -= 1;
    globus_free(curr);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Dequeueing write: %u Stalled: %u\n",
                                                    lfs_handle->queue_length,
                                                    lfs_handle->starved_ops);
    globus_cond_signal(lfs_handle->dequeued_cond);
    globus_mutex_unlock(lfs_handle->buffer_mutex);
    return 1;
}
void lfs_throw_queue_error(lfs_handle_t *lfs_handle, globus_result_t rc) {
    globus_mutex_lock(lfs_handle->buffer_mutex);
    lfs_handle->background_status = rc;
    globus_mutex_unlock(lfs_handle->buffer_mutex);
}

void * lfs_queue_handler(void * handle) {
    lfs_handle_t * lfs_handle = (lfs_handle_t *) handle;

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Starting write backend\n");
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_byte_t *buffer;
    globus_size_t nbytes;
    globus_off_t offset;
    while (lfs_dequeue_buffer(lfs_handle, &buffer, &nbytes, &offset)) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Backend dumping buffer at %lu length %u blocks.\n", offset, nbytes/lfs_handle->block_size);
        if ((rc = lfs_dump_buffer_immed(lfs_handle, buffer, nbytes, offset)) != GLOBUS_SUCCESS) {
            lfs_throw_queue_error(lfs_handle, rc);
        }
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Terminating write backend\n");
    return NULL;
}
globus_result_t start_writers(lfs_handle_t *lfs_handle) {
    globus_result_t rc = GLOBUS_SUCCESS;
    GlobusGFSName(start_writers);
    // concurrent writes
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Starting backend threads\n");
    lfs_handle->write_pool = globus_malloc(lfs_handle->concurrent_writes *
                                            sizeof(pthread_t));
    if (!lfs_handle->write_pool) {
        MemoryError(lfs_handle, "Couldn't allocate thread pool\n", rc);
        return rc;
    }
    lfs_handle->queue_head = NULL;
    lfs_handle->starved_ops = 0;
    lfs_handle->blocked_ops = 0;
    lfs_handle->background_status = GLOBUS_SUCCESS;
    lfs_handle->queue_open = 1;
    lfs_handle->blocked_writers = 0;
    int i;
    globus_result_t temp_rc;
    for (i=0; i < lfs_handle->concurrent_writes; ++i) {
        temp_rc = pthread_create(&lfs_handle->write_pool[i], NULL, lfs_queue_handler, (void *) lfs_handle);
        if (temp_rc != GLOBUS_SUCCESS) {
            rc = temp_rc;
        }
    }

    return rc;
}

globus_result_t stop_writers(lfs_handle_t *lfs_handle) {
    globus_result_t rc = GLOBUS_SUCCESS;
    GlobusGFSName(stop_writers);
    globus_mutex_lock(lfs_handle->buffer_mutex);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Stopping backend threads\n");
    lfs_handle->queue_open = 0;
    globus_cond_broadcast(lfs_handle->queued_cond);
    globus_mutex_unlock(lfs_handle->buffer_mutex);
    int i;
    for (i=0; i < lfs_handle->concurrent_writes; ++i) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Stopping backend thread # %i\n", i);
        globus_mutex_lock(lfs_handle->buffer_mutex);
        globus_cond_broadcast(lfs_handle->queued_cond);
        globus_mutex_unlock(lfs_handle->buffer_mutex);
        pthread_join(lfs_handle->write_pool[i], NULL);
    }
    return NULL;
}


// multithreaded
globus_result_t lfs_dump_buffer_immed(lfs_handle_t *lfs_handle, globus_byte_t *buffer, globus_size_t nbytes, globus_off_t offset) {
    globus_result_t rc = GLOBUS_SUCCESS;

    GlobusGFSName(lfs_dump_buffer_immed);
    if (nbytes % lfs_handle->block_size == 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Dumping buffer at %lu length %u blocks.\n", offset, nbytes/lfs_handle->block_size);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Dumping buffer at %lu length %u.\n", offset, nbytes);
    }
    if (lfs_handle->syslog_host != NULL) {
        syslog(LOG_INFO, lfs_handle->syslog_msg, "WRITE", nbytes, offset);
    }
    globus_size_t bytes_written;
    STATSD_TIMER_START(read_timer);
    if (is_lfs_path(lfs_handle, lfs_handle->pathname)) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Dumping buffer at %lu to LFS.\n", offset);
        bytes_written = lfs_write(lfs_handle->pathname_munged, buffer, nbytes, offset, lfs_handle->fd);
        if (bytes_written != nbytes) {
            SystemError(lfs_handle, "write into LFS", rc);
            set_done(lfs_handle, rc);
            globus_free(buffer);
            return rc;
        }
        STATSD_TIMER_END("write_time", read_timer);
        STATSD_COUNT("lfs_bytes_written",bytes_written);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Dumping buffer at %lu to filesystem.\n", offset);
        bytes_written = pwrite(lfs_handle->fd_posix, buffer, nbytes, offset);
        if (bytes_written != nbytes) {
            SystemError(lfs_handle, "write into POSIX", rc);
            set_done(lfs_handle, rc);
            globus_free(buffer);
            return rc;
        }
        STATSD_COUNT("posix_bytes_written", bytes_written);
        STATSD_TIMER_END("posix_write_time", read_timer);
    }


    // Checksum after writing to disk.  This way, if a non-transient corruption occurs
    // during writing to Hadoop, we detect it and hopefully fail the file.

    globus_mutex_lock(lfs_handle->offset_mutex);
    if (lfs_handle->cksm_types) {
        lfs_handle->blocked_ops += 1;
        while (lfs_handle->committed_offset != offset) {
            globus_abstime_t timer;
            timer.tv_sec = 10;
            timer.tv_nsec = 0;
            globus_cond_wait(lfs_handle->offset_cond,
                                  lfs_handle->offset_mutex);
            if (lfs_handle->committed_offset > offset) {
                globus_cond_broadcast(lfs_handle->offset_cond);
                globus_mutex_unlock(lfs_handle->offset_mutex);
                globus_free(buffer);
                set_done(lfs_handle, rc);
                lfs_handle->blocked_ops -= 1;
                SystemError(lfs_handle, "The checksumming got skipped", rc);
                return -1;
            }
        }
        lfs_handle->blocked_ops -= 1;
        lfs_handle->committed_offset += bytes_written;
        lfs_update_checksums(lfs_handle, buffer, bytes_written);
        globus_cond_broadcast(lfs_handle->offset_cond);
    }
    if ((rc = globus_mutex_unlock(lfs_handle->offset_mutex)) != GLOBUS_SUCCESS) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Mutex fail %lu\n", rc);
        SystemError(lfs_handle, "Couldn't unlock mutex", rc);
    }
    globus_free(buffer);
    return rc;
}

/**
 *  Buffer management functions for the read workflow
 */
inline globus_result_t
allocate_buffers(
    lfs_handle_t * lfs_handle,
    globus_size_t          num_buffers)
{
    GlobusGFSName(allocate_buffers);
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_ssize_t new_size = num_buffers-lfs_handle->buffer_count;
    if (new_size > 0) {
        // Re-allocate our buffers
        lfs_handle->buffer = globus_realloc(lfs_handle->buffer,
            num_buffers*lfs_handle->block_size*sizeof(globus_byte_t));
        lfs_handle->used = globus_realloc(lfs_handle->used,
            num_buffers*sizeof(globus_bool_t));
        lfs_handle->offsets = globus_realloc(lfs_handle->offsets,
            num_buffers*sizeof(globus_off_t));
        lfs_handle->nbytes = globus_realloc(lfs_handle->nbytes,
            num_buffers*sizeof(globus_size_t));
        lfs_handle->buffer_pointers = globus_realloc(lfs_handle->buffer_pointers,
            num_buffers*sizeof(globus_byte_t *));
        memset(lfs_handle->used+lfs_handle->buffer_count, 0, sizeof(short)*new_size);
        lfs_handle->buffer_count = num_buffers;

        if (!lfs_handle->buffer || !lfs_handle->offsets
                || !lfs_handle->used || !lfs_handle->nbytes
                || !lfs_handle->buffer_pointers) {
            MemoryError(lfs_handle, "Allocating buffers for read", rc)
            return rc;
        }
    }
    return rc;
}

inline globus_ssize_t
find_buffer(
    lfs_handle_t * lfs_handle,
    globus_byte_t * buffer)
{
    globus_ssize_t result = -1;
    globus_size_t idx;
    for (idx=0; idx<lfs_handle->buffer_count; idx++) {
        if (lfs_handle->buffer+idx*lfs_handle->block_size == buffer) {
            result = idx;
            break;
        }
    }
    return result;
}

inline globus_ssize_t
find_empty_buffer(
    lfs_handle_t * lfs_handle)
{
    globus_ssize_t result = -1;
    globus_size_t idx = 0;
    for (idx=0; idx<lfs_handle->buffer_count; idx++) {
        if (!lfs_handle->used[idx]) {
            result = idx;
            break;
        }
    }
    if (result >= 0) {
        lfs_handle->used[idx] = 1;
    }
    return result;
}

inline void
disgard_buffer(
    lfs_handle_t * lfs_handle,
    globus_ssize_t idx)
{
    if (idx >= 0 && idx < lfs_handle->buffer_count) {
        lfs_handle->used[idx] = 0;
    }
}

