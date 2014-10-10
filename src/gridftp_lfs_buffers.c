
#include "gridftp_lfs.h"
#include <syslog.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdlib.h>

#define FOREACH_LIST(type, head, var) for (type * var = head; var != NULL; var = var->next)

// fix some missing #defines
#ifndef MADV_HUGEPAGE
# define MADV_HUGEPAGE     14
#endif
#ifndef MADV_DONTDUMP
# define MADV_DONTDUMP  16
#endif

// must NOT be within a lock
void lfs_log_buffer_status(lfs_handle_t * lfs_handle) {
    unsigned long blocks_total, blocks_free, blocks_filling, blocks_ready, blocks_pending, blocks_writing;
    blocks_total = blocks_free = blocks_filling =  blocks_ready = blocks_pending = blocks_writing = 0;
    globus_mutex_lock(lfs_handle->buffer_mutex);
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        for (globus_size_t i = 0; i < (buffer_iter->total_buffer_size/buffer_iter->block_size); ++i) {
            ++blocks_total;
            switch (buffer_iter->used[i]) {
                case LFS_BUFFER_FREE:
                    ++blocks_free;
                    break;
                case LFS_BUFFER_FILLING:
                    ++blocks_filling;
                    break;
                case LFS_BUFFER_READY:
                    ++blocks_ready;
                    break;
                case LFS_BUFFER_PENDING_WRITE:
                    ++blocks_pending;
                    break;
                case LFS_BUFFER_WRITING:
                    ++blocks_writing;
                    break;
            }
        }
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                "Buffers: total: %lu free: %lu filling: %lu ready: %lu pending: %lu writing %lu\n",
                blocks_total, blocks_free, blocks_filling, blocks_ready, blocks_pending, blocks_writing);
    globus_mutex_unlock(lfs_handle->buffer_mutex);
}

void lfs_reap_buffers(lfs_handle_t * lfs_handle) {
    lfs_buffer_t * prev = NULL;
    unsigned long big_buffer_count = 0;
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        big_buffer_count += 1;
    }
    if (big_buffer_count <= lfs_handle->write_size_buffers) {
        return;
    }
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        int buffer_free = 1;
        for (globus_size_t i = 0; i < (buffer_iter->total_buffer_size/buffer_iter->block_size); ++i) {
            if (buffer_iter->used[i] != LFS_BUFFER_FREE) {
                buffer_free = 0;
                break;
            }
        }
        if (buffer_free == 0) {
            prev = buffer_iter;
            continue;
        }
        globus_free(buffer_iter->offsets);
        globus_free(buffer_iter->nbytes);
        globus_free(buffer_iter->used);
        free(buffer_iter->buffer);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Freeing buffer\n");
        if (buffer_iter == lfs_handle->buffer_head) {
            // move the head past us
            lfs_handle->buffer_head = buffer_iter->next;
            globus_free(buffer_iter);
            buffer_iter = lfs_handle->buffer_head;
            if (buffer_iter == NULL) {
                break;
            }
        } else {
            // find the previous guy and jump past us
            prev->next = buffer_iter->next;
            // but rewind the iterator so the next loop goes to the right place
            globus_free(buffer_iter);
            buffer_iter = prev;
        }
    }
}

globus_result_t lfs_allocate_new_buffer(lfs_handle_t * lfs_handle) {
    GlobusGFSName(lfs_allocate_new_buffer);
    lfs_log_buffer_status(lfs_handle);
    globus_result_t rc = GLOBUS_SUCCESS;
    lfs_buffer_t * buffer_info = globus_malloc(sizeof(lfs_buffer_t));
    if (!buffer_info) { goto alloc_fail1; }
    unsigned int items = lfs_handle->preferred_write_size / lfs_handle->block_size;
    buffer_info->total_buffer_size = items * lfs_handle->block_size;
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Buffer will have %u blocks containing %lu total bytes\n", items, buffer_info->total_buffer_size);
    buffer_info->block_size = lfs_handle->block_size;
    buffer_info->offsets = globus_malloc(sizeof(globus_off_t) * items);
    if (!buffer_info->offsets) { goto alloc_fail2; }
    buffer_info->nbytes = globus_malloc(sizeof(globus_size_t) * items);
    if (!buffer_info->nbytes) { goto alloc_fail3; }
    int retval = posix_memalign((void **)&buffer_info->buffer, 2 * 1024 * 1024, buffer_info->total_buffer_size);
    // try to do something smart with the big buffers
    if (madvise(buffer_info->buffer, buffer_info->total_buffer_size, MADV_HUGEPAGE | MADV_DONTDUMP | MADV_RANDOM) == EINVAL) {
        if (madvise(buffer_info->buffer, buffer_info->total_buffer_size, MADV_HUGEPAGE | MADV_RANDOM) == EINVAL) {
            madvise(buffer_info->buffer, buffer_info->total_buffer_size, MADV_RANDOM);
        }
    }
    if (retval != 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Failed to get an aligned page %s\n", strerror(retval));
        buffer_info->buffer = globus_malloc(buffer_info->total_buffer_size);
    }
    if (!buffer_info->buffer) { goto alloc_fail4; }
    buffer_info->used = globus_malloc(sizeof(char) * items);
    if (!buffer_info->used) { goto alloc_fail5; }
    memset(buffer_info->used, LFS_BUFFER_FREE, items);
    globus_mutex_lock(lfs_handle->buffer_mutex);
    buffer_info->next = lfs_handle->buffer_head;
    lfs_handle->buffer_head = buffer_info;
    globus_mutex_unlock(lfs_handle->buffer_mutex);
    return rc;
alloc_fail5:
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error5\n.");
    free(buffer_info->buffer);
alloc_fail4:
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error4\n.");
    globus_free(buffer_info->nbytes);
alloc_fail3:
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error3\n.");
    globus_free(buffer_info->offsets);
alloc_fail2:
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error2\n.");
    globus_free(buffer_info);
alloc_fail1:
    rc = GlobusGFSErrorGeneric("Memory allocation error.");
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error1\n.");
    globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
    return rc;
}

globus_byte_t * lfs_get_free_buffer(lfs_handle_t *lfs_handle, globus_size_t nbytes) {
    globus_mutex_lock(lfs_handle->buffer_mutex);
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        if (nbytes > buffer_iter->block_size) {
            continue;
        }
        for (globus_size_t i = 0; i < (buffer_iter->total_buffer_size/buffer_iter->block_size); ++i) {
            if (buffer_iter->used[i] == 0) {
                buffer_iter->used[i] = LFS_BUFFER_FILLING;
                globus_mutex_unlock(lfs_handle->buffer_mutex);
                globus_byte_t * retval = buffer_iter->buffer + buffer_iter->block_size * i;
                //globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Allocating buffer %lu distance away from %lu: %lu\n.", buffer_iter->block_size * i, buffer_iter->buffer, retval);
                return retval;
            }
        }
    }
    globus_mutex_unlock(lfs_handle->buffer_mutex);
    // we need a new buffer block
    if (lfs_allocate_new_buffer(lfs_handle) == GLOBUS_SUCCESS) {
        return lfs_get_free_buffer(lfs_handle, nbytes);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Tried to allocate buffer and then failed\n.");
        return NULL;
    }
}
// MUST be called with buffer_mutex already locked
globus_size_t count_blocks(lfs_handle_t * lfs_handle, unsigned char state) {
    globus_size_t buffers_used = 0;
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        for (globus_size_t i = 0; i < (buffer_iter->total_buffer_size/buffer_iter->block_size); ++i) {
            if (buffer_iter->used[i] == state) {
                ++buffers_used;
            }
        }
    }
    return buffers_used;
}
// MUST be called with buffer_mutex already locked
globus_size_t count_total_blocks(lfs_handle_t * lfs_handle, unsigned char state) {
    globus_size_t buffers_used = 0;
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        buffers_used += buffer_iter->total_buffer_size/buffer_iter->block_size;
    }
    return buffers_used;
}


// MUST be called with buffer_mutex already locked
globus_size_t count_bytes(lfs_handle_t * lfs_handle, unsigned char state) {
    globus_size_t bytes_ready = 0;
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        for (globus_size_t i = 0; i < (buffer_iter->total_buffer_size/buffer_iter->block_size); ++i) {
            if (buffer_iter->used[i] == state) {
                bytes_ready += buffer_iter->block_size;
            }
        }
    }
    return bytes_ready;
}
// MUST be called with buffer_mutex already locked
globus_result_t lfs_dump_buffers(lfs_handle_t *lfs_handle, int dump_partial) {
    globus_size_t bytes_ready = count_bytes(lfs_handle, LFS_BUFFER_READY);
    globus_size_t bytes_pending = 0;
    int notify_writers = 0;
    if ((bytes_ready >= lfs_handle->preferred_write_size) || (bytes_ready > 0 && dump_partial)) {
        FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
            for (globus_size_t i = 0; i < (buffer_iter->total_buffer_size/buffer_iter->block_size); ++i) {
                if (buffer_iter->used[i] == LFS_BUFFER_READY) {
                    buffer_iter->used[i] = LFS_BUFFER_PENDING_WRITE;
                    bytes_pending += buffer_iter->nbytes[i];
                    notify_writers = 1;
                }
                if (bytes_pending >= lfs_handle->preferred_write_size) {
                    break;
                }
            }
            if (bytes_pending >= lfs_handle->preferred_write_size) {
                break;
            }
        }                   
    }
    if (notify_writers) {
        globus_cond_signal(lfs_handle->queued_cond);
    }
    return GLOBUS_SUCCESS;
}
// MUST lock buffer_mutex
globus_result_t lfs_mark_buffer_ready(lfs_handle_t * lfs_handle, globus_byte_t* buffer, globus_off_t offset, globus_size_t nbytes) {
    GlobusGFSName(lfs_mark_buffer_ready);
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        if ( (buffer >= buffer_iter->buffer) && (buffer < (buffer_iter->buffer + buffer_iter->total_buffer_size)) ) {
            unsigned int index = (buffer - buffer_iter->buffer)/buffer_iter->block_size;
            buffer_iter->used[index] = LFS_BUFFER_READY;
            buffer_iter->nbytes[index] = nbytes;
            buffer_iter->offsets[index] = offset;
            globus_mutex_unlock(lfs_handle->buffer_mutex);
            return GLOBUS_SUCCESS;
        }
    }
    globus_result_t rc = GlobusGFSErrorGeneric("Tried to mark a nonexistent buffer ready");
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Tried to mark a nonexistent buffer ready\n");
    return rc;
}

// On the writers backend, see if there's a good block to write
int lfs_dequeue_buffer(lfs_handle_t *lfs_handle, ex_iovec_t **iovec_file, tbuffer_t * buffer, unsigned char *** used_array) {
    GlobusGFSName(lfs_dequeue_buffer);
    globus_mutex_lock(lfs_handle->buffer_mutex);
    lfs_handle->starved_ops += 1;
    globus_size_t bytes_ready;
    while (1) {
        bytes_ready = count_bytes(lfs_handle, LFS_BUFFER_PENDING_WRITE);
        if (bytes_ready && (!lfs_handle->queue_open)) {
            // someone told us to exit
            break;
        } else if ((!lfs_handle->queue_open) && (bytes_ready == 0)) {
            lfs_handle->starved_ops -= 1;
            globus_cond_broadcast(lfs_handle->queued_cond);
            globus_mutex_unlock(lfs_handle->buffer_mutex);
            return 0;
        } else if (bytes_ready >= lfs_handle->preferred_write_size) {
            break;
        }
        globus_cond_wait(lfs_handle->queued_cond, lfs_handle->buffer_mutex);
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Backend dumping buffer of %u bytes. (preferred %u)\n", bytes_ready, lfs_handle->preferred_write_size);
    lfs_handle->starved_ops -= 1;
    unsigned int blocks_ready = 0;
    bytes_ready = 0;
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        for (globus_size_t i = 0; i < (buffer_iter->total_buffer_size/buffer_iter->block_size); ++i) {
            if (buffer_iter->used[i] == LFS_BUFFER_PENDING_WRITE) {
                ++blocks_ready;
                bytes_ready += buffer_iter->nbytes[i];
            }
            if (bytes_ready >= lfs_handle->preferred_write_size) {
                break;
            }
        }
        if (bytes_ready >= lfs_handle->preferred_write_size) {
            break;
        }
    }
    *iovec_file = globus_malloc(sizeof(ex_iovec_t) * blocks_ready);
    iovec_t *iovec_mem = globus_malloc(sizeof(iovec_t) * blocks_ready);
    *used_array = globus_malloc(sizeof(char *) * blocks_ready);
    if (!(*iovec_file) || !iovec_mem || !(*used_array)) {
        globus_result_t rc = GlobusGFSErrorGeneric("Memory allocation error.");
        lfs_handle->background_status = rc;
        globus_mutex_unlock(lfs_handle->buffer_mutex);
        return 0;
    }
    memset(*iovec_file, 0, sizeof(ex_iovec_t) * blocks_ready);
    memset(iovec_mem, 0, sizeof(iovec_t) * blocks_ready);
    unsigned int block_iter = 0;
    unsigned int bytes_writing = 0;
    FOREACH_LIST(lfs_buffer_t, lfs_handle->buffer_head, buffer_iter) {
        for (globus_size_t i = 0; i < (buffer_iter->total_buffer_size/buffer_iter->block_size); ++i) {
            if (buffer_iter->used[i] == LFS_BUFFER_PENDING_WRITE) {
                buffer_iter->used[i] = LFS_BUFFER_WRITING;
                bytes_writing += buffer_iter->nbytes[i];
                ((*iovec_file) + block_iter)->offset = buffer_iter->offsets[i];
                ((*iovec_file) + block_iter)->len = buffer_iter->nbytes[i];
                if ((*iovec_file)[block_iter].len == 0) { 
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Zero-length block? You idiot!\n");
                }
                iovec_mem[block_iter].iov_base = (void *)( buffer_iter->buffer + i * buffer_iter->block_size );
                iovec_mem[block_iter].iov_len = buffer_iter->nbytes[i];
                (*used_array)[block_iter] = &(buffer_iter->used[i]);
                ++block_iter;
            }
            if (bytes_writing >= lfs_handle->preferred_write_size) {
                break;
            }
        }
        if (bytes_writing >= lfs_handle->preferred_write_size) {
            break;
        }
    }
    tbuffer_vec(buffer, bytes_ready, blocks_ready, iovec_mem);
    if (count_bytes(lfs_handle, LFS_BUFFER_PENDING_WRITE) >= lfs_handle->preferred_write_size) {
        globus_cond_signal(lfs_handle->queued_cond);
    }
    globus_mutex_unlock(lfs_handle->buffer_mutex);
    return 1;
}
void lfs_throw_queue_error(lfs_handle_t *lfs_handle, globus_result_t rc) {
    globus_mutex_lock(lfs_handle->buffer_mutex);
    lfs_handle->background_status = rc;
    globus_mutex_unlock(lfs_handle->buffer_mutex);
}

// entry point from pthread_create
void * lfs_queue_handler(void * handle) {
    lfs_handle_t * lfs_handle = (lfs_handle_t *) handle;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Starting write backend\n");
    globus_result_t rc = GLOBUS_SUCCESS;
    if (!lfs_handle) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Backend got a null pointer\n");
        return NULL;
    }
    tbuffer_t buffer;
    ex_iovec_t * iovec_file = NULL;
    unsigned char ** used_array = NULL;
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Pointer vals: %lu %lu %lu\n", &buffer, iovec_file, used_array);
    while (lfs_dequeue_buffer((lfs_handle_t *) handle, &iovec_file, &buffer, &used_array)) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Pointer vals post: %lu %lu %lu\n", &buffer, iovec_file, used_array);
        if (buffer.buf.n == 0) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Zero blocks? You idiot!\n");
            continue;
        }
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Backend dumping buffer of %u blocks. First block at %lu thread %lu\n", buffer.buf.n, buffer.buf.iov[0], (unsigned long) syscall(SYS_gettid));
        if ((rc = lfs_dump_buffer_immed((lfs_handle_t *) handle, iovec_file, &buffer)) != GLOBUS_SUCCESS) {
            lfs_throw_queue_error(lfs_handle, rc);
        }
        globus_mutex_lock(lfs_handle->buffer_mutex);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Buffers free  pre: %lu writing %lu\n", count_blocks(lfs_handle, LFS_BUFFER_FREE),count_blocks(lfs_handle, LFS_BUFFER_WRITING));
        for (unsigned int i = 0; i < buffer.buf.n; ++i) {
            *(*(used_array + i)) = (unsigned char) LFS_BUFFER_FREE;
        }
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Buffers free post: %lu writing %lu\n", count_blocks(lfs_handle, LFS_BUFFER_FREE),count_blocks(lfs_handle, LFS_BUFFER_WRITING));
        lfs_reap_buffers(lfs_handle);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Buffers free reap: %lu writing %lu\n", count_blocks(lfs_handle, LFS_BUFFER_FREE),count_blocks(lfs_handle, LFS_BUFFER_WRITING));
        globus_mutex_unlock(lfs_handle->buffer_mutex);
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
    if (!lfs_handle) {
        MemoryError(lfs_handle, "Have a null lfs_handle\n", rc);
        return rc;
    }
    if (!lfs_handle->write_pool) {
        MemoryError(lfs_handle, "Couldn't allocate thread pool\n", rc);
        return rc;
    }

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
    return rc;
}

// Last step - physically write to disk
globus_result_t lfs_dump_buffer_immed(lfs_handle_t * lfs_handle, ex_iovec_t * iovec_file, tbuffer_t * buffer) {
    globus_result_t rc = GLOBUS_SUCCESS;

    GlobusGFSName(lfs_dump_buffer_immed);
    globus_size_t nbytes = buffer->buf.total_bytes;

    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "dump_immed pre-checksum %u bytes. (preferred %u)\n", nbytes, lfs_handle->preferred_write_size);

    // Checksum when writing to disk.  This way, if a non-transient corruption occurs
    // during writing to Hadoop, we detect it and hopefully fail the file.
    if (lfs_handle->cksm_types) {
        for (unsigned int i = 0; i < buffer->buf.n; ++i) {
            //  buffer.buf.iov[i].iov_base, buffer.buf.iov[i].iov_len , iovec_file[i].offset
            lfs_update_checksums(lfs_handle, buffer->buf.iov[i].iov_base,  buffer->buf.iov[i].iov_len , iovec_file[i].offset);
        }
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "dump_imed post-checksum %u bytes. (preferred %u)\n", nbytes, lfs_handle->preferred_write_size);
    // now do the actual write
    globus_size_t bytes_written;
    STATSD_TIMER_START(write_timer);
    if (is_lfs_path(lfs_handle, lfs_handle->pathname)) {
        bytes_written = lfs_write_ex(lfs_handle->pathname_munged, buffer->buf.n, iovec_file, buffer, 0, lfs_handle->fd);
        if (bytes_written != nbytes) {
            STATSD_COUNT("lfs_write_failure",1);
            SystemError(lfs_handle, "write into LFS", rc);
            set_done(lfs_handle, rc);
            return rc;
        }
        STATSD_TIMER_END("write_time", write_timer);
        STATSD_COUNT("lfs_bytes_written",bytes_written);
    } else {
        for (unsigned int i = 0; i < buffer->buf.n; ++i) {
            bytes_written = pwrite(lfs_handle->fd_posix, buffer->buf.iov[i].iov_base, buffer->buf.iov[i].iov_len , iovec_file[i].offset);
            if (bytes_written != buffer->buf.iov[i].iov_len) {
                SystemError(lfs_handle, "write into POSIX", rc);
                set_done(lfs_handle, rc);
                return rc;
            }
            STATSD_COUNT("posix_bytes_written", bytes_written);
            STATSD_TIMER_END("posix_write_time", write_timer);
            STATSD_TIMER_RESET(write_timer);
        }
    }
    lfs_log_buffer_status(lfs_handle);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "dump-immed post-write %u bytes. (preferred %u)\n", nbytes, lfs_handle->preferred_write_size);
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
