
#include "gridftp_lfs.h"
#include <syslog.h>
#include <sys/mman.h>

/*************************************************************************
 *  use_file_buffer
 *  ---------------
 *  Decide whether we should use a file buffer based on the current
 *  memory usage.
 *  Returns 1 if we should use a file buffer.
 *  Else, returns 0.
 ************************************************************************/
static inline int
use_file_buffer(globus_l_gfs_lfs_handle_t * lfs_handle) {

    unsigned int buffer_count = lfs_handle->buffer_count;

    if (buffer_count >= lfs_handle->max_buffer_count-1) {
        return 1;
    }
    if ((lfs_handle->using_file_buffer == 1) && (buffer_count > lfs_handle->max_buffer_count/2)) {
        return 1;
    }
    return 0;
}

/*************************************************************************
 *  remove_file_buffer
 *  ------------------
 *  This is called when cleaning up a file buffer. The file on disk is removed and
 *  the internal memory for storing the filename is freed.
 ************************************************************************/

void
remove_file_buffer(lfs_handle_t * lfs_handle) {
    if (lfs_handle->tmp_file_pattern) {
        snprintf(err_msg, MSG_SIZE, "Removing file buffer %s.\n", lfs_handle->tmp_file_pattern);
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
        globus_free(lfs_handle->tmp_file_pattern);
        lfs_handle->tmp_file_pattern = (char *)NULL;
    }
}

/**
 *  Initialize backing store
 */
static globus_result_t lfs_initialize_file(globus_l_gfs_lfs_handle_t * lfs_handle) {
    int i, cnt;
    globus_result_t rc = GLOBUS_SUCCESS;
    // Initial file buffer.
    GlobusGFSName(globus_l_gfs_lfs_initialize_file);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Switching from memory buffer to file buffer.\n");

    char *tmpdir=getenv("TMPDIR");
    if (tmpdir == NULL) {
        tmpdir = "/tmp";
    }
    lfs_handle->tmp_file_pattern = globus_malloc(sizeof(char) * (strlen(tmpdir) + 32));
    sprintf(lfs_handle->tmp_file_pattern, "%s/gridftp-lfs-buffer-XXXXXX", tmpdir);

    lfs_handle->tmpfilefd = mkstemp(lfs_handle->tmp_file_pattern);
    int filedes = lfs_handle->tmpfilefd;
    if (filedes == -1) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to determine file descriptor of temporary file.\n");
            rc = GlobusGFSErrorGeneric("Failed to determine file descriptor of temporary file.");
            remove_file_buffer(lfs_handle);
            return rc;
    }
    unlink(lfs_handle->tmp_file_pattern);
    snprintf(err_msg, MSG_SIZE, "Created file buffer %s.\n", lfs_handle->tmp_file_pattern);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
    char * tmp_write = globus_calloc(lfs_handle->block_size, sizeof(globus_byte_t));
    if (tmp_write == NULL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Could not allocate memory for dumping file buffer.\n");
        rc = GlobusGFSErrorGeneric("Could not allocate memory for dumping file buffer.");
        return rc;
    }
    /* Write into the file to create its initial size */
    cnt = lfs_handle->buffer_count;
    for (i=0; i<cnt; i++) {
        if (write(filedes, tmp_write, sizeof(globus_byte_t)*lfs_handle->block_size) < 0) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to initialize backing file.\n");
            rc = GlobusGFSErrorGeneric("Failed to initialize backing file.");
            globus_free(tmp_write);
            return rc;
        }
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Pre-filled file buffer with empty data.\n");
    globus_free(tmp_write);
    return rc;
}

static globus_result_t lfs_populate_mmap(globus_l_gfs_lfs_handle_t* lfs_handle) {
    GlobusGFSName(lfs_populate_mmap);
    int filedes = lfs_handle->tmpfilefd, cnt;
    globus_result_t rc = GLOBUS_SUCCESS;
    globus_byte_t * file_buffer = mmap(0, lfs_handle->block_size*lfs_handle->max_file_buffer_count*sizeof(globus_byte_t),
        PROT_READ | PROT_WRITE, MAP_SHARED, filedes, 0);
    if (file_buffer == (globus_byte_t *)-1) {
        if (errno == ENOMEM) {
            snprintf(err_msg, MSG_SIZE, "Error mmapping the file buffer (%ld bytes): errno=ENOMEM\n",
                lfs_handle->block_size*lfs_handle->max_file_buffer_count*sizeof(globus_byte_t));
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
        } else {
            snprintf(err_msg, MSG_SIZE, "Error mmapping the file buffer: errno=%d\n", errno);
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
        }
        remove_file_buffer(lfs_handle);
        rc = GlobusGFSErrorGeneric("Failed to mmap() the file buffer.");
        return rc;
    }
    cnt = lfs_handle->buffer_count;
    memcpy(file_buffer, lfs_handle->buffer, cnt*lfs_handle->block_size*sizeof(globus_byte_t));
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Memory buffers copied to disk buffer.\n");
    globus_free(lfs_handle->buffer);
    lfs_handle->buffer = file_buffer;
    lfs_handle->using_file_buffer = 1;
    return GLOBUS_SUCCESS;
}

int min_buffers(int a, globus_l_gfs_lfs_handle_t * lfs_handle) { 
    if (a < lfs_handle->min_buffer_count) { 
        return lfs_handle->min_buffer_count; 
    } else { 
        return a;
    }
}

globus_size_t lfs_used_buffer_count(globus_l_gfs_lfs_handle_t * lfs_handle) {
    int i, cnt = lfs_handle->buffer_count;
    globus_size_t result = 0;
    for (i=0; i<cnt; i++) {
        if (lfs_handle->used[i]) {
            ++result;
        }
    }
    return result;
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

    // Determine the type of buffer to use; allocate or transfer buffers as necessary
    int use_buffer = use_file_buffer(lfs_handle);
    if ((use_buffer == 1) && (lfs_handle->using_file_buffer == 0)) {
        if ((rc = lfs_initialize_file(lfs_handle)) != GLOBUS_SUCCESS) {
            return rc;
        }
        if ((rc = lfs_populate_mmap(lfs_handle)) != GLOBUS_SUCCESS) {
            return rc;
        }
    } else if (use_buffer == 1) {
        // Do nothing.  Continue to use the file buffer for now.
    } else if (lfs_handle->using_file_buffer == 1 && cnt < lfs_handle->max_buffer_count) {
        // Turn off file buffering; copy data to a new memory buffer
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Switching from file buffer to memory buffer.\n");
        actual_cnt = min_buffers(cnt, lfs_handle);
        globus_byte_t * tmp_buffer = globus_malloc(sizeof(globus_byte_t)*lfs_handle->block_size*actual_cnt);
        if (tmp_buffer == NULL) {
            rc = GlobusGFSErrorGeneric("Memory allocation error.");
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error.");
            return rc;
        }
        memcpy(tmp_buffer, lfs_handle->buffer, actual_cnt*lfs_handle->block_size*sizeof(globus_byte_t));
        munmap(lfs_handle->buffer, lfs_handle->block_size*lfs_handle->buffer_count*sizeof(globus_byte_t));
        lfs_handle->using_file_buffer = 0;
        close(lfs_handle->tmpfilefd);
        remove_file_buffer(lfs_handle);
        lfs_handle->buffer = tmp_buffer;
    } else {
            // Do nothing.  Continue to use the file buffer for now.
    }

    // Search for a free space in our buffer, and then actually make the copy.
    // Prefer to put it into the right place based on modulo math
    int preferred_location = (offset % 
                                (lfs_handle->preferred_write_size *
                                 lfs_handle->write_size_buffers) ) / 
                             lfs_handle->block_size;

    if ((preferred_location < lfs_handle->buffer_count) &&
            (lfs_handle->used[preferred_location] == 0)) {
        i = preferred_location;
    } else {
        int found_unpreferred = 0;
        for (i = lfs_handle->min_buffer_count; i<cnt; i++) {
            if (lfs_handle->used[i] == 0) {
                found_unpreferred = 1;
                break;
            }
        }
        if (!found_unpreferred) {
            for (i = 0; i<cnt; i++) {
                if (lfs_handle->used[i] == 0) {
                    break;
                }
            }
        }
    }
   
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Trying to find a slot. Preferred %u chosen %u out of %u\n",
                            preferred_location, i, lfs_handle->buffer_count);
    // if i == cnt, we didn't find anywhere to stick this buffer..
    if (i != cnt) {
        if (offset % lfs_handle->block_size == 0) {
            snprintf(err_msg, MSG_SIZE, "Stored some bytes in buffer %d; block offset %lu.\n", i, offset/lfs_handle->block_size);
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);
        } else {
            snprintf(err_msg, MSG_SIZE, "Stored some bytes in buffer %d; offset %lu.\n", i, offset);
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);
        }
        lfs_handle->nbytes[i] = nbytes;
        lfs_handle->offsets[i] = offset;
        lfs_handle->used[i] = 1;
        lfs_handle->buffer_pointers[i] = buffer;
        wrote_something=1;
        memcpy(lfs_handle->buffer+i*lfs_handle->block_size, buffer, nbytes*sizeof(globus_byte_t));
    }

    // Check to see how many unused buffers we have;
    i = cnt;
    while (i>0) {
        i--;
        if ((lfs_handle->used[i] == 1) || (i <= lfs_handle->min_buffer_count)) {
            break;
        }
    }
    i++;

    actual_cnt = min_buffers(cnt, lfs_handle);
    snprintf(err_msg, MSG_SIZE, "There are %i extra buffers.\n", actual_cnt-i);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);
    // If there are more than 10 unused buffers, deallocate.
    if ((actual_cnt - i > 10) && (i > lfs_handle->min_buffer_count)) {
        snprintf(err_msg, MSG_SIZE, "About to deallocate %i buffers; %i will be left.\n", cnt-i, i);
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);
        lfs_handle->buffer_count = min_buffers(i, lfs_handle);
        lfs_handle->nbytes = globus_realloc(lfs_handle->nbytes, lfs_handle->buffer_count*sizeof(globus_size_t));
        lfs_handle->offsets = globus_realloc(lfs_handle->offsets, lfs_handle->buffer_count*sizeof(globus_off_t));
        lfs_handle->used = globus_realloc(lfs_handle->used, lfs_handle->buffer_count*sizeof(short));
        lfs_handle->buffer_pointers = globus_realloc(lfs_handle->buffer_pointers, lfs_handle->buffer_count*sizeof(globus_byte_t *));
        if (lfs_handle->using_file_buffer == 0)
            lfs_handle->buffer = globus_realloc(lfs_handle->buffer, lfs_handle->buffer_count*lfs_handle->block_size*sizeof(globus_byte_t));
        else {
            // Truncate the file holding our backing data (note we don't resize the mmap).
            if (ftruncate(lfs_handle->tmpfilefd, lfs_handle->buffer_count*lfs_handle->block_size*sizeof(globus_byte_t))) {
                rc = GlobusGFSErrorGeneric("Unable to truncate our file-backed data.");
                globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to truncate our file-backed data.\n");
            }
            lseek(lfs_handle->tmpfilefd, 0, SEEK_END);
        }
        if (lfs_handle->buffer == NULL || lfs_handle->nbytes==NULL || 
                lfs_handle->offsets==NULL || lfs_handle->used==NULL ||
                lfs_handle->buffer_pointers==NULL) {
            rc = GlobusGFSErrorGeneric("Memory allocation error.");
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error.");
            globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
            return rc;
        }
    }

    // If wrote_something=0, then we have filled up all our buffers; allocate a new one.
    if (wrote_something == 0) {
        lfs_handle->buffer_count += 1;
        if (lfs_handle->buffer_count > lfs_handle->max_buffer_count/2) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Initializing buffer number %d.\n", lfs_handle->buffer_count);
        } else {
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Initializing buffer number %d.\n", lfs_handle->buffer_count);
        }
        // Refuse to allocate more than the max.
        if ((lfs_handle->using_file_buffer == 0) && (lfs_handle->buffer_count == lfs_handle->max_buffer_count)) {
            // Out of memory buffers; we really shouldn't hit this code anymore.
            char * hostname = globus_malloc(sizeof(char)*256);
            memset(hostname, '\0', sizeof(char)*256);
            if (gethostname(hostname, 255) != 0) {
                sprintf(hostname, "UNKNOWN");
            }
            snprintf(err_msg, MSG_SIZE, "Allocated all %i memory buffers on server %s; aborting transfer.", lfs_handle->max_buffer_count, hostname);
            globus_free(hostname);
            rc = GlobusGFSErrorGeneric(err_msg);
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to store data into LFS buffer.\n");
        } else if ((lfs_handle->using_file_buffer == 1) && (lfs_handle->buffer_count == lfs_handle->max_file_buffer_count)) {
            // Out of file buffers.
            char * hostname = globus_malloc(sizeof(char)*256);
            memset(hostname, '\0', sizeof(char)*256);
            if (gethostname(hostname, 255) != 0) {
                sprintf(hostname, "UNKNOWN");
            }
            snprintf(err_msg, MSG_SIZE, "Allocated all %i file-backed buffers on server %s; aborting transfer.", lfs_handle->max_file_buffer_count, hostname);
            globus_free(hostname);
            rc = GlobusGFSErrorGeneric(err_msg);
            globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Failed to store data into LFS file buffer.\n");
        } else {
            // Increase the size of all our buffers which track memory usage
            lfs_handle->nbytes = globus_realloc(lfs_handle->nbytes, lfs_handle->buffer_count*sizeof(globus_size_t));
            lfs_handle->offsets = globus_realloc(lfs_handle->offsets, lfs_handle->buffer_count*sizeof(globus_off_t));
            lfs_handle->used = globus_realloc(lfs_handle->used, lfs_handle->buffer_count*sizeof(short));
            lfs_handle->buffer_pointers = globus_realloc(lfs_handle->buffer_pointers, lfs_handle->buffer_count*sizeof(short));
            lfs_handle->used[lfs_handle->buffer_count-1] = 1;
            // Only reallocate the physical buffer if we're using a memory buffer, otherwise we screw up our mmap
            if (lfs_handle->using_file_buffer == 0) {
                lfs_handle->buffer = globus_realloc(lfs_handle->buffer, lfs_handle->buffer_count*lfs_handle->block_size*sizeof(globus_byte_t));
            } else {
                // This not only extends the size of our file, but we extend it with the desired buffer data.
                lseek(lfs_handle->tmpfilefd, (lfs_handle->buffer_count-1)*lfs_handle->block_size, SEEK_SET);
                if (write(lfs_handle->tmpfilefd, buffer, nbytes*sizeof(globus_byte_t)) < 0) {
                    rc = GlobusGFSErrorGeneric("Unable to extend our file-backed buffers; aborting transfer.");
                    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to extend our file-backed buffers; aborting transfer.\n");
                }
                // If our buffer was too small,
                if (nbytes < lfs_handle->block_size) {
                    int addl_size = lfs_handle->block_size-nbytes;
                    char * tmp_write = globus_calloc(addl_size, sizeof(globus_byte_t));
                    if (write(lfs_handle->tmpfilefd, tmp_write, sizeof(globus_byte_t)*addl_size) < 0) {
                        rc = GlobusGFSErrorGeneric("Unable to extend our file-backed buffers; aborting transfer.");
                        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Unable to extend our file-backed buffers; aborting transfer.\n");
                    }
                    globus_free(tmp_write);
                }
                //lfs_handle->buffer = mmap(lfs_handle->buffer, lfs_handle->block_size*lfs_handle->max_file_buffer_count*sizeof(globus_byte_t), PROT_READ | PROT_WRITE, MAP_PRIVATE, lfs_handle->tmpfilefd, 0);
            }
            if (lfs_handle->buffer == NULL || lfs_handle->nbytes==NULL || 
                    lfs_handle->offsets==NULL || lfs_handle->used==NULL ||
                    lfs_handle->buffer_pointers==NULL) {
                rc = GlobusGFSErrorGeneric("Memory allocation error.");
                globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Memory allocation error.\n");
                globus_gridftp_server_finished_transfer(lfs_handle->op, rc);
            }
            // In the case where we have file buffers, we already wrote the contents of buffer previously.
            if (lfs_handle->using_file_buffer == 0) {
                memcpy(lfs_handle->buffer+(lfs_handle->buffer_count-1)*lfs_handle->block_size, buffer, nbytes*sizeof(globus_byte_t));
            }
            lfs_handle->nbytes[lfs_handle->buffer_count-1] = nbytes;
            lfs_handle->offsets[lfs_handle->buffer_count-1] = offset;
            lfs_handle->buffer_pointers[i] = buffer;
        }
    }

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

    wrote_something=1;
    globus_size_t accumulated_amount = 0;
    globus_size_t target_amount = lfs_handle->preferred_write_size;
    globus_off_t offset_begin;
    size_t buffer_begin;
    // Loop through all our buffers; loop again if we write something.
    while (wrote_something == 1) {
        wrote_something=0;
        if (accumulated_amount != 0) {
            SystemError(lfs_handle, "accumulated_amount should be zero", errno);
        }
        // For each of our buffers.
        int found_head = 0;
        globus_mutex_lock(lfs_handle->offset_mutex);
        for (i=0; i<cnt; i++) {
            // Do checks to see if we're at the front of a train
            if (!found_head && lfs_handle->used[i] && offsets[i] == lfs_handle->offset) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Found beginning of buffer. Block %i\n", i);
                offset_begin = lfs_handle->offset;
                buffer_begin = i;
                found_head = 1;
                accumulated_amount = 0;
            }
            if (!found_head) {
                continue;
            }
            if (!lfs_handle->used[i] || (offset_begin + accumulated_amount != offsets[i])) {
                found_head = 0;
                accumulated_amount = 0;
                continue;
            }   
            /**
             * So, we would like to dump buffers IF any of:
             * 1) We are at the end of the list of buffers (i=cnt-1)
             * 2) lfs_handle->nbytes != lfs_handle>block_size
             * 3) We have accumulated 10MB of data
             * 4) next buffer is used AND current_offset + block_size != next_offset
             */
            int checkOne = (i == cnt - 1);
            int checkTwo = (nbytes[i] != lfs_handle->block_size);
            int checkThree = (accumulated_amount + nbytes[i] >= target_amount);
            // this check makes no sense if we're at the end of the list
            int checkFour = ((i != cnt -1) && (lfs_handle->used[i+1]) &&
                                (offsets[i] + nbytes[i] != offsets[i+1]));
            if ( checkOne || checkTwo || checkThree || checkFour ) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "dumping %u to %u: %i %i %i %i\n",
                                        buffer_begin, i, checkOne, checkTwo,
                                        checkThree, checkFour);
                // dump things out immediately
                globus_size_t tmp_nbytes = accumulated_amount +
                                            nbytes[i]*sizeof(globus_byte_t);
                globus_byte_t *tmp_buffer = globus_malloc(tmp_nbytes);
                int j;
                globus_byte_t *copy_pointer = tmp_buffer;
                for (j=buffer_begin;j<=i;++j) {
                    lfs_handle->used[j] = 0;
                    memcpy(copy_pointer, lfs_handle->buffer_pointers[j], nbytes[j]);
                    copy_pointer += nbytes[j];
                    globus_free(lfs_handle->buffer_pointers[j]);
                }
                off_t old_offset = lfs_handle->offset;
                if ((rc = lfs_dump_buffer_immed(lfs_handle, tmp_buffer, tmp_nbytes, old_offset)) != GLOBUS_SUCCESS) {
                    return rc;
                }
                lfs_handle->offset += tmp_nbytes;
                globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Offset jumps from %i to %i\n",old_offset, lfs_handle->offset);
                globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Offset blocks jumps from %i to %i\n",old_offset/lfs_handle->block_size, lfs_handle->offset/lfs_handle->block_size);
                // lfs_handle->outstanding -= i - buffer_begin + 1;
                if (tmp_nbytes > 0) {
                    wrote_something = 1;
                }
                for (j=buffer_begin;j<=i;++j) {
                    lfs_handle->used[j] = 0;
                }
                found_head = 0;
                accumulated_amount = 0;
            } else {
                // We chose to not dump immediately. Maybe the next pass will 
                // push us over the edge.
                accumulated_amount += nbytes[i]*sizeof(globus_byte_t);
            }
        }
        globus_mutex_unlock(lfs_handle->offset_mutex);
    }
    if (accumulated_amount != 0) {
        SystemError(lfs_handle, "accumulated_amount should be zero", errno);
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

    wrote_something=1;
    // Loop through all our buffers; loop again if we write something.
    while (wrote_something == 1) {
        wrote_something=0;
        // For each of our buffers.
        for (i=0; i<cnt; i++) {
            if (lfs_handle->used[i] == 1 && offsets[i] == lfs_handle->offset) {
                globus_byte_t *tmp_buffer = lfs_handle->buffer_pointers[i];
                globus_size_t tmp_nbytes = nbytes[i]*sizeof(globus_byte_t);
                if ((rc = lfs_dump_buffer_immed(lfs_handle, tmp_buffer, tmp_nbytes, lfs_handle->offset)) != GLOBUS_SUCCESS) {
                    return rc;
                }
                if (tmp_nbytes > 0) {
                    wrote_something = 1;
                }
                lfs_handle->used[i] = 0;
                lfs_handle->offset += tmp_nbytes;
            }
        }
    }
    return rc;
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
        while (lfs_handle->committed_offset != offset) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Preparing to checksum at offset %lu (current: %lu)\n", offset, lfs_handle->committed_offset);
            globus_cond_wait(lfs_handle->offset_cond, lfs_handle->offset_mutex);
            if (lfs_handle->committed_offset > offset) {
                // what the hell, man?
                SystemError(lfs_handle, "The checksumming got skipped", rc);
                globus_cond_broadcast(lfs_handle->offset_cond);
                globus_mutex_unlock(lfs_handle->offset_mutex);
                globus_free(buffer);
                set_done(lfs_handle, rc);
                return -1;
            }
        }
        lfs_handle->committed_offset += nbytes;
        lfs_update_checksums(lfs_handle, buffer, nbytes);
        globus_cond_broadcast(lfs_handle->offset_cond);
    }
    globus_mutex_unlock(lfs_handle->offset_mutex);
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

