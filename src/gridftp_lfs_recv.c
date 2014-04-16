#include <errno.h>
#include <unistd.h>
#include "gridftp_lfs.h"

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}

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

static void
lfs_dispatch_write(
    globus_l_gfs_lfs_handle_t *      lfs_handle);

// Taken from globus_gridftp_server_file.c
// Assume md5_human is length MD5_DIGEST_LENGTH*2+1
// Assume md5_openssl is length MD5_DIGEST_LENGTH
static void human_readable_md5(unsigned char *md5_human, const unsigned char *md5_openssl) {
    unsigned int i;
    unsigned char * md5ptr = md5_human;
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        sprintf(md5ptr, "%02x", md5_openssl[i]);
        md5ptr++;
        md5ptr++;
    }
    md5ptr = '\0';
}

/*************************************************************************
 *  close_and_clean
 *  --------------
 *  Close the LFS file and clean up the write-related resources in the
 *  handle.
 *************************************************************************/
static globus_result_t
close_and_clean(lfs_handle_t *lfs_handle, globus_result_t rc) {
    STATSD_COUNT("close_and_clean",1);
    GlobusGFSName(close_and_clean);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Trying to close file in LFS; zero outstanding blocks.\n");
    int retval;
    if (is_close_done(lfs_handle)) {
        return lfs_handle->done_status;
    }

    if (is_lfs_path(lfs_handle, lfs_handle->pathname)) {
        if ((retval = lfs_release_real(lfs_handle->pathname_munged, lfs_handle->fd, lfs_handle->fs)) != 0)
        {
            rc = retval;
            GenericError(lfs_handle, "Failed to close file in LFS.", retval);
            lfs_handle->fd = NULL;
        }
    } else {
        if ((retval = close(lfs_handle->fd_posix)) != 0) {
            rc = retval;
            GenericError(lfs_handle, "Failed to close file in POSIX.", retval);
            lfs_handle->fd_posix = 0;
        }
    }
    if (lfs_handle->using_file_buffer == 0) {
        globus_free(lfs_handle->buffer);
    } else {
        munmap(lfs_handle->buffer, lfs_handle->block_size*lfs_handle->buffer_count*sizeof(globus_byte_t));
        lfs_handle->using_file_buffer = 0;
        close(lfs_handle->tmpfilefd);
    }
    globus_free(lfs_handle->used);
    globus_free(lfs_handle->nbytes);
    globus_free(lfs_handle->offsets);
    globus_free(lfs_handle->buffer_pointers);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "receive %d blocks of size %d bytes\n",
        lfs_handle->io_count, lfs_handle->io_block_size);

    unsigned char final_cksm_human[2*MD5_DIGEST_LENGTH+1];

    if (lfs_handle->cksm_types) {
        lfs_finalize_checksums(lfs_handle);
        human_readable_md5(final_cksm_human, lfs_handle->md5_output);
        if ((lfs_handle->done_status == GLOBUS_SUCCESS) && (lfs_handle->expected_cksm)) {
            if (strncmp(final_cksm_human, lfs_handle->expected_cksm, 2*MD5_DIGEST_LENGTH) != 0) {
                GenericError(lfs_handle, "Calculated checksum %s does not match expected checksum %s.\n", rc);
            }
        }
        if ((lfs_handle->done_status == GLOBUS_SUCCESS) && (rc == GLOBUS_SUCCESS) && is_lfs_path(lfs_handle,lfs_handle->pathname)) {
            rc = lfs_save_checksum(lfs_handle);
        }
    }
    if (lfs_handle->sent_finish != GLOBUS_TRUE) {
        if (lfs_handle->log_filename)
            unlink(lfs_handle->log_filename);
    }

    set_close_done(lfs_handle, rc);
    return rc;
}

/*************************************************************************
 * determine_replicas
 * ------------------
 * Determine the number of replicas for this file based on the pathname.
 *************************************************************************/
#define DEFAULT_LINE_LENGTH 256
int determine_replicas (const char * path) {
    return 1;
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
    lfs_handle->sent_finish = GLOBUS_FALSE;

    const char *path = lfs_handle->pathname;

    if (is_lfs_path(lfs_handle, path)) {
        ADVANCE_SLASHES(path);
        if (strncmp(path, lfs_handle->mount_point, lfs_handle->mount_point_len) == 0) {
            path += lfs_handle->mount_point_len;
        }
        ADVANCE_SLASHES(path);
    }

    lfs_handle->pathname_munged = (char*)globus_malloc(strlen(path)+1);
    if (!lfs_handle->pathname_munged) {MemoryError(lfs_handle, "Unable to make a copy of the path name.", rc); return rc;}
    strcpy(lfs_handle->pathname_munged, path);

    lfs_handle->expected_cksm = NULL;

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "We are going to open file %s.\n", lfs_handle->pathname);
    lfs_handle->outstanding = 0;
    lfs_handle->done = GLOBUS_FALSE;
    lfs_handle->done_status = GLOBUS_SUCCESS;
    globus_gridftp_server_get_block_size(lfs_handle->op, &lfs_handle->block_size);
    
    // Since we have the block size, we can compute the min buffer count
    lfs_handle->min_buffer_count = (lfs_handle->preferred_write_size * lfs_handle->write_size_buffers) / lfs_handle->block_size + 1;

    //globus_gridftp_server_get_optimal_concurrency(lfs_handle->op,
    //                                              &lfs_handle->optimal_count);
    // the number of in-flight blocks (I think)
    lfs_handle->optimal_count = (lfs_handle->preferred_write_size * 
                                    (lfs_handle->write_size_buffers - 1) )/ lfs_handle->block_size;
    lfs_handle->buffer_count = lfs_handle->min_buffer_count;
    lfs_handle->nbytes = globus_malloc(lfs_handle->buffer_count*sizeof(globus_size_t));
    lfs_handle->offsets = globus_malloc(lfs_handle->buffer_count*sizeof(globus_off_t));
    lfs_handle->used = globus_malloc(lfs_handle->buffer_count*sizeof(short));
    lfs_handle->buffer_pointers = globus_malloc(lfs_handle->buffer_count*sizeof(globus_byte_t *));
    int i;
    for (i=0; i<lfs_handle->buffer_count; i++)
        lfs_handle->used[i] = 0;
    lfs_handle->buffer = globus_malloc(lfs_handle->buffer_count*lfs_handle->block_size*sizeof(globus_byte_t));
    if (lfs_handle->buffer == NULL || lfs_handle->nbytes==NULL ||
            lfs_handle->offsets==NULL || lfs_handle->used==NULL ||
            lfs_handle->buffer_pointers==NULL) {
        MemoryError(lfs_handle, "Memory allocation error.", rc);
        return rc;
    }

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Opened %u buffers.\n", lfs_handle->buffer_count);
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
    globus_l_gfs_lfs_handle_t *        lfs_handle;
    globus_result_t                     rc = GLOBUS_SUCCESS;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Receiving a file: %s\n", transfer_info->pathname);
    GlobusGFSName(lfs_recv);


    lfs_handle = (lfs_handle_t *) user_arg;
    globus_mutex_lock(lfs_handle->mutex);

    lfs_handle->op = op;
    char * PathName=transfer_info->pathname;
    lfs_handle->pathname = PathName;
    if (is_lfs_path(lfs_handle, PathName)) {
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
        lfs_handle->expected_cksm =
            globus_libc_strdup(transfer_info->expected_checksum);
    }
    if (transfer_info->expected_checksum_alg) {
        lfs_parse_checksum_types(lfs_handle, transfer_info->expected_checksum_alg);
    }

    lfs_initialize_checksums(lfs_handle);

	globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Open file %s.\n",
            lfs_handle->pathname);
    int retval;
    if (is_lfs_path(lfs_handle, PathName)) {
        struct stat fileInfo;
        retval = lfs_stat_real(lfs_handle->pathname_munged, (&fileInfo), lfs_handle->fs);
        if (retval == -ENOENT) {
            // the file doesn't exist, make an empty one
            dev_t rdev;
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "File %s doesn't exist, creating it\n", lfs_handle->pathname_munged);
            // TODO can this fail?
            int mknod_retval = lfs_mknod_real(lfs_handle->pathname_munged, 0644, rdev, lfs_handle->fs);
            if (mknod_retval != 0 && mknod_retval != -EEXIST) {
                GenericError(lfs_handle, "Can't make new, blank file.", mknod_retval);
                goto cleanup;
            }
        } else if (S_ISDIR(fileInfo.st_mode)) {
            GenericError(lfs_handle, "Destination path is a directory; cannot overwrite.", retval);
            goto cleanup;
        }

        lfs_handle->fd = (struct fuse_file_info*)globus_malloc(sizeof(struct fuse_file_info));
        if (lfs_handle->fd == NULL)
        {
            MemoryError(lfs_handle, "Memory allocation error.", rc);
            return rc;
        }
        memset(lfs_handle->fd, 0, sizeof(struct fuse_file_info));
        lfs_handle->fd->direct_io = 0;
        lfs_handle->fd->flags = O_WRONLY;
        retval = lfs_open_real(lfs_handle->pathname_munged, lfs_handle->fd, lfs_handle->fs);
        if (retval != 0)
        {
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
        retval = open(PathName,  O_WRONLY | O_CREAT );
        if (retval > 0) {
            lfs_handle->fd_posix = retval;
        } else {
            SystemError(lfs_handle, "opening file; POSIX error", rc);
            goto cleanup;
        }
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
        "Successfully opened file %s for user %s.\n", lfs_handle->pathname,
         lfs_handle->username);

    globus_gridftp_server_begin_transfer(lfs_handle->op, 0, lfs_handle);
    lfs_dispatch_write(lfs_handle);

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        set_done(lfs_handle, rc);
        if (!lfs_handle->sent_finish) {
            globus_gridftp_server_finished_transfer(op, lfs_handle->done_status);
            lfs_handle->sent_finish = GLOBUS_TRUE;
        }
    }
    globus_mutex_unlock(lfs_handle->mutex);
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
    globus_result_t                     rc = GLOBUS_SUCCESS;
    globus_l_gfs_lfs_handle_t *        lfs_handle;

    GlobusGFSName(lfs_handle_write_op);
    lfs_handle = (globus_l_gfs_lfs_handle_t *) user_arg;

    globus_mutex_lock(lfs_handle->mutex);

    globus_gridftp_server_update_bytes_written(op, offset, nbytes);

#ifdef FAKE_ERROR
    block_count ++;
    if (block_count == 30) {
        GenericError(lfs_handle, "Got bored, threw an error.", rc);
        goto cleanup;
    }
#endif

    // If the transfer is done and not successful, don't bother saving this block
    // If it is done and successful, maybe we're the last-to-arrive block?
    if (is_done(lfs_handle) && lfs_handle->done_status != GLOBUS_SUCCESS) {
        rc = lfs_handle->done_status;
        goto cleanup;
    }

    if (result != GLOBUS_SUCCESS) {
        rc = result;
        goto cleanup;
    } else if (eof) {
        set_done(lfs_handle, GLOBUS_SUCCESS);
    }

    if (nbytes == 0) {
        // There were no bytes left; we don't have an EOF, but all bytes
        // should be in-flight.
        set_done(lfs_handle, GLOBUS_SUCCESS);
        goto cleanup;
    }
    
    if (lfs_used_buffer_count(lfs_handle) > lfs_handle->stall_buffer_count) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Buffer count too high. Stalling.\n");
        sleep(1);
    }
    // Try to store the buffer into memory, a seperate thread handles consuming
    // this
    if ((rc = lfs_store_buffer(lfs_handle, buffer, offset, nbytes)) != GLOBUS_SUCCESS) {
        goto cleanup;
    }

    if ((rc = lfs_dump_buffers(lfs_handle)) != GLOBUS_SUCCESS) {
        goto cleanup;
    }
cleanup:
    // Do some statistics
    if (rc == GLOBUS_SUCCESS) {
        if (nbytes != lfs_handle->io_block_size) {
            if (lfs_handle->io_block_size != 0) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "receive %d blocks of size %d bytes\n",
                    lfs_handle->io_count,lfs_handle->io_block_size);
            }
            lfs_handle->io_block_size = nbytes;
            lfs_handle->io_count=1;
        } else {
            lfs_handle->io_count++;
        }
    }

    // Finish the transfer on failure
    if (rc != GLOBUS_SUCCESS) {
        set_done(lfs_handle, rc);
    }
    
    // deallocate on the other side of the buffer thread
    //if (buffer) {
    //    globus_free(buffer);
    //}

    lfs_handle->outstanding--;
    if (!is_done(lfs_handle)) {
        // Request more transfers.
        lfs_dispatch_write(lfs_handle);
    } else if (lfs_handle->outstanding == 0) {
        // No I/O in-flight, clean-up.
        lfs_dump_buffers_unbatched(lfs_handle);
        rc = close_and_clean(lfs_handle, rc);
        if (!lfs_handle->sent_finish) {
            globus_gridftp_server_finished_transfer(op, lfs_handle->done_status);
            lfs_handle->sent_finish = GLOBUS_TRUE;
        }
    } else if (rc != GLOBUS_SUCCESS) {
        // Don't close the file because the other transfers will want to finish up.
        // However, do set the failure status.
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
            "We failed to finish the transfer, but there are %i outstanding writes left over.\n",
            lfs_handle->outstanding);
        if (!lfs_handle->sent_finish) {
            globus_gridftp_server_finished_transfer(op, lfs_handle->done_status);
            lfs_handle->sent_finish = GLOBUS_TRUE;
        }
    } else {
        // Nothing to do if we are done and there was no error, but outstanding transfers exist.
    }
    globus_mutex_unlock(lfs_handle->mutex);
}

/*************************************************************************
 *  lfs_dispatch_write
 *  -------------------
 *  Create requests for additional write operations.
 *  Note: The lfs_handle mutex *must* be locked prior to calling
 *************************************************************************/
static
void
lfs_dispatch_write(
    globus_l_gfs_lfs_handle_t *      lfs_handle)
{
    globus_byte_t *                     buffer;
    globus_result_t                     rc = GLOBUS_SUCCESS;

    GlobusGFSName(lfs_dispatch_write);
/*
    if (is_done(lfs_handle)) {
        return;
    }
*/
    //globus_gridftp_server_get_optimal_concurrency(lfs_handle->op,
    //                                             &lfs_handle->optimal_count);
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP,
        "lfs_dispatch_write; outstanding %d, optimal %d.\n",
        lfs_handle->outstanding, lfs_handle->optimal_count);

    while (lfs_handle->outstanding < lfs_handle->optimal_count)  {

        buffer = globus_malloc(lfs_handle->block_size);
        if (buffer == NULL) {
            MemoryError(lfs_handle, "Fail to allocate buffer for LFS data.", rc);
            goto cleanup;
        }

        rc = globus_gridftp_server_register_read(lfs_handle->op,
            buffer, lfs_handle->block_size, lfs_handle_write_op,
            lfs_handle);

        if (rc != GLOBUS_SUCCESS) {
            //GenericError(lfs_handle, "globus_gridftp_server_register_read() fail", rc);
            goto cleanup;
        }
        lfs_handle->outstanding++;

    }

cleanup:
    if (rc != GLOBUS_SUCCESS) {
        set_done(lfs_handle, rc);
        if (!lfs_handle->sent_finish) {
            globus_gridftp_server_finished_transfer(lfs_handle->op, lfs_handle->done_status);
        }
    }
}

