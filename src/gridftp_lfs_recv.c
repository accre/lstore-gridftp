#include <errno.h>
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

    GlobusGFSName(close_and_clean);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Trying to close file in LFS; zero outstanding blocks.\n");
    if (is_close_done(lfs_handle)) {
        return lfs_handle->done_status;
    }

    // Only close the file for successful transfers and if the handle is valid.
    // This might cause long-term leaks, but Java has been crash-y when closing
    // invalid handles.
    if ((rc == GLOBUS_SUCCESS) &&
            (lfs_handle->fd != NULL) && (lfs_handle->fs != NULL) && 
            (lfsCloseFile(lfs_handle->fs, lfs_handle->fd) == -1)) {
        GenericError(lfs_handle, "Failed to close file in LFS.", rc);
        lfs_handle->fd = NULL;
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
        if ((lfs_handle->done_status == GLOBUS_SUCCESS) && (rc == GLOBUS_SUCCESS)) {
            rc = lfs_save_checksum(lfs_handle);
        }
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
    int num_replicas = 0;
    char * replica_map = getenv("GRIDFTP_LFS_REPLICA_MAP");
    if (!replica_map) return num_replicas;

    char *map_line = (char *)globus_malloc(DEFAULT_LINE_LENGTH);
    if (!map_line) return num_replicas;

    size_t line_length = DEFAULT_LINE_LENGTH;
    char *map_line_index;
    const char *filename_index;
    ssize_t bytes_read = 0;
    FILE *replica_map_fd = fopen(replica_map, "r");
    if (replica_map_fd == NULL) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Could not open %s for reading.\n", replica_map);
        free(map_line);
        return num_replicas;
    }
    while ( (bytes_read = getline(&map_line, &line_length, replica_map_fd)) > -1) {
        map_line_index = map_line;
        filename_index = path;
        // Skip comment lines
        if (map_line && map_line[0] == '#') continue;

        // Skip over leading whitespace
        while(*map_line_index && *map_line_index == ' ') map_line_index++;

        // Try and match the map line and filename
        while(*map_line_index && *filename_index && 
                (*map_line_index == *filename_index)) {
            map_line_index++;
            filename_index++;
        }

        /*
        * If we've reached the end of the pattern, then we've found
        * a match with the lfs filename.  Snarf up the # replicas
        * from the remainder of the line.
        */
        while (*map_line_index && 
                (*map_line_index == ' ' || 
                 *map_line_index == '=' || 
                 *map_line_index == '\t')) {
            map_line_index++;
        }
        if (sscanf(map_line_index, "%d", &num_replicas) != 1) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                "Unable to determine the number of replicas for %s", map_line);
        }
    }

    if (map_line != NULL) free(map_line);
    fclose(replica_map_fd);

    return num_replicas;
}

/*************************************************************************
 * prepare_handle
 * --------------
 * Do all the prep work for preparing an lfs_handle to be opened
 *************************************************************************/
globus_result_t prepare_handle(lfs_handle_t *lfs_handle) {
    GlobusGFSName(prepare_handle);
    globus_result_t rc;
    lfs_handle->sent_finish = GLOBUS_FALSE;

    const char *path = lfs_handle->pathname;

    ADVANCE_SLASHES(path);
    if (strncmp(path, lfs_handle->mount_point, lfs_handle->mount_point_len) == 0) {
        path += lfs_handle->mount_point_len;
    }
    ADVANCE_SLASHES(path);

    lfs_handle->pathname = (char*)globus_malloc(strlen(path)+1);
    if (!lfs_handle->pathname) {MemoryError(lfs_handle, "Unable to make a copy of the path name.", rc); return rc;}
    strcpy(lfs_handle->pathname, path);

    lfs_handle->expected_cksm = NULL;
  
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "We are going to open file %s.\n", lfs_handle->pathname);
    lfs_handle->outstanding = 0;
    lfs_handle->done = GLOBUS_FALSE;
    lfs_handle->done_status = GLOBUS_SUCCESS;
    globus_gridftp_server_get_block_size(lfs_handle->op, &lfs_handle->block_size);


    // LFS cannot start transfers in the middle of a file.
    globus_gridftp_server_get_write_range(lfs_handle->op,
                                          &lfs_handle->offset,
                                          &lfs_handle->op_length);

    if (lfs_handle->offset) {GenericError(lfs_handle, "Non-zero offsets are not supported.", rc); return rc;}

    globus_gridftp_server_get_optimal_concurrency(lfs_handle->op,
                                                  &lfs_handle->optimal_count);
    lfs_handle->buffer_count = lfs_handle->optimal_count;
    lfs_handle->nbytes = globus_malloc(lfs_handle->buffer_count*sizeof(globus_size_t));
    lfs_handle->offsets = globus_malloc(lfs_handle->buffer_count*sizeof(globus_off_t));
    lfs_handle->used = globus_malloc(lfs_handle->buffer_count*sizeof(short));
    int i;
    for (i=0; i<lfs_handle->buffer_count; i++)
        lfs_handle->used[i] = 0;
    lfs_handle->buffer = globus_malloc(lfs_handle->buffer_count*lfs_handle->block_size*sizeof(globus_byte_t));
    if (lfs_handle->buffer == NULL || lfs_handle->nbytes==NULL || 
            lfs_handle->offsets==NULL || lfs_handle->used==NULL) {
        MemoryError(lfs_handle, "Memory allocation error.", rc);
        return rc;
    }
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

    GlobusGFSName(lfs_recv);


    lfs_handle = (lfs_handle_t *) user_arg;
    globus_mutex_lock(lfs_handle->mutex);

    lfs_handle->op = op;
    lfs_handle->pathname = transfer_info->pathname;

    if ((rc = prepare_handle(lfs_handle)) != GLOBUS_SUCCESS) goto cleanup;

    if (transfer_info->expected_checksum) {
        lfs_handle->expected_cksm =
            globus_libc_strdup(transfer_info->expected_checksum);
    }
    if (transfer_info->expected_checksum_alg) {
        lfs_parse_checksum_types(lfs_handle, transfer_info->expected_checksum_alg);
    }

    lfs_initialize_checksums(lfs_handle);

    int num_replicas = determine_replicas(lfs_handle->pathname);
    if (!num_replicas && lfs_handle->replicas) num_replicas = lfs_handle->replicas;

    if (num_replicas == 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Open file %s.\n", lfs_handle->pathname);
    } else {
	globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Open file %s with %d replicas.\n",
            lfs_handle->pathname, num_replicas);
    }
    
    struct stat fileInfo;
    if (lfs_stat(lfs_handle->pathname, (&fileInfo)) !=0) {
        GenericError(lfs_handle, "Can't stat pathname.", rc);
        goto cleanup;
    } else if (S_ISDIR(fileInfo.st_mode)) {
        GenericError(lfs_handle, "Destination path is a directory; cannot overwrite.", rc);
        goto cleanup;
    }

    //lfs_handle->fd = lfsOpenFile(lfs_handle->fs, lfs_handle->pathname, O_WRONLY, 0, num_replicas, 0);
    int retval = lfs_open(lfs_handle->pathname, lfs_handle->fd);
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

    // First, see if we can dump this block immediately.
    if (offset == lfs_handle->offset) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, "Dumping this block immediately.\n");
        if ((rc = lfs_dump_buffer_immed(lfs_handle, buffer, nbytes)) != GLOBUS_SUCCESS) {
            goto cleanup;
        }
    } else {
        // Try to store the buffer into memory.
        if ((rc = lfs_store_buffer(lfs_handle, buffer, offset, nbytes)) != GLOBUS_SUCCESS) {
            goto cleanup;
        }
    }

    // Try to write out as many buffers as we can to LFS.
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

    if (buffer) {
        globus_free(buffer);
    }
    lfs_handle->outstanding--;

    if (!is_done(lfs_handle)) {
        // Request more transfers.
        lfs_dispatch_write(lfs_handle);
    } else if (lfs_handle->outstanding == 0) {
        // No I/O in-flight, clean-up.
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
    globus_gridftp_server_get_optimal_concurrency(lfs_handle->op,
                                                  &lfs_handle->optimal_count);
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

