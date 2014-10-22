
/*
 * Portions of this file Copyright 2008-2011 University of Nebraska-Lincoln
 *
 * This file is licensed under the
 * terms of the Apache Public License, found at
 * http://www.apache.org/licenses/LICENSE-2.0.html.
 */


#include <lio/lio.h>
#include <lio/lio_fuse.h>
#include <stdint.h>
#include <openssl/md5.h>

#include <globus/globus_gridftp_server.h>
#include "gridftp_lfs_error.h"
#include "statsd-client.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// Note that we hide all symbols from the global scope except the module itself.
#pragma GCC visibility push(hidden)

// Data types and globals
#define default_id 00;

// Global statsd socket
extern statsd_link * lfs_statsd_link;
#define STATSD_COUNT(name, count) if (lfs_statsd_link) { statsd_count(lfs_statsd_link, name, count, 1.0); }
#define STATSD_TIMER_START(variable) time_t variable; time(& variable );
#define STATSD_TIMER_END(name, variable) time_t variable ## _end; if (lfs_statsd_link) { time(& variable ## _end); statsd_timing(lfs_statsd_link, name, (int) (difftime(variable ## _end, variable) * 1000.0)); }
#define STATSD_TIMER_RESET(variable) time(& variable);

// Note: This really should be const, but the globus module activation code
// doesn't have this as const.
extern globus_version_t gridftp_lfs_local_version;

#define LFS_CKSM_TYPE_CKSUM   1
#define LFS_CKSM_TYPE_CRC32   2
#define LFS_CKSM_TYPE_ADLER32 4
#define LFS_CKSM_TYPE_MD5     8

#define LFS_BUFFER_FREE 0
#define LFS_BUFFER_FILLING 1
#define LFS_BUFFER_READY 2
#define LFS_BUFFER_PENDING_WRITE 3
#define LFS_BUFFER_WRITING 4


typedef struct lfs_queue_item_s {
    globus_byte_t * buffer;
    globus_size_t nbytes;
    globus_off_t offset;
    short buffer_in_file;
    struct lfs_queue_item_s * next;
} lfs_queue_item_t;

typedef struct lfs_buffer_s {
    globus_size_t total_buffer_size;
    globus_size_t block_size;
    globus_byte_t * buffer;
    globus_off_t * offsets;
    globus_size_t * nbytes;
    unsigned char * used;
    struct lfs_buffer_s * next;
} lfs_buffer_t;


typedef struct globus_l_gfs_lfs_handle_s
{
    char *                              pathname;
    char *                              pathname_munged;
    // used to be the HDFS filesystem handle
    struct lio_fuse_t *                 fs;
    // used to be the HDFS filehandle
    struct fuse_file_info *             fd;
    int                                 fd_posix;
    globus_size_t                       block_size;
    globus_off_t                        op_length; // Length of the requested read/write size
    globus_off_t                        offset; // offset on gridftp side
    globus_off_t                        committed_offset; // offset against actual storage
    unsigned int                        done;
    globus_result_t                     done_status; // The status of the finished transfer.
    globus_bool_t                       sent_finish; // Whether or not we have sent the client an abort.
    // I should refactor this. "Queue" in this context is large, FS-friendly
    // chunks
    globus_bool_t                       queue_open; // Whether or not the queue should be open
    lfs_queue_item_t *                  queue_head;
    unsigned int                        queue_length;
    globus_off_t                        queue_offset;
    // small_queue in this context is small, gridftp/network friendly chunks
    lfs_queue_item_t *                  free_head;
    unsigned int                        free_length;
    lfs_queue_item_t *                  small_queue_head;
    unsigned int                        small_queue_length;
    globus_result_t                     background_status;
    unsigned int                        starved_ops;
    unsigned int                        blocked_ops;
    unsigned int                        concurrent_writes;
    globus_size_t                       queued_bytes;
    globus_size_t                       max_queued_bytes;
    pthread_t *                         write_pool;
    globus_gfs_operation_t              op;
    globus_byte_t *                     buffer; // to be deprecated. one big char *
    globus_byte_t **                    buffer_pointers; // list of pointers to char *s globus gave us
    globus_off_t *                      offsets; // The offset of each buffer.
    globus_size_t *                     nbytes; // The number of bytes in each buffer.
    unsigned int                        preferred_write_size; // what to prefer to send to LFS
    unsigned int                        write_size_buffers; // how many of these chunks should we keep around
    unsigned int                        min_buffer_count; // calculated after we know block size
    short *                             used;
    int                                 optimal_count;
    unsigned int                        stall_buffer_count;
    unsigned int                        max_buffer_count;
    unsigned int                        max_file_buffer_count;
    unsigned int                        buffer_count; // Number of buffers we currently maintain in memory waiting to be written to LFS.
    unsigned int                        outstanding;
    globus_mutex_t *                    mutex;
    globus_mutex_t *                    buffer_mutex;
    globus_mutex_t *                    offset_mutex;
    globus_mutex_t *                    checksum_mutex;
    globus_cond_t *                     offset_cond;
    globus_cond_t *                     queued_cond;    // triggered when something is added to the queue
    globus_cond_t *                     dequeued_cond;  // triggered when something is popped off the queue
    unsigned int                        blocked_writers;
    int                                 port;
    char *                              lfs_config;
    char *                              log_filename;
    char *                              host;
    char *                              mount_point;
    unsigned int                        mount_point_len;
    unsigned int                        replicas;
    char *                              username;
    char *                              tmp_file_pattern;
    int                                 tmpfilefd;
    globus_bool_t                       using_file_buffer;
    char *                              syslog_host; // The host to send syslog message to.
    char *                              remote_host; // The remote host connecting to us.
    char *                              local_host;  // Our local hostname.
    char *                              syslog_msg;  // Message printed out to syslog.
    unsigned int                        io_block_size;
    unsigned long long                  io_count;
    globus_bool_t                       eof;

    // Checksumming support
    char *                              expected_cksm;
    const char *                        cksm_root;
    unsigned char                       cksm_types;
    MD5_CTX                             md5;
    char                                md5_output[MD5_DIGEST_LENGTH];
    char                                md5_output_human[MD5_DIGEST_LENGTH*2+1];
    unsigned char                       adler32_human[2*sizeof(uint32_t)+1];
    uint32_t                            crc32;
    uint32_t                            cksum;
    
    // new buffer variables
    lfs_buffer_t *                      buffer_head;
    // new checksum support
    unsigned long                        checksum_length;
    globus_off_t * checksum_offsets;
    globus_size_t * checksum_lens; 
    unsigned long checksum_index;
    uint32_t * adler32; 
    uint32_t adler32_combined;
    // Statsd support
    statsd_link *                       statsd_link;
} globus_l_gfs_lfs_handle_t;
typedef globus_l_gfs_lfs_handle_t lfs_handle_t;

#define MSG_SIZE 1024
extern char err_msg[MSG_SIZE];

// figure out if a path if LFS based
bool is_lfs_path(const globus_l_gfs_lfs_handle_t * lfs_handle, const char * path);
globus_byte_t * lfs_get_free_buffer(lfs_handle_t *lfs_handle, globus_size_t nbytes);
globus_result_t lfs_mark_buffer_ready(lfs_handle_t * lfs_handle, globus_byte_t* buffer, globus_off_t offset, globus_size_t nbytes);
globus_size_t count_blocks(lfs_handle_t * lfs_handle, unsigned char state);
// Function for sending a file to the client.
void
lfs_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg);


// Function for receiving a file from the client.
void
lfs_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg);

// Buffer management for writes
globus_result_t
lfs_store_buffer(
    globus_l_gfs_lfs_handle_t * lfs_handle,
    globus_byte_t* buffer,
    globus_off_t offset,
    globus_size_t nbytes);

globus_result_t
lfs_dump_buffers(
    globus_l_gfs_lfs_handle_t *      lfs_handle,
    int                              dump_partial);

globus_result_t
lfs_dump_buffers_unbatched(
    globus_l_gfs_lfs_handle_t *      lfs_handle);

globus_result_t
lfs_dump_buffer_immed(
        lfs_handle_t * lfs_handle, 
        ex_iovec_t * iovec_file, 
        tbuffer_t * buffer,
        unsigned int n_ops);

globus_size_t lfs_used_buffer_count(globus_l_gfs_lfs_handle_t * lfs_handle);
globus_result_t start_writers(lfs_handle_t *lfs_handle);
globus_result_t stop_writers(lfs_handle_t *lfs_handle);

//// Buffer management for reads
// Buffer management for reads
 globus_result_t
allocate_buffers(
    lfs_handle_t *    lfs_handle,
    globus_size_t             num_buffers);

 globus_ssize_t
find_buffer(
    lfs_handle_t *    lfs_handle,
    globus_byte_t *    buffer);

 globus_ssize_t
find_empty_buffer(
    lfs_handle_t *    lfs_handle);

 void
disgard_buffer(
    lfs_handle_t * lfs_handle,
    globus_ssize_t idx);

void
remove_file_buffer(
    lfs_handle_t * lfs_handle);
// Metadata-related functions
void
lfs_stat_gridftp(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg);

// Some helper functions
// All must be called with the lfs_handle mutex held
void
set_done(
    lfs_handle_t *    lfs_handle,
    globus_result_t    rc);

void
set_close_done(
    lfs_handle_t *    lfs_handle,
    globus_result_t    rc);

globus_bool_t
is_done(
    lfs_handle_t *    lfs_handle);

globus_bool_t
is_close_done(
    lfs_handle_t *    lfs_handle);

// Checksumming support
void
lfs_parse_checksum_types(
    lfs_handle_t *    lfs_handle,
    const char *       types);

void
lfs_initialize_checksums(
    lfs_handle_t *    lfs_handle);

void
lfs_update_checksums(
    lfs_handle_t *    lfs_handle,
    globus_byte_t *    buffer,
    globus_size_t      nbytes,
    globus_off_t       offset);

void
lfs_finalize_checksums(
    lfs_handle_t *    lfs_handle);

globus_result_t
lfs_save_checksum(
    lfs_handle_t *    lfs_handle);

globus_result_t
lfs_get_checksum(
    lfs_handle_t *    lfs_handle,
    const char *       pathname,
    const char *       requested_cksm,
    char **            cksm_value);

#pragma GCC visibility pop

