
/*
 * Portions of this file Copyright 2008-2011 University of Nebraska-Lincoln
 *
 * This file is licensed under the
 * terms of the Apache Public License, found at
 * http://www.apache.org/licenses/LICENSE-2.0.html.
 */


#ifndef _GRIDFTP_LFS_H_
#define _GRIDFTP_LFS_H_

#include <lio/lio.h>
#include <lio/lio_fuse.h>
#include <stdint.h>
#include <openssl/md5.h>
#include "zlib.h"

#include <globus/globus_gridftp_server.h>
#include "gridftp_lfs_error.h"
#include "statsd-client.h"
#include "ex3_compare.h"
#include "interval_skiplist.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define ADVANCE_SLASHES(x) {while (x[0] == '/' && x[1] == '/') x++;}


// Note that we hide all symbols from the global scope except the module itself.
#pragma GCC visibility push(hidden)

// Data types and globals
#define default_id 00;

// Global statsd socket
extern statsd_link * lfs_statsd_link;
#define STATSD_COUNT(name, count) if (lfs_statsd_link) { statsd_count(lfs_statsd_link, name, count, 1.0); }
#define STATSD_TIMER_END(name, variable) time_t variable ## _end; if (lfs_statsd_link) { time(& variable ## _end); statsd_timing(lfs_statsd_link, name, (int) (difftime(variable ## _end, variable) * 1000.0)); }
#define STATSD_TIMER_RESET(variable) variable = apr_time_now()
#define STATSD_TIMER_POST(name, variable) if (lfs_statsd_link) { statsd_timing(lfs_statsd_link, name, (int) apr_time_msec(apr_time_now()-variable)); }

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


typedef struct {
    ex_off_t offset;
    ex_off_t len;
    uLong adler32;
} gftp_adler32_t;

// ** Forward declaration
struct globus_l_gfs_handle_s;
typedef struct globus_l_gfs_lfs_handle_s lfs_handle_t;

typedef struct {     //** Buffer used for writing
    char *      buffer;
    ex_off_t    offset;
    ex_off_t    nbytes;
    int         eof;
    uLong       adler32;
    lfs_handle_t *lfs_handle;
} lfs_buffer_t;

typedef struct {
    Stack_t *stack;
    apr_thread_mutex_t *lock;
    apr_thread_cond_t *cond;
} lfs_queue_t;

struct globus_l_gfs_lfs_handle_s {
    apr_pool_t *          mpool;                // ** APR memory pool
    apr_thread_cond_t *   cond;                 // ** GLobal cond
    apr_thread_mutex_t *  lock;                 // ** GLobal lock
    apr_thread_t *        backend_thread;       // ** The backend reading or writing thread to LIO
    apr_thread_t **       cksum_thread;         // ** Checksum worker threads
    atomic_int_t          inflight_count;       // ** Number of inflight buffers
    atomic_int_t          io_count;             // ** Number of data blocks containing data
    char                  adler32_human[2*sizeof(uLong)+1];  // ** Human readable version of adler32 checksum
    char *                data_buffer;          // ** Pointer to athe actual large data buffer which gets parcelled out in buffers
    char *                debug_level;
    char *                expected_checksum;    // ** Expected checksum from GridFTP
    char *                expected_checksum_alg;// ** Expected checksum algorithm from GridFTP
    char *                lfs_config;           // ** LIO config file
    char *                local_host;           // ** My hostname
    char *                log_filename;         // ** LIO gridftp log filename
    char *                mount_point;          // ** LFS mount prefix
    char *                pathname;             // ** GridFTP name
    char *                pathname_munged;      // ** Munged LFS path
    char *                remote_host;          // ** The remote host connecting to us.
    char *                syslog_host;          // **
    char *                syslog_msg;           // ** Message printed out to syslog.
    char *                username;             // ** Gridftp username
    double                high_water_fraction;  // ** Flush when the used buffer count gets above this
    double                low_water_fraction;   // ** Need to get the used buffer count below this when flushing
    ex_off_t              buffer_size;          // ** Individual buffer size
    ex_off_t              default_size;         // ** Default file size to create if none given
    ex_off_t              gridftp_buffer_size;  // ** This is what GridFTP wants to send
    ex_off_t              last_block_offset;    // ** Offset of the last block
    ex_off_t              total_buffer_size;    // ** Total amount of buffer space to use for caching
    globus_cond_t *       globus_cond;          // ** Globus lock just used in the interface layer between LIO/Globus
    globus_gfs_operation_t op;                  // ** Send/Recv globus operation
    globus_mutex_t *      globus_lock;          // ** Globus lock just used in the interface layer between LIO/Globus
    globus_off_t          offset;               // ** offset on gridftp side
    globus_off_t          op_length;            // ** Length of the requested read/write size
    globus_result_t       done_status;          // ** Return code for GridFTP
    int                   do_calc_adler32;      // ** Do calculate adler32 for writes if = 1
    int                   done;                 // ** Finished flag
    int                   fd_posix;             // ** POSIX file handle
    int                   high_water_flush;     // ** Flush when the used buffer count gets above this
    int                   is_lio;               // ** (=1) if the file is an LFS file
    int                   log_autoremove;       // ** Automatically remove the gridftp log(=1)
    int                   low_water_flush;      // ** Need to get the used buffer count below this when flushing
    int                   n_buffers;            // ** Total number of buffers
    int                   n_cksum_threads;      // ** Number of checksum threads
    int                   load_limit;
    int                   send_stages;          // ** Number of read stages
    lfs_buffer_t *        buffers;              // ** Array of write buffers
    lfs_queue_t           backend_stack;        // ** backend write/read buffer stack
    lfs_queue_t           cksum_stack;          // ** Buffer's that need checksummed stack
    lio_config_t *        fs;                   // ** LIO context
    lio_fd_t *            fd;                   // ** LIO file handle
    unsigned int          mount_point_len;
};

#define MSG_SIZE 1024
extern char err_msg[MSG_SIZE];

// figure out if a path if LFS based
bool is_lfs_path(const lfs_handle_t * lfs_handle, const char * path);
globus_byte_t * lfs_get_free_buffer(lfs_handle_t *lfs_handle, globus_size_t nbytes);
globus_result_t lfs_mark_buffer_ready(lfs_handle_t * lfs_handle, globus_byte_t* buffer, globus_off_t offset, globus_size_t nbytes);
globus_size_t count_blocks(lfs_handle_t * lfs_handle, unsigned char state);
globus_size_t count_total_blocks(lfs_handle_t * lfs_handle, unsigned char state);

void lfs_queue_init(lfs_queue_t *s, apr_pool_t *mpool);
void lfs_queue_teardown(lfs_queue_t *s);

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
    lfs_destroy_checksums(
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
void lfs_trev(globus_gfs_event_info_t *, void *);
inline void set_done(lfs_handle_t *, globus_result_t);
int  lfs_activate(void);
int  lfs_deactivate(void);
void lfs_command(globus_gfs_operation_t, globus_gfs_command_info_t *, void *);
void lfs_start(globus_gfs_operation_t, globus_gfs_session_info_t *);

void lfs_destroy_gridftp(void * user_arg);

void lfs_start(globus_gfs_operation_t op,
                globus_gfs_session_info_t * session_info);
lfs_handle_t * lfs_gridftp_load_config(globus_gfs_session_info_t * session_info,
                                       char ** errstr);
void handle_errstr(char ** errstr, char * error);
void lfs_cluster_sort(int *cluster_order, ex_off_t *cluster_weight,
                        int n_clusters);
void lfs_cluster_weight(interval_skiplist_t *written_intervals,
                        lfs_cluster_t *cluster, ex_off_t *cluster_weight,
                        int n_clusters);
void lfs_cluster(list_t *sorted_buffers, lfs_cluster_t *cluster, 
                        int *n_clusters);
void human_readable_adler32(char *adler32_human, uLong adler32);
void *lfs_cksum_thread(apr_thread_t *th, void *data);
#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif

