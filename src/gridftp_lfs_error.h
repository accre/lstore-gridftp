// *********************************************************************************************************
// ****** NOTE: In order for these macros to work in your code you must have called            *************
// ******       the GlobusGFSName(your-func-here) macro to define the local _gfs_name variable *************
// *********************************************************************************************************

// Messages should not end with newline
#define MESSAGE_BUFFER_SIZE 1024

#define SomeError(lfs_handle, msg) \
    char * formatted_msg = (char *)globus_malloc(MESSAGE_BUFFER_SIZE); \
    char * user = lfs_handle ? lfs_handle->username : NULL; \
    char * path = lfs_handle ? lfs_handle->pathname : NULL; \
    char * host = lfs_handle ? lfs_handle->local_host : NULL; \
    snprintf(formatted_msg, MESSAGE_BUFFER_SIZE, "%s (host=%s, user=%s, path=%s)", msg, host, user, path); \
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "%s\n", formatted_msg);
    

#define GenericError(lfs_handle, msg, rc) \
    SomeError(lfs_handle, msg) \
    rc = GlobusGFSErrorGeneric(formatted_msg); \
    globus_free(formatted_msg);


#define SystemError(lfs_handle, msg, rc) \
    SomeError(lfs_handle, msg) \
    rc = GlobusGFSErrorSystemError(formatted_msg, errno); \
    globus_free(formatted_msg);


#define MemoryError(lfs_handle, msg, rc) \
    SomeError(lfs_handle, msg) \
    rc = GlobusGFSErrorMemory(formatted_msg); \
    globus_free(formatted_msg);

