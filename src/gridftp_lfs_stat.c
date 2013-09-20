
#include "gridftp_lfs.h"
#include <grp.h>

/* Forward decls for this file.
 * Copied from the Globus file plugin implementation.
 */
static void
globus_l_gfs_file_partition_path(
    const char *                        pathname,
    char *                              basepath,
    char *                              filename);

static void
globus_l_gfs_file_destroy_stat(
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count);

static void
globus_l_gfs_file_copy_stat(
    globus_gfs_stat_t *                 stat_object,
    struct stat *                      fileInfo,
    const char *                        filename,
    const char *                        symlink_target);

// callaback needed from readdir stuff
int fill_from_fuse(
        void *              buf,
        const char *        name,
        const struct stat * stbuf,
        off_t               off)
{
    // Readdir calls this once per directory entry
    globus_l_gfs_file_copy_stat(
        (globus_gfs_stat_t *) buf + off, 
        stbuf, 
        name, 
        NULL);
    return 0;
}
int dummy_filler(
        void *              buf,
        const char *        name,
        const struct stat * stbuf,
        off_t               off)
{
    off_t temp = *((off_t *)buf) + 1;
    *((off_t*)buf) = temp;
    return 0;
}
/*************************************************************************
 *  stat
 *  ----
 *  This interface function is called whenever the server needs 
 *  information about a given file or resource.  It is called then an
 *  LIST is sent by the client, when the server needs to verify that 
 *  a file exists and has the proper permissions, etc.
 ************************************************************************/
void
lfs_stat_gridftp(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    globus_result_t                     result;
    globus_gfs_stat_t *                 stat_array;
    int                                 stat_count = 0;
    char                                basepath[MAXPATHLEN];
    char                                filename[MAXPATHLEN];
    char *                              PathName;
    globus_l_gfs_lfs_handle_t *       lfs_handle;
    GlobusGFSName(globus_l_gfs_lfs_stat);

    lfs_handle = (globus_l_gfs_lfs_handle_t *) user_arg;
    PathName=stat_info->pathname;
    while (PathName[0] == '/' && PathName[1] == '/')
    {
        PathName++;
    }
    if (strncmp(PathName, lfs_handle->mount_point, lfs_handle->mount_point_len)==0) {
        PathName += lfs_handle->mount_point_len;
    }
    while (PathName[0] == '/' && PathName[1] == '/')
    {   
        PathName++;
    }

    snprintf(err_msg, MSG_SIZE, "Going to do stat on file %s.\n", PathName);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);
 

    struct stat fileInfo;
    int retval = lfs_stat(PathName, &fileInfo);
    if (retval == -ENOENT) {
        result = GlobusGFSErrorSystemError("Stat: file oesn't exist", ENOENT);
        goto error_stat1;
    } else if (retval != 0) {
        result = GlobusGFSErrorSystemError("Stat: unknown error", 1);
        goto error_stat1;
    }
    snprintf(err_msg, MSG_SIZE, "Finished LFS stat operation.\n");
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);

    mode_t mode = fileInfo.st_mode;

    globus_l_gfs_file_partition_path(PathName, basepath, filename);
   
    // TODO: cleanup of fileInfo is pretty horrid.
 
    if(!S_ISDIR(mode) || stat_info->file_only)
    {
        stat_array = (globus_gfs_stat_t *)
            globus_malloc(sizeof(globus_gfs_stat_t));
        if(!stat_array)
        {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc1;
        }
        
        globus_l_gfs_file_copy_stat(
            stat_array, &fileInfo, filename, NULL);
        lfsFreeFileInfo(fileInfo, 1);
        stat_count = 1;
    }
    else
    {
        int i, dirfd, retval;
        struct fuse_file_info dirInfo;
        dirfd = retval = 0;
        retval = lfs_opendir(PathName, &dirInfo);
        //lfsFileInfo * dir = lfsListDirectory(lfs_handle->fs, PathName, &stat_count);
        if (retval == -ENOENT) {
            result = GlobusGFSErrorSystemError("Stat: path doesn't exist", ENOENT);
            goto error_open;
        } else if (retval < 0) {
            result = GlobusGFSErrorSystemError("Unknown opendir error", retval);
            goto error_open;
        }
        //dirInfo->fh
        off_t dirCount = 0;
        // dummy_filler will increment dirCount
        retval = lfs_readdir(PathName, &dirCount, dummy_filler, 0, &dirInfo); 
        stat_array = (globus_gfs_stat_t *) \
                                globus_malloc(\
                                    sizeof(globus_gfs_stat_t) * dirCount);
        stat_count = dirCount;
        if(!stat_array)
        {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc1;
        }
        if (dirCount == 0)
        {
            result = GlobusGFSErrorSystemError("Stat: got an empty directory?", ENOENT);
            goto error_read;
        }
        // have the array initialized, fill it
        retval = lfs_readdir(PathName, stat_array, fill_from_fuse, 0, &dirInfo);
        if (retval == -ENOENT) {
            result = GlobusGFSErrorSystemError("Stat: path doesn't exist", ENOENT);
            goto error_read;
        } else if (retval < 0) {
            result = GlobusGFSErrorSystemError("Unknown opendir error", retval);
            goto error_read;
        }
    }
    
    globus_gridftp_server_finished_stat(
        op, GLOBUS_SUCCESS, stat_array, stat_count);
    
    
    globus_l_gfs_file_destroy_stat(stat_array, stat_count);
    return;

error_read:
    globus_l_gfs_file_destroy_stat(stat_array, stat_count);
    
error_alloc2:
error_open:
error_alloc1:
error_stat1:
    globus_gridftp_server_finished_stat(op, result, NULL, 0);

/*    GlobusGFSFileDebugExitWithError();  */
}

/* basepath and filename must be MAXPATHLEN long
 * the pathname may be absolute or relative, basepath will be the same */
static void
globus_l_gfs_file_partition_path(
    const char *                        pathname,
    char *                              basepath,
    char *                              filename)
{
    char                                buf[MAXPATHLEN];
    char *                              filepart;
    GlobusGFSName(globus_l_gfs_file_partition_path);

    strncpy(buf, pathname, MAXPATHLEN);

    buf[MAXPATHLEN - 1] = '\0';

    filepart = strrchr(buf, '/');
    while(filepart && !*(filepart + 1) && filepart != buf)
    {
        *filepart = '\0';
        filepart = strrchr(buf, '/');
    }

    if(!filepart)
    {
        strcpy(filename, buf);
        basepath[0] = '\0';
    }
    else
    {
        if(filepart == buf)
        {
            if(!*(filepart + 1))
            {
                basepath[0] = '\0';
                filename[0] = '/';
                filename[1] = '\0';
            }
            else
            {
                *filepart++ = '\0';
                basepath[0] = '/';
                basepath[1] = '\0';
                strcpy(filename, filepart);
            }
        }
        else
        {
            *filepart++ = '\0';
            strcpy(basepath, buf);
            strcpy(filename, filepart);
        }
    }
}

static void
globus_l_gfs_file_destroy_stat(
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count)
{
    int                                 i;
    GlobusGFSName(globus_l_gfs_file_destroy_stat);

    for(i = 0; i < stat_count; i++)
    {
        if(stat_array[i].name != NULL)
        {
            globus_free(stat_array[i].name);
        }
        if(stat_array[i].symlink_target != NULL)
        {
            globus_free(stat_array[i].symlink_target);
        }
    }
    globus_free(stat_array);
}

static void
globus_l_gfs_file_copy_stat(
    globus_gfs_stat_t *                 stat_object,
    struct stat *                      fileInfo,
    const char *                        filename,
    const char *                        symlink_target)
{
    struct passwd *result;
    struct group *gresult;
    GlobusGFSName(globus_l_gfs_file_copy_stat);

    stat_object->mode     = (S_ISDIR(fileInfo->st_mode)) ? (S_IFDIR | fileInfo->st_mode) :  (S_IFREG | fileInfo->st_mode);
    stat_object->nlink    = (S_ISDIR(fileInfo->st_mode)) ? 3 : 1;
    stat_object->uid = fileInfo->st_uid;
    stat_object->gid = fileInfo->st_gid;
    stat_object->size     = (S_ISDIR(fileInfo->st_mode)) ? 4096 : fileInfo->st_size;
    stat_object->mtime    = fileInfo->st_mtime;
    stat_object->atime    = fileInfo->st_atime;
    stat_object->ctime    = fileInfo->st_ctime;
    stat_object->dev      = fileInfo->st_dev;
    stat_object->ino      = fileInfo->st_ino;

    stat_object->name = NULL;
    if(filename && *filename)
    {
        const char * real_filename = filename;
        while (strchr(real_filename, '/')) {
            if (*(real_filename+1) != '\0') {
                real_filename++;
            } else {
                break;
            }
        }
        stat_object->name = strdup(real_filename);
    }
    if(symlink_target && *symlink_target)
    {
        stat_object->symlink_target = strdup(symlink_target);
    }
    else
    {
        stat_object->symlink_target = NULL;
    }
}

