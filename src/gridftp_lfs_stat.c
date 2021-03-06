
#include "gridftp_lfs.h"
#include "type_malloc.h"
#include <grp.h>

/* Forward decls for this file.
 * Copied from the Globus file plugin implementation.
 */
static void globus_l_gfs_file_partition_path(const char * pathname,
                                             char * basepath,
                                             char * filename);

static void globus_l_gfs_file_destroy_stat(globus_gfs_stat_t * stat_array,
                                           int stat_count);

static void globus_l_gfs_file_copy_stat(globus_gfs_stat_t * stat_object,
                                        struct stat * fileInfo,
                                        const char * filename,
                                        const char * symlink_target);

/*************************************************************************
 *  stat
 *  ----
 *  This interface function is called whenever the server needs
 *  information about a given file or resource.  It is called then an
 *  LIST is sent by the client, when the server needs to verify that
 *  a file exists and has the proper permissions, etc.
 ************************************************************************/
// Used for falling back to POSIX instead of LFS
void lfs_stat_gridftp_posix(globus_gfs_operation_t op,
                            globus_gfs_stat_info_t * stat_info,
                            __attribute__((unused)) void * user_arg)
{
    DIR * dir;
    char * PathName;
    char basepath[MAXPATHLEN];
    char filename[MAXPATHLEN];
    char symlink_target[MAXPATHLEN];
    globus_gfs_stat_t * stat_array;
    globus_result_t result;
    int stat_count = 0;
    struct stat stat_buf;
    GlobusGFSName(globus_l_gfs_posix_stat);
    PathName=stat_info->pathname;

    /*
       If we do stat_info->pathname++, it will cause third-party transfer
       hanging if there is a leading // in path. Don't know why. To work
       around, we replaced it with PathName.
    */
    while (PathName[0] == '/' && PathName[1] == '/') {
        PathName++;
    }

    /* lstat is the same as stat when not operating on a link */
    if(lstat(PathName, &stat_buf) != 0) {
        result = GlobusGFSErrorSystemError("stat", errno);
        goto error_stat1;
    }
    /* if this is a link we still need to stat to get the info we are
        interested in and then use realpath() to get the full path of
        the symlink target */
    *symlink_target = '\0';
    if(S_ISLNK(stat_buf.st_mode)) {
        if(stat(PathName, &stat_buf) != 0) {
            result = GlobusGFSErrorSystemError("stat", errno);
            goto error_stat1;
        }
        if(realpath(PathName, symlink_target) == NULL) {
            result = GlobusGFSErrorSystemError("realpath", errno);
            goto error_stat1;
        }
    }
    globus_l_gfs_file_partition_path(PathName, basepath, filename);

    if(!S_ISDIR(stat_buf.st_mode) || stat_info->file_only) {
        stat_array = (globus_gfs_stat_t *)
                     globus_malloc(sizeof(globus_gfs_stat_t));
        if(!stat_array) {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc1;
        }

        globus_l_gfs_file_copy_stat(stat_array, &stat_buf, filename,
                                    symlink_target);
        stat_count = 1;
    } else {
        struct dirent *                 dir_entry;
        int                             i;
        char                            dir_path[MAXPATHLEN];

        dir = opendir(PathName);
        if(!dir) {
            result = GlobusGFSErrorSystemError("opendir", errno);
            goto error_open;
        }

        stat_count = 0;
        while(globus_libc_readdir_r(dir, &dir_entry) == 0 && dir_entry) {
            stat_count++;
            globus_free(dir_entry);
        }

        rewinddir(dir);

        stat_array = (globus_gfs_stat_t *)
                     globus_malloc(sizeof(globus_gfs_stat_t) * stat_count);
        if(!stat_array) {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc2;
        }

        snprintf(dir_path, sizeof(dir_path), "%s/%s", basepath, filename);
        dir_path[MAXPATHLEN - 1] = '\0';

        for(i = 0;
                globus_libc_readdir_r(dir, &dir_entry) == 0 && dir_entry;
                i++) {
            char                        tmp_path[MAXPATHLEN];
            char                        *path;

            snprintf(tmp_path, sizeof(tmp_path), "%s/%s", dir_path, dir_entry->d_name);
            tmp_path[MAXPATHLEN - 1] = '\0';
            path=tmp_path;

            /* function globus_l_gfs_file_partition_path() seems to add two
               extra '/'s to the beginning of tmp_path. XROOTD is sensitive
               to the extra '/'s not defined in XROOTD_VMP so we remove them */
            if (path[0] == '/' && path[1] == '/') {
                path++;
            }
            while (path[0] == '/' && path[1] == '/') {
                path++;
            }
            /* lstat is the same as stat when not operating on a link */
            if(lstat(path, &stat_buf) != 0) {
                result = GlobusGFSErrorSystemError("lstat", errno);
                globus_free(dir_entry);
                /* just skip invalid entries */
                stat_count--;
                i--;
                continue;
            }
            /* if this is a link we still need to stat to get the info we are
                interested in and then use realpath() to get the full path of
                the symlink target */
            *symlink_target = '\0';
            if(S_ISLNK(stat_buf.st_mode)) {
                if(stat(path, &stat_buf) != 0) {
                    result = GlobusGFSErrorSystemError("stat", errno);
                    globus_free(dir_entry);
                    /* just skip invalid entries */
                    stat_count--;
                    i--;
                    continue;
                }
                if(realpath(path, symlink_target) == NULL) {
                    result = GlobusGFSErrorSystemError("realpath", errno);
                    globus_free(dir_entry);
                    /* just skip invalid entries */
                    stat_count--;
                    i--;
                    continue;
                }
            }
            globus_l_gfs_file_copy_stat(
                &stat_array[i], &stat_buf, dir_entry->d_name, symlink_target);
            globus_free(dir_entry);
        }

        if(i != stat_count) {
            result = GlobusGFSErrorSystemError("readdir", errno);
            goto error_read;
        }

        closedir(dir);
    }

    globus_gridftp_server_finished_stat(op, GLOBUS_SUCCESS, stat_array,
                                        stat_count);


    globus_l_gfs_file_destroy_stat(stat_array, stat_count);

    return;

error_read:
    globus_l_gfs_file_destroy_stat(stat_array, stat_count);

error_alloc2:
    closedir(dir);

error_open:
error_alloc1:
error_stat1:
    globus_gridftp_server_finished_stat(op, result, NULL, 0);

    /*    GlobusGFSFileDebugExitWithError();  */
}
void
lfs_stat_gridftp(globus_gfs_operation_t op, globus_gfs_stat_info_t * stat_info,
                 void * user_arg)
{
    char * PathName;
    char basepath[MAXPATHLEN];
    char filename[MAXPATHLEN];
    globus_gfs_stat_t * stat_array;
    globus_result_t result;
    int stat_count = 0;
    lfs_handle_t * lfs_handle;
    GlobusGFSName(globus_l_gfs_lfs_stat);

    lfs_handle = (lfs_handle_t *) user_arg;
    PathName=stat_info->pathname;
    if (!is_lfs_path(lfs_handle, PathName)) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,
                               "Falling back to POSIX stat, file not in LFS\n");
        return lfs_stat_gridftp_posix(op, stat_info, user_arg);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "Doing stats of %s\n", PathName);
    }
    while (PathName[0] == '/' && PathName[1] == '/') {
        PathName++;
    }
    if (strncmp(PathName, lfs_handle->mount_point,
                lfs_handle->mount_point_len)==0) {
        PathName += lfs_handle->mount_point_len;
    }
    while (PathName[0] == '/' && PathName[1] == '/') {
        PathName++;
    }
    snprintf(err_msg, MSG_SIZE, "Going to do stat on file %s.\n", PathName);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, err_msg);

    // ** If we made it here then it's a file in LFS
    struct stat fileInfo;
    struct stat *stat;
    char *readlink = NULL;
    int retval;

    retval = lio_stat(lfs_handle->fs, lfs_handle->fs->creds, PathName, &fileInfo,
                      lfs_handle->mount_point, &readlink);
    if (retval == -ENOENT) {
        result = GlobusGFSErrorSystemError("Stat: file doesn't exist", ENOENT);
        goto error_stat1;
    } else if (retval != 0) {
        result = GlobusGFSErrorSystemError("Stat: unknown error", retval);
        goto error_stat1;
    }

    snprintf(err_msg, MSG_SIZE, "Finished LFS stat operation.\n");
    globus_gfs_log_message(GLOBUS_GFS_LOG_DUMP, err_msg);

    mode_t mode = fileInfo.st_mode;

    globus_l_gfs_file_partition_path(PathName, basepath, filename);

    // TODO: cleanup of fileInfo is pretty horrid.

    if(!S_ISDIR(mode) || stat_info->file_only) {
        stat_array = (globus_gfs_stat_t *)
                     globus_malloc(sizeof(globus_gfs_stat_t));
        if(!stat_array) {
            result = GlobusGFSErrorMemory("stat_array");
            goto error_alloc1;
        }

        globus_l_gfs_file_copy_stat(
            stat_array, &fileInfo, filename, readlink);
        if (readlink) free(readlink);
        //lfsFreeFileInfo(fileInfo, 1);
        stat_count = 1;
    } else {
        Stack_t *stack = new_stack();  // ** This is where all the stats go

        // ** Already have the info for "."
        type_malloc(stat, struct stat, 1);
        *stat = fileInfo;
        push(stack, stat);
        push(stack, strdup("."));
        push(stack, readlink);

        // ** Now do the same for ".."
        char *dotdot;
        if (strcmp(basepath, "/") != 0) {
            char *file;
            os_path_split(basepath, &dotdot, &file);
            free(file);
        } else {
            dotdot = strdup(basepath);
        }

        retval = lio_stat(lfs_handle->fs, lfs_handle->fs->creds, dotdot, &fileInfo,
                          lfs_handle->mount_point, &readlink);
        if (retval == -ENOENT) {
            result = GlobusGFSErrorSystemError("Stat: file doesn't exist", ENOENT);
            goto error_stat1;
        } else if (retval != 0) {
            result = GlobusGFSErrorSystemError("Stat: unknown error", retval);
            goto error_stat1;
        }

        log_printf(1, "dot=%s dotdot=%s\n", PathName, dotdot);

        type_malloc(stat, struct stat, 1);
        *stat = fileInfo;
        push(stack, stat);
        push(stack, strdup(".."));
        free(dotdot);


        // ** Now make the iterator
        char *val[_lio_stat_key_size];
        int v_size[_lio_stat_key_size];
        char path[OS_PATH_MAX];
        char *fname;
        int i, ftype, prefix_len;
        os_object_iter_t *it;
        os_regex_table_t *path_regex;

        for (i=0; i<_lio_stat_key_size; i++) {
            v_size[i] = -lfs_handle->fs->max_attr;
            val[i] = NULL;
        }

        snprintf(path, OS_PATH_MAX, "%s/%s", PathName, "*");
        path_regex = os_path_glob2regex(path);
        it = lio_create_object_iter_alist(lfs_handle->fs, lfs_handle->fs->creds,
                                          path_regex, NULL, OS_OBJECT_ANY, 0,
                                          _lio_stat_keys, (void **)val, v_size,
                                          _lio_stat_key_size);

        // ** Now do the looping
        for (;;) {
            // ** If we made it here then grab the next file and look it up.
            ftype = lio_next_object(lfs_handle->fs, it, &fname, &prefix_len);
            if (ftype <= 0) { // ** No more files
                break;
            }

            type_malloc(stat, struct stat, 1);
            _lio_parse_stat_vals(fname, stat, val, v_size,
                                 lfs_handle->mount_point, &readlink);
            push(stack, stat);
            push(stack, strdup(fname+prefix_len+1));
            push(stack, readlink);
            free(fname);
        }

        // ** Now destroy the iterator
        lio_destroy_object_iter(lfs_handle->fs, it);
        os_regex_table_destroy(path_regex);

        // ** Put everything in the format globus wants
        stat_count = stack_size(stack) / 2;
        stat_array = (globus_gfs_stat_t *) 
                        globus_malloc(sizeof(globus_gfs_stat_t) * stat_count);
        for (i=stat_count-1; i>0; i--) {
            readlink = pop(stack);
            fname = pop(stack);
            stat = pop(stack);
            globus_l_gfs_file_copy_stat(stat_array + i, stat, fname, readlink);
            free(stat);
            free(fname);
            free(readlink);
        }

        free_stack(stack, 1);
    }

    globus_gridftp_server_finished_stat(op, GLOBUS_SUCCESS, stat_array,
                                        stat_count);


    globus_l_gfs_file_destroy_stat(stat_array, stat_count);
    return;

error_alloc1:
error_stat1:
    globus_gridftp_server_finished_stat(op, result, NULL, 0);

    /*    GlobusGFSFileDebugExitWithError();  */
}

/* basepath and filename must be MAXPATHLEN long
 * the pathname may be absolute or relative, basepath will be the same */
static void globus_l_gfs_file_partition_path(const char * pathname,
                                             char * basepath, char * filename)
{
    char buf[MAXPATHLEN];
    char * filepart;
    GlobusGFSName(globus_l_gfs_file_partition_path);

    strncpy(buf, pathname, MAXPATHLEN);

    buf[MAXPATHLEN - 1] = '\0';

    filepart = strrchr(buf, '/');
    while(filepart && !*(filepart + 1) && filepart != buf) {
        *filepart = '\0';
        filepart = strrchr(buf, '/');
    }

    if(!filepart) {
        strcpy(filename, buf);
        basepath[0] = '\0';
    } else {
        if(filepart == buf) {
            if(!*(filepart + 1)) {
                basepath[0] = '\0';
                filename[0] = '/';
                filename[1] = '\0';
            } else {
                *filepart++ = '\0';
                basepath[0] = '/';
                basepath[1] = '\0';
                strcpy(filename, filepart);
            }
        } else {
            *filepart++ = '\0';
            strcpy(basepath, buf);
            strcpy(filename, filepart);
        }
    }
}

static void globus_l_gfs_file_destroy_stat(globus_gfs_stat_t * stat_array,
                                           int stat_count)
{
    int i;
    GlobusGFSName(globus_l_gfs_file_destroy_stat);

    for(i = 0; i < stat_count; i++) {
        if(stat_array[i].name != NULL) {
            globus_free(stat_array[i].name);
        }
        if(stat_array[i].symlink_target != NULL) {
            globus_free(stat_array[i].symlink_target);
        }
    }
    globus_free(stat_array);
}

static void globus_l_gfs_file_copy_stat(globus_gfs_stat_t * stat_object,
                                        struct stat * fileInfo,
                                        const char * filename,
                                        const char * symlink_target)
{
    GlobusGFSName(globus_l_gfs_file_copy_stat);

    stat_object->mode     = (S_ISDIR(fileInfo->st_mode)) ? (S_IFDIR |
                            fileInfo->st_mode) :  (S_IFREG | fileInfo->st_mode);
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
    if(filename && *filename) {
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
    if(symlink_target && (strlen(symlink_target) != 0)) {
        stat_object->symlink_target = strdup(symlink_target);
    } else {
        stat_object->symlink_target = NULL;
    }
}

