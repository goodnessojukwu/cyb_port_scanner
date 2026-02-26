#include "port_scanner.h"

/**
 * find_process_by_inode - Maps a socket inode to its owning process
 * @target_inode: The unsigned long inode number extracted from /proc/net/
 * @out_pid: Pointer to an integer where the found Process ID will be stored
 * @out_comm: Pointer to a string buffer where the process name will be stored
 *
 * Description: Crawls through the /proc filesystem, inspecting the file
 * descriptors of running processes to find a match for the target socket inode.
 * Return: void
 */
void find_process_by_inode(unsigned long target_inode, int *out_pid, char *out_comm)
{
    /* proc_dir: Directory stream for the root /proc directory */
    DIR *proc_dir;
    /* entry: Structure representing a directory entry within /proc */
    struct dirent *entry;

    *out_pid = -1;
    strcpy(out_comm, "Unknown");

    if (!(proc_dir = opendir("/proc")))
        return;

    while ((entry = readdir(proc_dir)) != NULL)
    {
        if (!isdigit(entry->d_name[0]))
            continue;

        /* fd_path: String holding the path to the process's file descriptor folder */
        char fd_path[512];
        snprintf(fd_path, sizeof(fd_path), "/proc/%s/fd", entry->d_name);
        
        /* fd_dir: Directory stream for a specific PID's /fd directory */
        DIR *fd_dir;
        if ((fd_dir = opendir(fd_path)) != NULL)
        {
            /* fd_entry: Structure representing a file descriptor symlink */
            struct dirent *fd_entry;
            while ((fd_entry = readdir(fd_dir)) != NULL)
            {
                if (fd_entry->d_name[0] == '.')
                    continue;

                /* link_path: Absolute path to the individual file descriptor symlink */
                char link_path[1024];
                snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_entry->d_name);
                
                /* target: Buffer to store the resolved target of the symlink */
                char target[512];
                /* len: Number of bytes written by readlink */
                ssize_t len = readlink(link_path, target, sizeof(target) - 1);
                
                if (len != -1)
                {
                    target[len] = '\0';
                    /* expected_target: Formatted string representing the socket inode we seek */
                    char expected_target[64];
                    snprintf(expected_target, sizeof(expected_target), "socket:[%lu]", target_inode);
                    
                    if (strcmp(target, expected_target) == 0)
                    {
                        *out_pid = atoi(entry->d_name);
                        
                        /* comm_path: Path to the process's command name file */
                        char comm_path[512];
                        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", entry->d_name);
                        
                        /* f: File pointer used to read the process name */
                        FILE *f = fopen(comm_path, "r");
                        if (f)
                        {
                            if (fgets(out_comm, 256, f))
                                out_comm[strcspn(out_comm, "\n")] = 0; 
                            fclose(f);
                        }
                        closedir(fd_dir);
                        closedir(proc_dir);
                        return;
                    }
                }
            }
            closedir(fd_dir);
        }
    }
    closedir(proc_dir);
}
