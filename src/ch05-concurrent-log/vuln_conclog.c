/*
 * vuln_conclog.c — Concurrent Log
 *
 * A multi-writer kernel logging device.  Each log entry is reference-
 * counted and freed when the last reader releases it.  The device is
 * designed for concurrent access (SMP=2).
 *
 * Bug:  The reference-count decrement in CMD_PUT is NOT atomic.  It
 *       reads refcount, checks > 0, then decrements and stores.  On
 *       SMP, two CPUs can race through the check simultaneously and
 *       both decrement, causing a double-free.
 *
 *       There is NO artificial delay (ndelay/udelay).  The race window
 *       is the natural gap between the read and the store of the
 *       refcount — the same pattern that causes real kernel bugs
 *       (cf. CVE-2016-4557, CVE-2022-29581, CVE-2023-3390).
 *
 * Intended exploitation path:
 *   1. Allocate a log entry (kmalloc-192)
 *   2. Race two threads on CMD_PUT → double-free
 *   3. Use userfaultfd or FUSE to widen the race window reliably
 *   4. Reclaim the first free with pipe_buffer (kmalloc-192 via F_SETPIPE_SZ
 *      with 4 pages: the ring is a power of two, 4 * 40 = 160 bytes)
 *   5. Second free corrupts the freelist → overlapping objects
 *   6. Leak kernel text via pipe_buffer->ops (→ anon_pipe_buf_ops)
 *   7. Build arbitrary read/write by corrupting pipe_buffer->page
 *   8. Overwrite current task's cred->uid to 0 (direct cred overwrite)
 *
 * This is intentionally a DIFFERENT exploitation path from CH04:
 *   - CH04 teaches modprobe_path (data target in .data section)
 *   - CH05 teaches cred overwrite (data target on the heap via task_struct)
 * Both are data-only, but the spray object (pipe_buffer vs msg_msg),
 * the leak source, and the write target are all different.
 *
 * Mitigations: Level 4 — SMEP + SMAP + KASLR + KPTI
 *
 * Device: /dev/conclog
 * Interface: ioctl() — 4 commands
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define DEVICE_NAME   "conclog"
#define MAX_ENTRIES   16
#define ENTRY_SIZE    184     /* data portion: struct total = 192 -> kmalloc-192 */

#define CMD_ALLOC     _IOW('L', 1, struct conclog_io)
#define CMD_READ      _IOR('L', 2, struct conclog_io)
#define CMD_WRITE     _IOW('L', 3, struct conclog_io)
#define CMD_PUT       _IOW('L', 4, struct conclog_io)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kernel-ctf-lab");
MODULE_DESCRIPTION("Concurrent Log — race condition → double free");

struct conclog_io {
    unsigned long idx;
    unsigned long size;
    char __user  *data;
};

/*
 * Log entry layout.  Total struct size (192) lands in kmalloc-192.
 * The refcount field is intentionally a plain int (not atomic_t)
 * — this is the bug.
 */
struct log_entry {
    int           refcount;   /* BUG: non-atomic reference count */
    unsigned int  data_len;
    char          data[ENTRY_SIZE];
};

static struct log_entry *entries[MAX_ENTRIES];

/*
 * NOTE: the entry table uses a shared (rw_semaphore) lock. CMD_PUT takes
 * only the read side, so two CPUs can run it at the same time. The lock
 * may sleep, so copy_{to,from}_user can fault (userfaultfd works).
 */
static DECLARE_RWSEM(log_rwlock);

static long conclog_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct conclog_io io;
    struct log_entry *e;
    int r;
    long ret = 0;

    if (copy_from_user(&io, (void __user *)arg, sizeof(io)))
        return -EFAULT;

    if (io.idx >= MAX_ENTRIES)
        return -EINVAL;

    switch (cmd) {
    case CMD_ALLOC:
        down_write(&log_rwlock);
        if (entries[io.idx]) {
            ret = -EEXIST;
        } else {
            entries[io.idx] = kmalloc(sizeof(struct log_entry), GFP_KERNEL);
            if (!entries[io.idx]) {
                ret = -ENOMEM;
            } else {
                memset(entries[io.idx], 0, sizeof(struct log_entry));
                entries[io.idx]->refcount = 1;
            }
        }
        up_write(&log_rwlock);
        break;

    case CMD_READ:
        down_read(&log_rwlock);
        if (!entries[io.idx] || entries[io.idx]->refcount <= 0) {
            ret = -ENOENT;
        } else {
            if (io.size > entries[io.idx]->data_len)
                io.size = entries[io.idx]->data_len;
            if (io.size > 0 && copy_to_user(io.data, entries[io.idx]->data, io.size))
                ret = -EFAULT;
        }
        up_read(&log_rwlock);
        break;

    case CMD_WRITE:
        down_read(&log_rwlock);
        if (!entries[io.idx] || entries[io.idx]->refcount <= 0) {
            ret = -ENOENT;
        } else {
            if (io.size > ENTRY_SIZE)
                io.size = ENTRY_SIZE;
            if (copy_from_user(entries[io.idx]->data, io.data, io.size))
                ret = -EFAULT;
            else
                entries[io.idx]->data_len = io.size;
        }
        up_read(&log_rwlock);
        break;

    case CMD_PUT:
        /*
         * Decrement refcount and free if it reaches zero.
         *
         * BUG: refcount is read once and written back non-atomically under
         * the shared lock. Two CPUs can both read r == 1, both store 0 and
         * both free the same entry (double free).
         */
        down_read(&log_rwlock);
        if (!entries[io.idx]) {
            ret = -ENOENT;
            up_read(&log_rwlock);
            break;
        }

        e = entries[io.idx];
        r = e->refcount;
        if (r > 0) {
            e->refcount = r - 1;
            if (r == 1) {
                kfree(e);
                entries[io.idx] = NULL;
            }
        } else {
            ret = -EINVAL;
        }
        up_read(&log_rwlock);
        break;

    default:
        ret = -ENOTTY;
    }

    return ret;
}

static int conclog_open(struct inode *i, struct file *f)
{
    return 0;
}

static int conclog_release(struct inode *i, struct file *f)
{
    return 0;
}

static const struct file_operations conclog_fops = {
    .owner          = THIS_MODULE,
    .open           = conclog_open,
    .release        = conclog_release,
    .unlocked_ioctl = conclog_ioctl,
};

static struct miscdevice conclog_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE_NAME,
    .fops  = &conclog_fops,
    .mode  = 0666,
};

static int __init conclog_init(void)
{
    int ret = misc_register(&conclog_dev);
    if (ret)
        pr_err("conclog: failed to register device\n");
    else
        pr_info("conclog: /dev/%s registered (max_entries=%d, smp required)\n",
                DEVICE_NAME, MAX_ENTRIES);
    return ret;
}

static void __exit conclog_exit(void)
{
    int i;
    down_write(&log_rwlock);
    for (i = 0; i < MAX_ENTRIES; i++) {
        kfree(entries[i]);
        entries[i] = NULL;
    }
    up_write(&log_rwlock);
    misc_deregister(&conclog_dev);
    pr_info("conclog: device unregistered\n");
}

module_init(conclog_init);
module_exit(conclog_exit);
