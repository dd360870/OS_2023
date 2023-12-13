#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kdev_t.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/cpumask.h>
#include <linux/mm.h>
#include <linux/ktime.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include "kfetch.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NYCU 312551165");
MODULE_DESCRIPTION("kfetch");
MODULE_VERSION("0.1");

#define KFETCH_DEV_NAME "kfetch"

/* MAX_LENGTH is set to 92 because
 * ssize_t can't fit the number > 92
 */
#define MAX_LENGTH 92

static dev_t kfetch_dev = 0;
static struct class *kfetch_class;
static DEFINE_MUTEX(kfetch_mutex);
static int major = 0, minor = 0;

static int kfetch_mask_info = 0;

const char icon[8][20] = {
    "                   ",
    "        .-.        ",
    "       (.. |       ",
    "       <>  |       ",
    "      / --- \\      ",
    "     ( |   | |     ",
    "   |\\\\_)___/\\)/\\   ",
    "  <__)------(__/   "};

static char buf[100] = "";

static void read_file(char *filename, char *buffer)
{
    struct file *fp;
    fp = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        printk("filp_open error: %ld\n", PTR_ERR(fp));
        return;
    }
    kernel_read(fp, buffer, 100, 0);
    filp_close(fp, NULL);
}

static void kfetch_cpu_model(char *ret)
{
    // 
    // or use current cpu speed
    read_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", buf);
    long freq = 0;
    kstrtol(buf, 10, &freq);
    struct cpuinfo_x86 *c = &cpu_data(0);
    if (freq == 0) {
        sprintf(ret, "%s", c->x86_model_id);
    }
    else {
        sprintf(ret, "%s @ %ldGHz", c->x86_model_id, freq);
    }
}

static char* hello(void)
{
    int info_count = 0;
    char infos[8][80] = { 0 };
    const char *hostname = utsname()->nodename;
    // The first line is the machine hostname, which is mandatory and cannot be disabled
    strcpy(infos[0], hostname);

    // The next line is a separator line with a length equal to the hostname
    memset(infos[1], '-', strlen(hostname));

    int info_order[KFETCH_NUM_INFO] = {
        // 1. Kernel: The kernel release
        KFETCH_RELEASE,
        // 2. CPU: The CPU model name
        KFETCH_CPU_MODEL,
        // 3. CPUs: The number of CPU cores, in the format <# of online CPUs> / <# of total CPUs>
        KFETCH_NUM_CPUS,
        // 4. Mem: The memory information, in the format<free memory> / <total memory> (in MB)
        KFETCH_MEM,
        // 5. Procs: The number of processes
        KFETCH_NUM_PROCS,
        // 6. Uptime: How long the system has been running, in minutes.
        KFETCH_UPTIME,
    };

    for (int i = 0; i < KFETCH_NUM_INFO; i++) {
        if (kfetch_mask_info & info_order[i]) {
            char temp[200] = "";
            switch (info_order[i]) {
                case KFETCH_CPU_MODEL:
                    kfetch_cpu_model(buf);
                    sprintf(temp, "CPU:      %s", buf);
                    break;
                case KFETCH_NUM_CPUS:
                    sprintf(temp, "CPUs:     %u / %u", num_online_cpus(), num_present_cpus());
                    break;
                case KFETCH_RELEASE:
                    sprintf(temp, "Kernel:   %s", utsname()->release);
                    break;
                case KFETCH_MEM:
                    struct sysinfo i;
                    si_meminfo(&i);
                    // ref: MemUsed = Memtotal + Shmem - MemFree - Buffers - Cached - SReclaimable
                    unsigned long available = (si_mem_available() << (PAGE_SHIFT - 10)) / 1024;
                    unsigned long total = (i.totalram << (PAGE_SHIFT - 10)) / 1024;
                    sprintf(temp, "Mem:      %lu MB / %lu MB", available , total);
                    break;
                case KFETCH_UPTIME:
                    s64  uptime;
                    uptime = ktime_divns(ktime_get_coarse_boottime(), NSEC_PER_SEC);
                    sprintf(temp, "Uptime:   %llu mins", uptime/60);
                    break;
                case KFETCH_NUM_PROCS:
                    read_file("/proc/loadavg", buf);
                    int u, v;
                    sscanf(buf, "%*lu.%*lu %*lu.%*lu %*lu.%*lu %d/%d", &u, &v);
                    sprintf(temp, "Procs:    %d", v);
                    break;

            }
            strcpy(infos[info_count+2], temp);
            info_count++;
        }
    }


    int s_len = 0;
    static char s[1000] = "";

    for (int i = 0; i < 8; i++) {
        int len = strlen(icon[i]);
        strncpy(s+s_len, icon[i], len);
        s_len += len;
        if (i < info_count+2) {
            len = strlen(infos[i]);
            strncpy(s+s_len, infos[i], len);
            s_len += len;
        }
        strncpy(s+s_len, "\n", 1);
        s_len += 1;
    }

    return s;
}

static int kfetch_open(struct inode *inode, struct file *file)
{
    if (!mutex_trylock(&kfetch_mutex)) {
        printk(KERN_ALERT "fibdrv is in use\n");
        return -EBUSY;
    }
    return 0;
}

static int kfetch_release(struct inode *inode, struct file *file)
{
    mutex_unlock(&kfetch_mutex);
    return 0;
}

/* calculate the fibonacci number at given offset */
static ssize_t kfetch_read(struct file *file,
                        char *buf,
                        size_t size,
                        loff_t *offset)
{
    char *s = hello();
    int len = strlen(s);
    if (copy_to_user(buf, s, len + 1)) {
        return -EFAULT;
    }
    return len + 1;
}

/* write operation is skipped */
static ssize_t kfetch_write(struct file *file,
                         const char *buf,
                         size_t size,
                         loff_t *offset)
{
    if (copy_from_user(&kfetch_mask_info, buf, size)) {
        return -EFAULT;
    }
    return 1;
}

const struct file_operations fib_fops = {
    .owner = THIS_MODULE,
    .read = kfetch_read,
    .write = kfetch_write,
    .open = kfetch_open,
    .release = kfetch_release,
};

static int __init init_kfetch_dev(void)
{
    int rc = 0;
    mutex_init(&kfetch_mutex);

    // Let's register the device
    // This will dynamically allocate the major number
    rc = major = register_chrdev(major, KFETCH_DEV_NAME, &fib_fops);
    if (rc < 0) {
        printk(KERN_ALERT "Failed to add cdev\n");
        rc = -2;
        goto failed_cdev;
    }
    kfetch_dev = MKDEV(major, minor);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    kfetch_class = class_create(KFETCH_DEV_NAME);
#else
    kfetch_class = class_create(THIS_MODULE, KFETCH_DEV_NAME);
#endif
    if (!kfetch_class) {
        printk(KERN_ALERT "Failed to create device class\n");
        rc = -3;
        goto failed_class_create;
    }

    if (!device_create(kfetch_class, NULL, kfetch_dev, NULL, KFETCH_DEV_NAME)) {
        printk(KERN_ALERT "Failed to create device\n");
        rc = -4;
        goto failed_device_create;
    }
    return rc;
failed_device_create:
    class_destroy(kfetch_class);
failed_class_create:
failed_cdev:
    unregister_chrdev(major, KFETCH_DEV_NAME);
    return rc;
}

static void __exit exit_kfetch_dev(void)
{
    mutex_destroy(&kfetch_mutex);
    device_destroy(kfetch_class, kfetch_dev);
    class_destroy(kfetch_class);
    unregister_chrdev(major, KFETCH_DEV_NAME);
}

module_init(init_kfetch_dev);
module_exit(exit_kfetch_dev);
