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

// Color: bold light yellow
#define COLOR_PRIMARY "\e[1;93m"
#define COLOR_DEFAULT "\e[0m"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NYCU 312551165");
MODULE_DESCRIPTION("HW3");
MODULE_VERSION("0.1");

static dev_t kfetch_dev = 0;
static struct class *kfetch_class;
static DEFINE_MUTEX(kfetch_mutex);
static int major = 0, minor = 0;

static int kfetch_mask_info = 0;

const char ICON[8][50] = {
    "                   ",
    "        .-.        ",
    "       (.. |       ",
    "       " COLOR_PRIMARY "<>" COLOR_DEFAULT "  |       ",
    "      / --- \\      ",
    "     ( |   | |     ",
    COLOR_PRIMARY "   |\\" COLOR_DEFAULT "\\_)___/\\)" COLOR_PRIMARY "/\\   " COLOR_DEFAULT,
    COLOR_PRIMARY "  <__)" COLOR_DEFAULT "------" COLOR_PRIMARY "(__/   " COLOR_DEFAULT};

// printing order
const int KFETCH_INFO_PRINT_ORDER[KFETCH_NUM_INFO] = {
    KFETCH_RELEASE,
    KFETCH_CPU_MODEL,
    KFETCH_NUM_CPUS,
    KFETCH_MEM,
    KFETCH_NUM_PROCS,
    KFETCH_UPTIME,
};

// read file in kernel space
static void read_file(char *filename, char *buffer, size_t len)
{
    struct file *fp;
    fp = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(fp)) {
        printk("filp_open error: %ld\n", PTR_ERR(fp));
        return;
    }
    kernel_read(fp, buffer, len, 0);
    filp_close(fp, NULL);
}

// read cpu model name
static const char* kfetch_cpu_model(void)
{
    static char ret[100] = "";
    char temp[100] = "";
    // max freq
    read_file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", temp, 100);
    long freq = 0;
    if (kstrtol(temp, 10, &freq)) {
        freq = 0;
    }
    struct cpuinfo_x86 *c = &cpu_data(0);
    if (freq == 0) {
        sprintf(ret, "%s", c->x86_model_id);
    }
    else {
        sprintf(ret, "%s @ %ld.%ldGHz", c->x86_model_id, freq/1000/1000, freq/1000%1000);
    }
    return ret;
}

void color_sprintf(char *des, const char *s, const char *color)
{
    sprintf(des, "%s%s%s", color, s, COLOR_DEFAULT);
}

static const char* get_info(int v) {
    static char ret[100] = "";
    switch (v) {
        case KFETCH_CPU_MODEL:
            color_sprintf(ret, "CPU:      ", COLOR_PRIMARY);
            strcat(ret, kfetch_cpu_model());
            break;
        case KFETCH_NUM_CPUS:
            color_sprintf(ret, "CPUs:     ", COLOR_PRIMARY);
            sprintf(ret+strlen(ret), "%u / %u", num_online_cpus(), num_present_cpus());
            break;
        case KFETCH_RELEASE:
            color_sprintf(ret, "Kernel:   ", COLOR_PRIMARY);
            strcat(ret, utsname()->release);
            break;
        case KFETCH_MEM:
            struct sysinfo i;
            si_meminfo(&i);
            unsigned long available = (si_mem_available() << (PAGE_SHIFT - 10)) / 1024;
            unsigned long total = (i.totalram << (PAGE_SHIFT - 10)) / 1024;
            color_sprintf(ret, "Mem:      ", COLOR_PRIMARY);
            sprintf(ret+strlen(ret), "%lu MB / %lu MB", available , total);
            break;
        case KFETCH_UPTIME:
            s64 uptime;
            uptime = ktime_divns(ktime_get_coarse_boottime(), NSEC_PER_SEC);
            color_sprintf(ret, "Uptime:   ", COLOR_PRIMARY);
            sprintf(ret+strlen(ret), "%llu mins", uptime/60);
            break;
        case KFETCH_NUM_PROCS:
            char temp[100] = "";
            read_file("/proc/loadavg", temp, 100);
            int u, v;
            sscanf(temp, "%*u.%*u %*u.%*u %*u.%*u %d/%d", &u, &v);
            color_sprintf(ret, "Procs:    ", COLOR_PRIMARY);
            sprintf(ret+strlen(ret), "%d", v);
            break;
        default:
            ret[0] = '\0';
    }
    return ret;
}

static void kfetch_output(char *output)
{
    const char *hostname = utsname()->nodename;
    const int hostname_len = strlen(hostname);

    int info_i = 0;

    int len = 0;
    for (int i = 0; i < 8; i++) {
        strcpy(output + len, ICON[i]);
        len += strlen(ICON[i]);

        if (i == 0) {
            color_sprintf(output + len, hostname, COLOR_PRIMARY);
            len += strlen(output + len);
        }
        else if (i == 1) {
            memset(output + len, '-', hostname_len);
            len += strlen(output + len);
        }
        else {
            // skip unspecified infos
            while ((info_i < KFETCH_NUM_INFO) && !(KFETCH_INFO_PRINT_ORDER[info_i] & kfetch_mask_info)) {
                info_i++;
            }

            if (info_i < KFETCH_NUM_INFO) {

                const char *info = get_info(KFETCH_INFO_PRINT_ORDER[info_i]);
                strcpy(output + len, info);
                len += strlen(info);

                info_i++;
            }
        }

        // newline
        memset(output + len, '\n', 1);
        len++;
    }
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
static ssize_t kfetch_read(struct file *file, char *buf, size_t size, loff_t *offset)
{
    char *s = kzalloc(KFETCH_BUF_SIZE, GFP_KERNEL);
    kfetch_output(s);
    int len = strlen(s);
    if (copy_to_user(buf, s, len + 1)) {
        return -EFAULT;
    }
    kfree(s);
    return len + 1;
}

static ssize_t kfetch_write(struct file *file, const char *buf, size_t size, loff_t *offset)
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
