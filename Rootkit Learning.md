# Rootkit Learning





## LKM（Linux 可加载模块）

### 定义

[IBM Developer——Linux  lkm]( https://www.ibm.com/developerworks/cn/linux/l-lkm/ )

​	典型的程序有一个 main 函数，其中 LKM 包含 entry 和 exit 函数（在 2.6 版本，您可以任意命名这些函数）。当向内核插入模块时，调用 entry 函数，从内核删除模块时则调用 exit 函数。因为 entry 和 exit 函数是用户定义的，所以存在 `module_init` 和 `module_exit` 宏，用于定义这些函数属于哪种函数。LKM 还包含一组必要的宏和一组可选的宏，用于定义模块的许可证、模块的作者、模块的描述等等。 

比如：

```
#include <linux/module.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Module Author");
MODULE_DESCRIPTION("Module Description");

static int __init mod_entry_func(void)
{
	return 0;
}

static void __init mod_exit_func(void)
{
	return;
}

module_init(mod_entry_func);
module_exit(mod_exit_func);
```

2.6版本的Linux内核提供了几个方法来管理内核模块

>  `insmod`（安装 LKM），`rmmod` （删除 LKM），`modprobe`（`insmod` 和 `rmmod` 的包装器），`depmod`（用于创建模块依赖项），以及 `modinfo`（用于为模块宏查找值） 







### 隐藏模块

主要隐藏的目标为：

1. 对lsmod隐藏
2. 对/proc/modules隐藏
3. 对/sys/module隐藏



其中，lsmod是通过读取/proc/modules来发挥作用的，因此我们对/proc/modules进行处理就能解决前面两个目标，另外需要处理/sys/module/下的模块子目录。



/proc/modules的内容是内核利用struct modules结构体的表头去遍历内核模块链表





### 关闭写保护

[CR0寄存器](https://en.wikipedia.org/wiki/Control_register#CR0)

 写保护指的是写入只读内存时出错，可以通过CR0寄存器控制开启与否，修改从0开始的第16个Bit

![image-20191028130225360](Rootkit Learning.assets/image-20191028130225360.png)

可以使用`read_cr0`，`write_cr0`来读取和写入CR0寄存器

```
static inline unsigned long read_cr0(void);
static inline void write_cr0(unsigned long x);
```

关闭写保护

```
void disable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
	write_cr0(cr0);
}
```

开启写保护

```
void enable_write_protection(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	write_cr0(cr0);
}
```

> 在设置或者清除某个比特，我们使用了[set_bit](https://www.kernel.org/doc/htmldocs/kernel-api/API-set-bit.html)与[clear_bit](https://www.kernel.org/doc/htmldocs/kernel-api/API-clear-bit.html)。 它们是 Linux 内核提供给内核模块使用的编程接口，简单易懂，同时还免去了我们自己写那种很难读的位运算的痛苦。 



## 内核编程学习



**LINUX_VERSION_CODE和KERNEL_VERSION**

[内核版本号以及判断方法](https://www.jianshu.com/p/045b98f070f1)

关于Linux内核版本的两个宏定义在`/usr/include/linux/version.h`

```
#define LINUX_VERSION_CODE 263213
#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))
```

假如我内核版本为4.4.45

- 首先将4.4.45 转为16进制为 0x04.0x04.0x2D
- 然后宏 KERNEL_VERSION(0x04,0x04,0x2D)展开之后得到04042D 这个16进制的数字
- 最后将0x040423 转化为十进制就得到了十进制的263213 即为 LINUX_VERSION_CODE的值263213

在使用时，可以根据版本号不同调用不同的API保持兼容

```
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
....//3.10.0 之前的API调用
#else 
....//3.10.0 版本之后的API调用
#endif 
```



**struct module**

[参考](https://blog.csdn.net/jk110333/article/details/8563647)

当使用insmod插入一个内核模块时，实际上调用的时系统调用init_module，在init_module中首先调用的是load_module，把用户态传入的整个内核模块文件创建成一个内核模块，返回一个struct module结构体，内核中就以此结构体代表该内核模块。

结构体struct module在内核中代表一个内核模块，其定义如下

```
struct module
    {
        enum module_state state;  //表示模块当前状态，枚举类型
        struct list_head list;  /作为一个全局链表的成员
        char name[MODULE_NAME_LEN];   //模块名字，一般以模块文件的文件名作为模块名
 
        struct module_kobject mkobj;
        struct module_param_attrs *param_attrs;
        const char *version;
        const char *srcversion;
 
        const struct kernel_symbol *syms;
        unsigned int num_syms;
        const unsigned long *crcs;
 
        const struct kernel_symbol *gpl_syms;
        unsigned int num_gpl_syms;
        const unsigned long *gpl_crcs;
 
        unsigned int num_exentries;
        const struct exception_table_entry *extable;
 
        int (*init)(void);
        void *module_init;
        void *module_core;
        unsigned long init_size, core_size;
        unsigned long init_text_size, core_text_size;
        struct mod_arch_specific arch;
        int unsafe;
        int license_gplok;
 
#ifdef CONFIG_MODULE_UNLOAD
        struct module_ref ref[NR_CPUS];
        struct list_head modules_which_use_me;
        struct task_struct *waiter;
        void (*exit)(void);
#endif
 
#ifdef CONFIG_KALLSYMS
        Elf_Sym *symtab;
        unsigned long num_symtab;
        char *strtab;
        struct module_sect_attrs *sect_attrs;
#endif
        void *percpu;
        char *args;
    };
```

enum module_state state

```
enum module_state
{
    MODULE_STATE_LIVE,  //模块当前正常使用中（存活状态） 0
    MODULE_STATE_COMING, //模块当前正在被加载  1 
    MODULE_STATE_GOING,  //模块当前正在被卸载  2
};
```

当load_module完成模块的创建工作后，会把状态置为MODULE_STATE_COMING，sys_init_module函数中完成模块的全部初始化工作后（包括把模块加入全局的模块列表，调用模块本身的初始化函数)，把模块状态置为MODULE_STATE_LIVE，最后，使用rmmod工具卸载模块时，会调用系统调用 delete_module，会把模块的状态置为MODULE_STATE_GOING。这是模块内部维护的一个状态。

struct list_head list

>  list是作为一个列表的成员，所有的内核模块都被维护在一个全局链表中，链表头是一个全局变量struct module *modules。任何一个新创建的模块，都会被加入到这个链表的头部 



**THIS_MODULE**

>  结构体*struct module*在内核中代表一个内核模块，通过*insmod(*实际执行*init_module*系统调用*)*把自己编写的内核模块插入内核时，模块便与一个 *struct module*结构体相关联，并成为内核的一部分。 

宏THIS_MODULE，它的定义如下

```
#define THIS_MODULE (&__this_module)
```

`__this_module`是一个struct module变量，代表当前模块。可以通过THIS_MODULE宏来引用模块的struct module结构。



**内核中的链表**

[参考](https://blog.popkx.com/linux-learning-18-how-the-kernel-operates-linked-lists/)

[参考](https://blog.csdn.net/funkunho/article/details/52041012)

一般地，内核中常采用链表来管理对象，定义如下

```
struct list_head {
	struct list_head *next, *prev;
};
```

把链表放入其他数据结构来进行管理，就像一根锁链把要管理的对象链在一起

初始化的两种方式：

1. struct list_head mylist;

```
struct list_head mylist;  // 定义一个链表
INIT_LIST_HEAD(&mylist); // 使用INIT_LIST_HEAD函数初始化链表

static inline void INIT_LIST_HEAD(struct list_head *list)
 {
     list->next = list;
     list->prev = list;
 }
```

经过INIT_LIST_HEAD之后，struct list_head mylist = {&(mylist) , &(mylist) };

也就是next和prev都被赋值为链表mylist的地址，链表初始化都是指向自己的，避免指向未知区域，这点很重要， 如果使用一个未被初始化的链表结点，很有可能会导致内核异常。 

2. LIST_HEAD(mylist)

使用LIST_HEAD宏定义初始化一个链表

```
#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) /
         struct list_head name = LIST_HEAD_INIT(name)
```



**链表的常用操作**

- 增加

list_add 和 list_add_tail

调用list_add可以将一个新链表结点插入到一个已知结点的后面；

调用list_add_tail可以将一个新链表结点插入到一个已知结点的前面；

这两个函数以不同的参数调用了相同的函数`__list_add`

```
static inline void __list_add(struct list_head *new , struct list_head *prev , struct list_head *next)
{
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}
```

该函数将new节点插入到prev节点和next节点之间，由prev->new->next

对于list_add：

```
static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
	//将new结点插入到head和head->next之间，也就是将new结点插入到特定的已知结点head的后面
}
```

对于list_add_tail：

```
static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
	//将new结点插入到head->prev和head之间，也就是将new结点插入到特定的已知结点head的前面
}
```



- 删除

 list_del 和 list_del_init 

调用list_del函数删除链表中的一个结点；

调用list_del_init函数删除链表中的一个结点，并初始化被删除的结点（也就是使被删除的结点的prev和next都指向自己）；











**proc_dir_entry 结构体**

定义在`fs/proc/internal.h`

struct proc_dir_entry 结构体是用来管理/proc文件系统目录项 ，在不同版本中可能有差异

```
struct proc_dir_entry {
    unsigned int low_ino;
    umode_t mode;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    void *data;
    atomic_t count;         /* use count */
    atomic_t in_use;        /* number of callers into module in progress; */
                            /* negative -> it's going away RSN */
    struct completion *pde_unload_completion;
    struct list_head pde_openers;   /* who did ->open, but not ->release */
    spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
    u8 namelen;
    char name[];
};
```



**pr_fmt**

针对特定的模板定义的

` include\linux\printk.h `

 在用户要输出的log前面添加额外的固定的信息 ，比如

```
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt /* has to precede printk.h */
```