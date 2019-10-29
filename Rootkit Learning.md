# Rootkit Learning

[TOC]



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
 
        struct module_kobject mkobj;  //组成设备模型的基本结构
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

**struct module_kobject mkobj**

[参考](https://www.cnblogs.com/xiaojiang1025/p/6193959.html)

[参考](http://kcmetercec.top/2018/03/09/linux_kernel_sysfs_tutorial/)

[参考](https://www.twblogs.net/a/5b8b2ccf2b717718832dd8f0/zh-cn)

```
//include/linux/module.h

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

//include/linux/kobject.h

struct kobject {  
    const char          *name;   //kobject对象的名字，对应sysfs下的一个目录
    struct list_head    entry;   //kobject中插入的head_list结构
    struct kobject      *parent;  //指向当前kobject父对象的指针，体现在sys结构中就是包含当前kobject对象的目录对象
    struct kset         *kset;    //表示当前kobject对象所属的集合
    struct kobj_type    *ktype;   //表示当前kobject的类型
    struct kernfs_node  *sd;     //表示VFS文件系统的目录项
    struct kref         kref;   // 对kobject的引用计数，当引用计数为0时，就回调之前注册的release方法释放该对象
    #ifdef CONFIG_DEBUG_KOBJECT_RELEASE  
    	struct delayed_work release;
    #endif
        unsigned int state_initialized:1;
        unsigned int state_in_sysfs:1;
        unsigned int state_add_uevent_sent:1;
        unsigned int state_remove_uevent_sent:1;
        unsigned int uevent_suppress:1;
};
```

>  `kobject`是组成设备模型的基本结构。`sysfs`是基于 RAM 的文件系统，它提供了用于向用户空间展示内核空间里对象、属性和链接的方法。`sysfs`和`kobject`层次紧密相连，将`kobject`层次关系展示出来，让用户层能够看到。一般`sysfs`挂载在`/sys/`，所以`/sys/module`就是`sysfs`的一个目录层次，包含当前加载的模块信息。所以，我们使用`kobject_del()`删除我们的模块的`kobject`，就可以达到隐藏的目的。 

kobject_del

```
//lib/kobject.c

void kobject_del(struct kobject *kobj)
{
	struct kernfs_node *sd;

	if (!kobj)
		return;

	sd = kobj->sd;       //获取kobj对象的文件系统目录项
	sysfs_remove_dir(kobj); //调用sysfs_remove_dir实际上是把kobj的sd结构置为NULL
	sysfs_put(sd);

	kobj->state_in_sysfs = 0;
	kobj_kset_leave(kobj);
	kobject_put(kobj->parent);
	kobj->parent = NULL;
}
```

struct kernfs_node  *sd;

```
struct kernfs_node {
	atomic_t		count;   //相关计数
	atomic_t		active;  //相关计数
#ifdef CONFIG_DEBUG_LOCK_ALLOC
	struct lockdep_map	dep_map;
#endif
	struct kernfs_node	*parent;  //本节点的父节点，这个比较重要，属性是文件，父节点是kobject
	const char		*name;     //节点名字

	struct rb_node		rb;     //红黑树节点

	const void		*ns;	//命名空间相关
	unsigned int		hash;	//命名空间相关
	//定义联合体
	union {
		struct kernfs_elem_dir		dir;     //目录
		struct kernfs_elem_symlink	symlink;   //符号链接
		struct kernfs_elem_attr		attr;    //属性
	};

	void			*priv;        //私有数据，kobject作为私有数据随kernfs_node传递

	unsigned short		flags;    //文件相关属性
	umode_t			mode;    //文件相关属性
	unsigned int		ino;   //子设备号
	struct kernfs_iattrs	*iattr;    //节点本身属性
};

```

struct kernfs_elem_attr

```
struct kernfs_elem_attr {
	const struct kernfs_ops	*ops;
	struct kernfs_open_node	*open;
	loff_t			size;
	struct kernfs_node	*notify_next;	/* for kernfs_notify() */
};
```



sysfs_remove_dir(kobj);

```
void sysfs_remove_dir(struct kobject *kobj)
{
	struct kernfs_node *kn = kobj->sd;
	spin_lock(&sysfs_symlink_target_lock);
	kobj->sd = NULL;
	spin_unlock(&sysfs_symlink_target_lock);

	if (kn) {
		WARN_ON_ONCE(kernfs_type(kn) != KERNFS_DIR);
		kernfs_remove(kn);
	}
}
```

**红黑树rbtree**

[参考](https://biscuitos.github.io/blog/Tree_RBTREE_rb_set_parent_color/)





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

这两个函数也调用了相同的函数__list_del：

```
static inline void __list_del(struct list_head * prev, struct list_head * next)
{
    next->prev = prev;
    prev->next = next;
}
```

 让prev结点和next结点互相指向 

对于list_del：

```
static inline void list_del(struct list_head *entry)
{
    __list_del(entry->prev, entry->next);  //就是entry节点的前后节点绕过entry节点相互指向
    entry->next = LIST_POISON1;            
    entry->prev = LIST_POISON2;
    //将entry结点的前后指针指向LIST_POISON1和LIST_POISON2，从而完成对entry结点的删除
}
```

LIST_POISON1和LIST_POISON2指得是什么暂时不清楚，一般来说要把这个节点释放掉都是指向NULL

对于list_del_init：

```
static inline void list_del_init(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	INIT_LIST_HEAD(entry);
}
```

与list_del不同，list_del_init将entry结点删除后，还会对entry结点做初始化，使得entry结点的prev和next都指向自己。 

- typeof、offsetof 和 container_of

定义如下：

```
#include <stddef.h>
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE*)0)->MEMBER)

#define container_of(ptr, type, member) ({          \
        const typeof( ((type *)0)->member ) *__mptr = (const typeof( ((type *)0)->member ) *)(ptr); \
        (type *)( (char *)__mptr - offsetof(type,member) );})
```

typeof是GNU对C新增得一个扩展关键字，用于获取对象类型，通常我们需要处理的对象都是指针，如果想知道指针所指向的对象的类型，可以使用typeof。

offsetof返回结构体TYPE中MEMBER成员相对于结构体首地址的偏移量。为什么offsetof可以得到某个成员的偏移量？

> `(TYPE *)0`,将 0 强制转换为`TYPE`型指针，记 `p = (TYPE *)0`，`p`是指向`TYPE`的指针，它的值是0。那么 `p->MEMBER` 就是 `MEMBER` 这个元素了，而`&(p->MEMBER)`就是`MEMBER`的地址，编译器认为0是一个有效的地址，则基地址为0，这样就巧妙的转化为了`TYPE`中的偏移量。再把结果强制转换为`size_t`型的就OK了。

container_of的作用的通过结构体变量中的一个域成员变量的指针来获取指向整个结构体变量的指针

>  创建一个类型为`const typeof( ((type *)0)->member ) *`，即类型为`type`结构的`member`域所对应的对象类型的常指针`__mptr` ，使用`ptr`初始化， 也就是获取到了member的地址。
>
>  因为数据结构是顺序存储的，此时如果知道`member`在`type`结构中的相对偏移，那么用`__mptr`减去此偏移便是`ptr`所属的`type`的地址。  



- list_entry

有了上面的基础就比较好理解，已知某个结构体abc的list对象地址（struct list_head *ptr），怎么获取到abc对象的地址呢，使用container_of宏！不过这里应该使用list_entry来做

```
#define list_entry(ptr, type, member)  container_of(ptr, type, member) ......
```

因此list_entry的作用就是获取某个成员对象所在的对象的地址。



- list_for_each_entry

```
/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))
```







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



 https://github.com/croemheld/lkm-rootkit/blob/master/src/module_hiding.c 



## Zeroevil库的使用



```
unsigned long **
get_sct(void);     //获取sys_call_table地址，调用get_sct_via_sys_close

unsigned long **
get_sct_via_sys_close(void);  //暴力搜索内存空间找到地址


void
disable_wp(void)     //关闭写保护，需要上锁

void
enable_wp(void)     //开启写保护，需要上锁



void
print_process_list(void)  //打印进程列表
```

