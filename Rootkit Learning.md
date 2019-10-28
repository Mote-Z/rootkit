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