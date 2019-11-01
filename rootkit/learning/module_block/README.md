# 阻止加载其他内核模块

guard目录下是阻止其他内核模块的加载，lamb目录下是一个简单的模块。

正常情况下lamb目录下模块的加载是这样的。

输入：

![image-20191101132434082](https://blog-1252880414.cos.ap-chengdu.myqcloud.com/rootkit_modules_block/image-1.png)

结果：

![image-20191101132445656](https://blog-1252880414.cos.ap-chengdu.myqcloud.com/rootkit_modules_block/image-2.png)

而当加载了module_block模块后，简单模块被其阻止加载了。

输入：

![image-20191101132238493](https://blog-1252880414.cos.ap-chengdu.myqcloud.com/rootkit_modules_block/image-3.png)

实验结果：

![image4](https://blog-1252880414.cos.ap-chengdu.myqcloud.com/rootkit_modules_block/image-4.png)

