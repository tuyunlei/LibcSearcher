# Search libc function offset

## 安装

```shell
git clone https://github.com/lieanu/LibcSearcher.git
cd LibcSearcher
python setup.py develop
```

## 添加数据库

```shell
cd libc-database
./get ubuntu
```

具体使用方法请参考[libc-database](https://github.com/niklasb/libc-database)

## 示例

```python
from LibcSearcher import *

#元组内第二个参数，为已泄露的实际地址,或最后12位(比如：0xd90)，int类型
obj = LibcSearcher(("fgets", 0X7ff39014bd90), ('puts', 0X7ff39014d940))

obj.dump("system")        #system 地址
obj.dump("str_bin_sh")    #/bin/sh 地址
obj.dump("__libc_start_main_ret")
```

如果遇到返回多个libc版本库的情况，可以通过`add_condition(leaked_func, leaked_address)`来添加限制条件，也可以手工选择其中一个libc版本（如果你确定的话）。

## 其它

水平一般，代码很烂，如有bug，欢迎吐槽。
