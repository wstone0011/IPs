# IPs
IP池，方便遍历，而不会消耗太多的存储空间。

原理：
例如，对于一个10.0.0.1/24如果直接一个个的放到list里，显然太大了，也没有必要，因为我们只要记住首、尾地址，然后遍历就好了。


功能上参考IPy库，但是这个库有不完善的地方，有很大的问题，用起来不方便。
https://pypi.python.org/pypi/IPy/
