## 进制 
**进制的定义：** N进制，由N个任意符号组成，逢N进1。 
以下是一些普遍使用的进制 
> 0 1 2 3 4 5 6 7 8 9 A B C D E F //16进制  
> 0 1 2 3 4 5 6 7 8 9             //10进制  
> 0 1 //二进制  
### 进制的运算：
做任意N进制的运算时，本质是通过查表的方式来进行。以8进制为例： 

| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
| -- | -- | -- | -- | -- | -- | -- | -- |
| 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 |
| 20 | 21 | 22 | 23 | 24 | 25 | 26 | 27 |
| 30 | 31 | 31 | 33 | 34 | 35 | 36 | 37 |
| 40 | 41 | 42 | 43 | 44 | 45 | 46 | 47 | 

`1+2`可以理解为`1`向后查`2`位，或者是`2`向后查`1`位  
`7+10`可以理解为`7`向后查`10`位,为`17`  
> 使用N进制时要以N进制的视角来看,此时这里的`10`(一零)表现为一个符号,代表8进制中的8 

同理，减法也是一样。`10-7`可以理解成`10`向前查`7`位,为`1`    
### 二进制的简写形式
计算机中的数据都是以二进制`0`和`1`来存储的,但是以`0`和`1`来看的话,难免过于难以理解  
二进制的使用、阅读都会变得比较麻烦,目前大部分的软件都是以16进制数来表示二进制数
|二进制| 0000 | 0001 | 0010 | 0011 | 0100 | 0101 | 0110 | 0111 | 1000 | 1001 | 1010 | 1011 | 1100 | 1101 | 1110 | 1111| 
| :----:| :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--: | :--:| 
|十六进制| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F |
### 数据宽度
在计算机中，因为受到硬件的制约，数据是有长度限制的，我们一般称之为**数据宽度**，超出最多宽度的数据会被丢弃掉。  
|名称|图示|大小|
|:--:|:--:|:--:|
|位(BIT)|▋|1位|
|字节(BYTE)|▋▋▋▋▋▋▋▋|8位|
|字(WORD)|▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋|16位,2个字节|
|双字(DWORD)|▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋▋|32位,4字节,2字|
### 无符号数、有符号数
朴素的理解，无符号数无符号，有符号数有符号  
以一个无符号二进制数举例：`01011101`  
|无符号数|有符号数|
| -- | -- |
|0x5D,93|0x5D,93|

将二进制数转成十六进制数和十进制数的情况下，无符号数在计算机中的表示并无区别  
**无符号数存储在计算机内的值就是其本身**  
###  原码、反码、补码  
**原码：** 最高位为符号位，其余各位为数值本身的绝对值  
**反码：** 正数反码和原码相同，负数反码符号位为`1`，其余位对原码取反  
**补码：** 正数补码和原码相同，负数补码符号位为`1`，其余位对原码取反+`1`  
如下，将`1` `-1` `8` `-8`以字节(BYTE)的形式存入计算机中，原码、反码、补码表示如下  
|:cherry_blossom:|1| -1|8| -8|
|:--:|:--:|:--:|:--:|:--:|
原码|0000 0001|1000 0001|0000 1000|1000 1000
反码|0000 0001|1111 1110|0000 1000|1111 0111
补码|0000 0001|1111 1111|0000 1000|1111 1000
### 计算机加减法
计算机中没有纯粹的四则运算，只能对`0`和`1`进行计算，计算机中的四则运算是以位运算的形式来呈现的  

|符号|描述|运算规则|
|:--:|:--:|:--:|
|& |与|两个位都为1时，结果才为1
|&#124; |或|两个位都为0时，结果才为0
|^ |异或 |两个位相同为0，相异为1
|~ |取反 |0变1，1变0
|<<|左移|各二进位全部左移若干位，高位丢弃，低位补0
|>>|右移|各二进位全部右移若干位，对无符号数，高位补0，有符号数，各编译器处理方法不一样，有的补符号位（算术右移），有的补0（逻辑右移）

#### 按位运算
运算|3&5|3&#124;5|3^5|~3|3<<1|3>>1
|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
3|0000 0011|0000 0011|0000 0011|0000 0011|0000 0011|0000 0011|
5|0000 0101|0000 0101|0000 0101|~|<<|>>|
结果|0000 0001|0000 0111|0000 0110|0000 1100|0000 0110|0000 0001|