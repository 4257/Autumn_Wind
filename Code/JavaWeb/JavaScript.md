![image](https://github.com/4257/Autumn_Wind/assets/49188843/1eba5c7f-bea3-4556-afa7-9d847a94423c)![image](https://github.com/4257/Autumn_Wind/assets/49188843/6802a58b-eea4-4bc2-a51e-7aaaddd40c57)![image](https://github.com/4257/Autumn_Wind/assets/49188843/6eba2ed8-0b09-4fbd-beea-3ae0e92e2e5e)![image](https://github.com/4257/Autumn_Wind/assets/49188843/3759efab-2eaf-4497-90a7-1a4088e53688)![image](https://github.com/4257/Autumn_Wind/assets/49188843/53d84d28-0bbc-49b9-a6f2-7ed5224ee29a)# JavaScript
```txt
HTML：负责网页的基本结构（页面元素和内容）。
CSS：负责网页的表现效果（页面元素的外观、位置等页面样式，如：颜色、大小等）。
JavaScript：负责网页的行为（交互效果）。
```
## JS引入方式
### 内部脚本
JavaScript代码必须位于<script></script>标签之间  
在HTML文档中，可以在任意地方，放置任意数量的<script>  
一般会把脚本置于<body>元素的底部，可改善显示速度  
```
<script>
    alert("Hello JavaScript")
</script>
```
### 外部引入
外部JS文件中，只包含JS代码，不包含`<script>`标签  
`<script>`标签不能自闭合  
```
<script src="js/demo.js"></script>

demo.js:

alert("Hello JavaScript")
```
## JS基础语法
### 输出语句
使用 window.alert() 写入警告框  
使用 document.write() 写入 HTML 输出  
使用 console.log() 写入浏览器控制台  
```
<script>
    window.alert("Hello JavaScript"); //浏览器弹出警告框
    document.write("Hello JavaScript"); //写入HTML,在浏览器展示
    console.log("Hello JavaScript"); //写入浏览器控制台
</script>
```
### 变量
```
特点：JS是弱类型语言，变量可以存放不同类型的值  
声明：  
	var：声明变量，全局作用域/函数作用域，允许重复声明  
	let：声明变量，块级作用域，不允许重复声明  
	const：声明常量，一旦声明，常量的值不能改变  
```
### 数据类型
```
number：数字（整数、小数、NaN(Not a Number)）
string：字符串，单双引皆可
boolean：布尔。true，false
null：对象为空
undefined：当声明的变量未初始化时，该变量的默认值是 undefined

使用 typeof 运算符可以获取数据类型：
var a = 20;
alert(typeof  a);
```
### 运算符
```
== 会进行类型转换，=== 不会进行类型转换
var a = 10;
alert(a == "10"); //true
alert(a === "10"); //false
alert(a === 10); //true

字符串类型转为数字：
将字符串字面值转为数字。 如果字面值不是数字，则转为NaN。
其他类型转为boolean：
Number：0 和 NaN为false，其他均转为true。
String：空字符串为false，其他均转为true。
Null 和 undefined ：均转为false。
```
## JS函数
JavaScript 函数通过 function 关键字进行定义，语法为:
```
function add(a , b){
    return a + b;
}
形式参数不需要类型。因为JavaScript是弱类型语言
返回值也不需要定义类型，可以在函数内部直接使用return返回即可
JS中，函数调用可以传递任意个数的参数。但只会接受定义的参数个数的参数
```
## JS对象
```
数组
JavaScript 中的数组相当于 Java 中集合，数组的长度是可变的，而 JavaScript 是弱类型，所以可以存储任意的类型的数据。
var arr = new Array(1,2,3,4);
var arr = [1,2,3,4];

length      设置或返回数组中元素的数量。

forEach()   遍历数组中的每个有值的元素，并调用一次传入的函数
push()      将新元素添加到数组的末尾，并返回新的长度。
splice()    从数组中删除元素。

字符
var str = new String("Hello String");
var str = "Hello String";

length          字符串的长度。
charAt()        返回在指定位置的字符。
indexOf()       检索字符串。
trim()          去除字符串两边的空格
substring()     提取字符串中两个指定的索引号之间的字符。

JSON
var user = {
    name:"Tom", 
    age:20, 
    gender:"male",
    eat: function(){
        alert("用膳~");
    }
};

var user = {
    name:"Tom", 
    age:20, 
    gender:"male",
    eat(){
        alert("用膳~");
    }
};

JSON字符串转为JS对象
var jsObject = JSON.parse(userStr);
JS对象转为JSON字符串
var jsonStr = JSON.stringify(jsObject);

BOM  浏览器对象模型

Window：浏览器窗口对象
  属性
       history：对 History 对象的只读引用。请参阅 History 对象。
       location：用于窗口或框架的 Location 对象。请参阅 Location 对象。
       navigator：对 Navigator 对象的只读引用。请参阅 Navigator 对象。
  方法
       alert()：显示带有一段消息和一个确认按钮的警告框。
       confirm()：显示带有一段消息以及确认按钮和取消按钮的对话框。
       setInterval()：按照指定的周期（以毫秒计）来调用函数或计算表达式。
       setTimeout()：在指定的毫秒数后调用函数或计算表达式。

Navigator：浏览器对象
Screen：屏幕对象
History：历史记录对象
Location：地址栏对象

DOM  文档对象模型

Document：整个文档对象
Element：元素对象
Attribute：属性对象
Text：文本对象
Comment：注释对象

HTML DOM - HTML 文档的标准模型
Image：<img>
Button ：<input type='button'>

根据id属性值获取，返回单个Element对象
var h1 = document.getElementById('h1');
根据标签名称获取，返回Element对象数组
var divs = document.getElementsByTagName('div');
根据name属性值获取，返回Element对象数组
var hobbys = document.getElementsByName('hobby');
根据class属性值获取，返回Element对象数组
var clss = document.getElementsByClassName('cls');
```
## JS事件监听
### 事件绑定
#### 一:通过 HTML标签中的事件属性进行绑定
```
<input type="button" onclick="on()" value="按钮1">

<script>
    function on(){
        alert('我被点击了!');
    }
</script>
```
#### 二：通过 DOM 元素属性绑定
```
<input type="button" id="btn" value="按钮2">

<script>
    document.getElementById('btn').onclick=function(){
        alert('我被点击了!');
    }
</script>
```
### 常见事件
```
onclick          鼠标单击事件
onblur           元素失去焦点
onfocus          元素获得焦点
onload           某个页面或图像被完成加载
onsubmit         当表单提交时触发该事件
onkeydown        某个键盘的键被按下
onmouseover      鼠标被移到某元素之上
onmouseout       鼠标从某元素移开
```


