# HTML-CSS
相关内容直接参照 [w3school](https://www.w3school.com.cn/index.html)
## Html结构
```html
<html>
	<head>    
		   <title>标题</title>
	</head>
	<body>
    
	</body>
</html>
```

# CSS
## CSS引入方式
### 行内样式
写在标签的style属性中(不推荐)
```css
<h1 style="xxx: xxx; xxx: xxx;">中国新闻网</h1>
```
### 内嵌样式
写在style标签中（可以写在页面任何位置，但通常约定写在head标签中）
```css
<style>
  h1 {
     xxx: xxx; 
     xxx: xxx;
  }
</style>
```
### 外联样式
写在一个单独的.css文件中（需要通过 link 标签在网页中引入）  
通常放在head标签中
```css
<link rel="stylesheet" href="css/news.css">
//文件内容
h1 {
   xxx: xxx; 
   xxx: xxx;
}
```
## CSS选择器
### 元素选择器
```css
元素名称 {
    color: red;
}

h1 {
    color: red;
}

<h1> Hello CSS </h1>
```
### ID选择器
```css
#id属性值 {
    color: red;
}

#hid {
    color: red;
}

<h1 id="hid"> CSS id Selector</h1>
```
### 类选择器
```css
.class属性值 {
    color: red;
}

.cls {
    color: red;
}

<h1 class="cls">CSS class Selector</h1>
```

