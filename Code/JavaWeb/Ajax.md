# Ajax
## 原生Ajax
```
<body>
    <input type="button" value="获取数据" onclick="getData()">
    <div id="div1"></div></body>

<script>
    function getData(){
        //1. 创建XMLHttpRequest 
        var xmlHttpRequest  = new XMLHttpRequest();
        //2. 发送异步请求
        xmlHttpRequest.open('GET','http://yapi.smart-xwork.cn/mock/169327/emp/list');
        xmlHttpRequest.send();//发送请求
        //3. 获取服务响应数据
        xmlHttpRequest.onreadystatechange = function(){
            if(xmlHttpRequest.readyState == 4 && xmlHttpRequest.status == 200){
                document.getElementById('div1').innerHTML = xmlHttpRequest.responseText;
            }
        }
    }
</script>
```
## Axios
Axios 对原生的Ajax进行了封装，简化书写，快速开发。
```
引入Axios的js文件
<script src="js/axios-0.18.0.js"></script>

使用Axios发送请求，并获取响应结果
axios({
    method: "get",
    url: "http://yapi.smart-xwork.cn/mock/169327/emp/list"
}).then((result) => {
    console.log(result.data);
});

axios({
    method: "post",
    url: "http://yapi.smart-xwork.cn/mock/169327/emp/deleteById",
    data: "id=1"
}).then((result) => {
    console.log(result.data);
});
```
### 请求方式别名
```
axios.get(url [, config])
axios.delete(url [, config])
axios.post(url [, data[, config]])
axios.put(url [, data[, config]])

axios.get("http://yapi.smart-xwork.cn/mock/169327/emp/list").then((result) => {
    console.log(result.data);
});

axios.post("http://yapi.smart-xwork.cn/mock/169327/emp/deleteById","id=1").then((result) => {
    console.log(result.data);
});
```
