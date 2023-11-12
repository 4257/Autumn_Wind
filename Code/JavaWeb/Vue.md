# Vue
## 引入Vue.js
```
<script src="js/vue.js"></script>

在JS代码区域，创建Vue核心对象，定义数据模型
<script>
    new Vue({
        el: "#app",
        data: {
            message: "Hello Vue!"
        }
    })
</script>

编写视图
<div id="app">
    <input type="text" v-model="message">
    {{ message }}
</div>
```
## 常用指令
```
v-bind        为HTML标签绑定属性值，如设置 href , css样式等

<a v-bind:href="url">传智教育</a>
<a :href="url">传智教育</a>
<script>
  new Vue({
     el: "#app",
     data: {
        url: "https://www.test.cn"
     }
  })
</script>

v-model       在表单元素上创建双向数据绑定

<input type="text" v-model="url">
v-on          为HTML标签绑定事件

<input type="button" value="按钮" v-on:click="handle()">
<input type="button" value="按钮" @click="handle()">

<script>
    new Vue({
        el: "#app",
        data: {
	//...
        },
        methods: {
            handle:function(){
                alert('我被点击了');
            }
        },
    })
</script>

v-if         
v-else-if     条件性的渲染某元素，判定为true时渲染,否则不渲染
v-else

年龄{{age}},经判定为:
<span v-if="age <= 35">年轻人</span>
<span v-else-if="age > 35 && age < 60">中年人</span>
<span v-else>老年人</span>

v-show        根据条件展示某元素，区别在于切换的是display属性的值

年龄{{age}},经判定为:
<span v-show="age <= 35">年轻人</span>

v-for         列表渲染，遍历容器的元素或者对象的属性
<div v-for="addr in addrs">{{addr}}</div>
<div v-for="(addr,index) in addrs">{{index + 1}} : {{addr}}</div>

data: {
   . . .
   addrs: ['北京','上海','广州','深圳','成都','杭州']
},
```
## Vue 生命周期
```
beforeCreate          创建前
created               创建后
beforeMount           挂载前
mounted               挂载完成
beforeUpdate          更新前
updated               更新后
beforeDestroy         销毁前
destroyed             销毁后
```
```
mounted：挂载完成，Vue初始化成功，HTML页面渲染成功。（发送请求到服务端，加载数据）
<script>
    new Vue({
        el: "#app",
        data: {
            
        },
        mounted() {
            console.log("Vue挂载完毕,发送请求获取数据");
        },
        methods: {
           
        },
    })
</script>
```
