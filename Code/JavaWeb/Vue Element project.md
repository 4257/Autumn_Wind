# Vue
安装`NodeJs`
安装vue`npm install -g @vue/cli`
`vue create vue-project01`
`vue ui`
```
vue.config.js

const { defineConfig } = require('@vue/cli-service')
module.exports = defineConfig({
  transpileDependencies: true,
  devServer: {
    port: 7000,
  }
})
```
## Vue 项目开发流程
```
Vue的组件文件以 .vue结尾，每个组件由三个部分组成：
<template>      模板部分，由它生成HTML代码
<script>        控制模板的数据来源和行为
<style>         css样式部分
```
## Element
安装:`npm install element-ui@2.15.3`
```
main.js

import ElementUI from 'element-ui';
import 'element-ui/lib/theme-chalk/index.css';
Vue.use(ElementUI);
```
## 使用Axios
```
Vue项目中使用Axios:
在项目目录下安装axios：npm  install axios;
需要使用axios时，导入axios：import axios from 'axios';
```
## Vue路由
VueRouter：路由器类，根据路由请求在路由视图中动态渲染选中的组件  
<router-link>：请求链接组件，浏览器会解析成<a>  
<router-view>：动态视图组件，用来渲染展示与路由路径对应的组件  
安装`npm install vue-router@3.5.1`  
```
在route->index.js中写入
  {
    path: '/page1',
    name: 'page1',
    component: () => import('../views/page/page1.vue')
  }
在需要跳转的标签中写入请求链接
<router-link to="/page1">页面一</router-link>
在main.js中启用动态视图组件
<router-view></router-view>
```
