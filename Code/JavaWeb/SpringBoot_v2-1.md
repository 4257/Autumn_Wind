# 请求参数
## 简单参数
### 原始方式
在原始的web程序中，获取请求参数，需要通过`HttpServletRequest`对象手动获取
```java
@RequestMapping("/simpleParam")
public String simpleParam(HttpServletRequest request){
    String name = request.getParameter("name");
    String ageStr = request.getParameter("age");
    int age = Integer.parseInt(ageStr);
    System.out.println(name+"  :  "+age);
    return "OK";
}
```
### SpringBoot方式
简单参数：参数名与形参变量名相同，定义形参即可接收参数
```java
@RequestMapping("/simpleParam")
public String simpleParam(String name , Integer age){
    System.out.println(name+"  :  "+age);
    return "OK";
}
```
简单参数：如果方法形参名称与请求参数名称不匹配，可以使用 `@RequestParam` 完成映射  
`@RequestParam`中的required属性默认为true，代表该请求参数必须传递，如果不传递将报错 如果该参数是可选的，可以将`required`属性设置为`false`
```java
@RequestMapping("/simpleParam")
public String simpleParam(@RequestParam(name = "name") String username , Integer age){
    System.out.println(username + " : " + age);
    return "OK";
}
```
## 实体参数
简单实体对象：请求参数名与形参对象属性名相同，定义POJO接收即可
```java
@RequestMapping("/simplePojo")
public String simplePojo(User user){
    System.out.println(user);
    return "OK";
}
```
```java
//实体对象
public class User {
    private String name;
    private Integer age;
}
```
复杂实体对象：请求参数名与形参对象属性名相同，按照对象层次结构关系即可接收嵌套POJO属性参数。
```java
@RequestMapping("/complexPojo")
public String complexPojo(User user){
    System.out.println(user);
    return "OK";
}
```
```java
//实体对象
public class User {
    private String name;
    private Integer age;
    private Address address;
}

//address对象
public class Address {
    private String province;
    private String city;
}
```
## 数组集合参数
数组参数：请求参数名与形参数组名称相同且请求参数为多个，定义数组类型形参即可接收参数
```java
@RequestMapping("/arrayParam")
public String arrayParam(String[] hobby){
    System.out.println(Arrays.toString(hobby));
    return "OK";
}
```
集合参数：请求参数名与形参集合名称相同且请求参数为多个 `@RequestParam` 绑定参数关系
```java
@RequestMapping("/listParam")
public String listParam(@RequestParam List<String> hobby){
    System.out.println(hobby);
    return "OK";
}
```
## 日期参数
日期参数：使用 `@DateTimeFormat` 注解完成日期参数格式转换 
```java
@RequestMapping("/dateParam")
public String dateParam(@DateTimeFormat(pattern = "yyyy-MM-dd HH:mm:ss") LocalDateTime updateTime){
    System.out.println(updateTime);
    return "OK";
}
```
## Json参数
JSON参数：JSON数据键名与形参对象属性名相同 定义POJO类型形参即可接收参数 需要使用 `@RequestBody` 标识
```java
@RequestMapping("/jsonParam")
public String jsonParam(@RequestBody User user){
    System.out.println(user);
    return "OK";
}
```
```
//实体对象
public class User {
    private String name;
    private Integer age;
    private Address address;
}

//address对象
public class Address {
    private String province;
    private String city;
}
```
## 路径参数
路径参数：通过请求URL直接传递参数 使用{…}来标识该路径参数 需要使用 `@PathVariable` 获取路径参数
```java
@RequestMapping("/path/{id}")
public String pathParam(@PathVariable Integer id){
    System.out.println(id);
    return "OK";
}
```
```
@RequestMapping("/path/{id}/{name}")
public String pathParam2(@PathVariable Integer id, @PathVariable String name){
    System.out.println(id+ " : " +name);
    return "OK";
}
```
