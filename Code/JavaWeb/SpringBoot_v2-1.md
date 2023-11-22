![image](https://github.com/4257/Autumn_Wind/assets/49188843/759b3e35-6fa5-4900-aa78-d9c3be22c99f)# 请求参数
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
# 响应数据
使用方法注解 或者类注解的方式 将方法返回值直接响应 如果返回值类型是 实体对象/集合 将会转换为JSON格式响应  
@RestController = @Controller + @ResponseBody;  
## 统一响应结果

## 分层解耦
controller：控制层 接收前端发送的请求 对请求进行处理 并响应数据  
service：业务逻辑层 处理具体的业务逻辑  
dao：数据访问层(Data Access Object)（持久层） 负责数据访问操作 包括数据的增 删 改 查   

控制反转： Inversion Of Control 简称IOC 对象的创建控制权由程序自身转移到外部（容器）这种思想称为控制反转  
依赖注入： Dependency Injection 简称DI 容器为应用程序提供运行时，所依赖的资源，称之为依赖注入  
Bean对象：IOC容器中创建 管理的对象 称之为bean  
### IOC
```
@Component        声明bean的基础注解        不属于以下三类时，用此注解
@Controller       @Component的衍生注解      标注在控制器类上
@Service          @Component的衍生注解      标注在控制器类上
@Repository       @Component的衍生注解      标注在数据访问类上（由于与mybatis整合，用的少）

声明bean的时候，可以通过value属性指定bean的名字，如果没有指定，默认为类名首字母小写。
使用以上四个注解都可以声明bean，但是在springboot集成web开发中，声明控制器bean只能用@Controller

前面声明bean的四大注解，要想生效，还需要被组件扫描注解@ComponentScan扫描。
@ComponentScan注解虽然没有显式配置，但是实际上已经包含在了启动类声明注解
@SpringBootApplication 中，默认扫描的范围是启动类所在包及其子包。
```
### DI
```
@Autowired：默认按照类型自动装配。
如果同类型的bean存在多个：
@Primary
@Autowired + @Qualifier("bean的名称")
@Resource(name="bean的名称")

@Autowired 是spring框架提供的注解，而@Resource是JDK提供的注解。
@Autowired 默认是按照类型注入，而@Resource默认是按照名称注入。
```
