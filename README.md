# UnExInfo
一种收集敏感信息的Burp插件

cpoy大神 [https://github.com/ScriptKid-Beta/Unexpected_information](https://github.com/ScriptKid-Beta/Unexpected_information)

#### 修改
1. 增加了特殊格式自动过滤
2. 优化了性能
3. jdk11

#### 介绍

##### 支持列表

- [x] 身份证信息
- [x] 手机号信息
- [x] IP信息
- [x] 邮箱信息
- [x] JS文件API接口路径
- [x] JS文件URL
- [x] 特殊字段
- [x] JSON Web Token
- [x] Shiro(rememberMe=delete)
- [x] 双向检测
- [x] 高亮显示

##### 高亮模式

```
邮箱 -> 黄色
内网IP -> 红色
手机号码 -> 绿色
身份证号码 -> 绿色
其他 -> 灰色(v2.3.1+)
```

当如数据包中存在有相关的对应信息(如手机号码、IP地址、邮箱、身份证号码等)存在时HTTP history标签页中的对应请求中自动标记颜色高亮，并且开启一个新的标签页名为”Unexpected information”显示匹配到的信息。

#### 如何使用

```
BurpSuite >> Extender >> Extensions >> Add >> Extension type: Java >> Select file ...>> 选择对应的插件(Unexpected information.jar)
注意：避免使用中文目录
```

