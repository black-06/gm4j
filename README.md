## 关于

[English](https://github.com/black-06/gm4j/wiki/English-Page)

gm4j 是国密算法的 java 实现,参见[密码行业标准化技术委员会](http://www.gmbz.org.cn/)

## 功能

* SM3 杂凑算法
* SM2 消息的签名与验证
* SM2 秘钥交换
* 其他 GM 算法正在实现中...
* 一个加密服务提供者
* 一个简单的加密工具类

## 使用

**计算 byte[] 的 SM3 的杂凑值**

```java
byte[] abc = "abc".getBytes(StandardCharsets.US_ASCII);
GMUtil.sm3(abc);
// or
GMProvider provider = new GMProvider();
MessageDigest digest = MessageDigest.getInstance("SM3", provider);
digest.digest(abc);
```

**计算字符串的 SM3 杂凑字符串**

```java
GMUtil.sm3("abc");
```

**计算字符串的 SM3 杂凑字符串,并转换为 16 进制字符串**

```java
GMUtil.sm3Hex("abc");
```

## 其他

**1.版权声明**

此代码使用 [Apache Licence v2](https://www.apache.org/licenses/LICENSE-2.0) 协议.

**2.联系我**

hello.bug@foxmail.com