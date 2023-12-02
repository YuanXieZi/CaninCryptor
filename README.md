# CaninCryptor
Encapsulated some common encryption algorithms using the Bouncycastle library  Such as RSA/AES/DES/3DES/Rijndael,etc
# For example 
如果你想要使用Rijndael加密
你可以选择ECB,CBC,CFB,OFB,CTR模式
下为示例代码
```java
    public static void main(String[] args) {
        RijndaelTool rijndaelTool = new RijndaelTool(true, "12345678123456781234567812345678".getBytes(), "123456781234567812345678".getBytes(), WorkMode.CBC, Paddings.ZERO, 192);
        byte[] en = rijndaelTool.processingBytes("demo rijndael".getBytes());
        rijndaelTool = new RijndaelTool(false , "12345678123456781234567812345678".getBytes(), "123456781234567812345678".getBytes(), WorkMode.CBC, Paddings.ZERO, 192);
        System.out.println(new String(rijndaelTool.processingBytes(en)));
    }
```
## 其中
bool参为是否加密，2,3参为key和iv,4,5是工作模式和填充模式
6是keyBits长度，取决于你的key,iv和工作模式
## 控制台输出为
demo rijndael
# 剩余加密方式可自行查看源码使用
