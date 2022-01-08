# Crypto++实现常用加密算法

加密算法实现部分：通过Crypto++库对常用算法进行实现与再封装。

源代码：https://github.com/ShenTiao/cryptoSchoolProject.git

<!--more-->

## 依赖

### Crypto++

Crypto++ 库是开源的 C++ 数据加密算法库，支持如下算法：RSA、MD5、DES、AES、SHA-256 等等，其中对于加密有对称加密和非对称加密。本实验通过 Cryto++ 库对字符串进行 MD5 校验，并用 AES 加密和解密。

[官网](https://cryptopp.com/) [手册](https://cryptopp.com/docs/ref/) [wiki及代码示例](https://www.cryptopp.com/wiki)

#### 安装依赖库

环境：Windows 10 64bit，VS2019。

首先官网Download-Release Notes下载最新压缩包。

下载后解压缩，找到解决方案cryptlib.sln，单独对cryplib进行生成：

![image-20211206170314034](https://s2.loli.net/2021/12/06/2R7Lig8oeplqjAs.png)

配置Release或者Debug或者两者都在x64环境下进行生成，可以在根目录x64/Output/Release下看到已经生成的lib库(以release为例)。

#### 建立SDK

建立一个目录CryptoPP，这里以C:\Program Files\CryptoPP为例，目录下新建目录include和lib，将生成好的lib库放在lib目录下：lib\Release。将解压缩的源文件所有cpp与h文件放置在include目录下。

在VS2019新建一个项目，修改项目配置：

![image-20211206170814097](https://s2.loli.net/2021/12/06/g8PNbseVpDaEqF4.png)

包含目录即刚刚创建的include文件目录，库目录即lib目录。注意：

![image-20211206170900318](https://s2.loli.net/2021/12/06/o93iwY4RUHyqS5v.png)

将运行库切换成/MT模式，链接器配置：

![image-20211206171045887](https://s2.loli.net/2021/12/06/ILkiNmDwXy7RZPY.png)

否则链接失败。



### pybind11

[github](https://github.com/pybind/pybind11)	[文档](https://pybind11.readthedocs.io/en/stable/)	

**pybind11**是一个轻量级的header-only库，它在 Python 中公开 C++ 类型，反之亦然，主要用于创建现有 C++ 代码的 Python 绑定。

核心特性：

![image-20211206171313554](https://s2.loli.net/2021/12/06/ZQMfBw9J1kzj8XK.png)

pybind11可以很好地将C++代码打包成dll库，windows上的pyd文件来导入python代码。

安装pybind11过程与crypto++类似，不同的是pybind11是header-only文件，只需要配置包含目录和库目录与链接依赖项，同时python本身的lib文件与include路径也需要同样添加进去。



### 第一段测试代码

#### C++

打包一段简单的MD5校验代码：

```C++
#include <pybind11/pybind11.h>
#include <md5.h>
#include <hex.h>
#include <files.h>
#include <osrng.h>
#include <filters.h>
#include <default.h>
#include <string>
#define _CRYPTO_UTIL_H_
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

namespace py = pybind11;
using namespace CryptoPP;

std::string& retMD5(std::string& data) {
	std::string digest;
	Weak1::MD5 md5;
	StringSource(data, true, new HashFilter(md5, new HexEncoder(new StringSink(digest))));
	return digest;
}

PYBIND11_MODULE(pycryptodll, m) {
	m.def("retMD5", &retMD5, "return the MD5 value");
}
```

编译提示：

`You may be using a weak algorithm that has been retained for backwards compatibility. Please '#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1' before including this .h file and prepend the class name with 'Weak::' to remove this warning.`

使用向后兼容的弱算法需要添加宏：

`#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1'`

注意22行`pycryptodll`处内容需要与项目同名，否则python解释器报错。

`PYBIND11_MODULE()`宏创建了一个函数，当`import`从 Python 中发出语句时将调用该函数 。模块名称 ( `example`) 作为第一个宏参数给出（不应包含在引号中）。第二个参数 ( `m`) 定义了一个类型变量，`py::module_`它是创建绑定的主要接口。该方法module_::def() 生成将`add()`函数公开给 Python 的绑定代码。

#### Python运行

```python
import pycryptodll
print(m.retMD5("123131"))
```

将pyd文件与py文件放在同目录下，输入以上代码即可调用函数。



# 加密部分

## 对称加密算法部分

### AES(CBC mode)

AES 采用的是对称加密，在密码学中又称 Rijndael 加密法，是美国联邦政府采用的一种区块加密标准。这个标准用来替代原先的 DES ，已经被多方分析且广为全世界所使用。 本次使用CBC模式，密码分组链接模式（CBC模式）：这种模式是先将明文切分成若干小段，然后每一小段与初始块或者上一段的密文段进行异或运算后，再与密钥进行加密。

加密流程图：

![image-20211207170621804](https://s2.loli.net/2021/12/07/Ou7JMUXEsKTpZ8I.png)

CBC模式:

![image-20211207171108714](https://s2.loli.net/2021/12/07/12ETvCjLok9aRbn.png)

AES密钥长度要求：

```cpp
enum AESKeyLength
{
    AES_KEY_LENGTH_16 = 16, AES_KEY_LENGTH_24 = 24, AES_KEY_LENGTH_32 = 32 
};
```

判断密钥长度是否满足：

```cpp
if (inData.empty() || Key.empty()) // 判断待加密的字符串或者密钥是否为空
    {
        errMsg = "indata or key is empty!!";
        return errMsg;
    }
unsigned int iKeyLen = Key.length();

    if (iKeyLen != AES_KEY_LENGTH_16 && iKeyLen != AES_KEY_LENGTH_24  //判断密钥的长度是否符合要求
        && iKeyLen != AES_KEY_LENGTH_32)
    {
        errMsg = "aes key invalid!!";
        return errMsg;
    }
```

MD5生成密钥必定满足32字节：

```cpp
//加密密钥key:MD5生成32字节密钥
const std::string encryAeskey(std::string& strKey) {
    const std::string Key = retMD5(strKey);
    return Key;
}
```

生成密文：

```cpp
try
    {
        CBC_Mode<AES>::Encryption e;  //CBC 模式加密
        e.SetKeyWithIV((byte*)Key.c_str(), iKeyLen, iv);
        //加密的关键， outData 就是加密后的数据
        StringSource ss(inData, true, new StreamTransformationFilter(e, new StringSink(outData)));    
    }
    catch (const CryptoPP::Exception& e)
    {
        errMsg = "Encryptor throw exception!!";
        return errMsg;
    }
```

接口函数：

```cpp
//将输入Key经过MD5加密生成的32字节密钥，返回密钥值，
const std::string encryAeskey(std::string& strKey) 
 
//AES加密函数，inData为明文，strKey为MD5加密前输入的key CBC下iv，返回加密字符串
std::string encrypt4aes(const std::string& inData,std::string& strKey,std::string& iv)
//AES解密函数 inData密文 strKey解密密钥 CBC下iv，返回解密字符串
std::string decrypt4aes(const std::string& inData, const std::string& strKey,std::string& iv)
```



### 3DES(CBC mode)

DES 使用一个 56 位的密钥以及附加的 8 位奇偶校验位，产生最大 64 位的分组大小。这是一个迭代的分组密码，使用称为 Feistel 的技术，其中将加密的文本块分成两半。使用子密钥对其中一半应用循环功能，然后将输出与另一半进行“异或”运算；接着交换这两半，这一过程会继续下去，但最后一个循环不交换。DES 使用 16 个循环，使用异或，置换，代换，移位操作四种基本运算。

TripleDES,是对纯文本数据的DES算法的多重应用，以增加原有DES算法的安全性。顾名思义，DES算法被应用了3次。TripleDES有两种变体:第一种是两个key;第二个是三个key。2-key TDEA提供大约80位的安全性，而3-key TDEA提供大约112位的安全性。相反，AES提供的最低安全级别为128。

本次实现2 Key Triple DES:

单次DES加密流程图：![image-20211208164432707](https://s2.loli.net/2021/12/08/VfpBGEvOU4dyZtr.png)

**上图左半部分描述了明文加密成密文的三个阶段。**

　　1、64位的明文经初始置换（IP）而重新排列。

　　2、进行16轮的置换和转换（基于Feistel结构）。

　　3、再做一次置换（IP-1，与初始置换互逆）。

**加密过程与解密过程基本一致。**

**上图右半部分是56位密钥的操作过程。**

　　1、密钥先做一个置换。

　　2、再做16次包含循环左移和置换的操作组合，每次都产生一个子密钥Ki。每一轮的置换操作都完全相同，但由于循环左移而使得每个子密钥不同。

**TripleDES总流程：**

![image-20211208171402234](https://s2.loli.net/2021/12/08/89unBC1RcSaLhyg.png)

忽略奇偶校验位。

2key变体的块大小为8字节(64位)，并使用一个16字节的密钥。

BC模式:

![image-20211207171108714](https://s2.loli.net/2021/12/07/12ETvCjLok9aRbn.png)





## 流密码部分

### RC4

加密流程图：

![image-20211213134030006](https://s2.loli.net/2021/12/13/9WrERUSM4ZjBQLl.png)

RC4包括初始化算法KSA，伪随机子密码生成算法PRGA两部分，S盒长度假设为256，密钥长度可配置。

一般key长度为1-256，crypto++中默认为16.

RC4作为流密码，该密码使用 40 位到 2048 位的密钥，并且没有初始化向量(iv)。

注意密钥长度：

> ```
> key length(default): 16
> key length (min): 1
> key length (max): 256
> iv size: 0
> ```



## 非对称加密

### RSA

crypto++库提供高级RSA加密和原始RSA加密方案。这里使用OAEP-SHA加密方案，最优非对称加密填充OAEP，OAEP对IND-CCA2是可证明安全的。由Bellare和Rogaway提出，是一种随机化的消息填充技术，而且是从消息空间到一个陷门单向置换（OWTP）定义域的一个易于求逆的变换。

![image-20211229173627961](https://s2.loli.net/2021/12/29/twzLFS8pVYCKmfy.png)

 OAEP变换是把密码学杂凑函数和一个著名对称密码算法结构结合起来构造的。OAEP构造可以看成是一个两轮Feistel密码，第一轮使用杂凑函数G，第二轮使用杂凑函数H，代替Feistel密码的“s盒函数”，但这里的两个“s盒函数”不是加密钥，而且两个半分组的大小可以不同。这里函数H即SHA。



## 消息认证

### MD5

**MD5信息摘要算法**（英语：MD5 Message-Digest Algorithm），一种被广泛使用的散列函数可以产生出一个128位的散列值。

由于MD5存在弱点，难以防止碰撞攻击，不适用于安全性认证。

MD5算法的原理可简要的叙述为：MD5码以512位分组来处理输入的信息，且每一分组又被划分为16个32位子分组，经过了一系列的处理后，算法的输出由四个32位分组组成，将这四个32位分组级联后将生成一个128位散列值。总体流程如下图所示，每次的运算都由前一轮的128位结果值和当前的512bit值进行运算。

Crypto++中md5内在Weak1命名空间中，使用pipeline来获取消息摘要并验证消息完整性。



## 数字签名

使用RSA-PSS进行数字签名。

签名过程：

![image-20211222155820581](https://s2.loli.net/2021/12/22/Ccnq5ymxolKSWwe.png)

需要输入待编码的消息内容和emBits比RSA模数n位长度小的值，输出em编码之后的内容。

填充1paddding1十六进制字符串00 00·····,填充2如图。

加盐salt一组伪随机数。

> 编码过程有如下步骤：
>
> 1. 生成消息M 的Hash值，mHash = Hash(M)
> 2. 生成伪随机字节串作为盐，得到M’ = padding1 || mHash || salt 的数据块
> 3. 生成M’ 的Hash值，H = Hash(M’)
> 4. 构造数据块DB = padding2 || salt
> 5. 计算H 的MGF值：dbMask = MGF(H, emLen - hLen - 1)
> 6. 计算maskedDB = DB xor dbMask
> 7. 将maskedDB 的最左8emLen - emBits设为0
> 8. EM = maskedDB || H || BC

这里哈希使用SHA256，公钥私钥以文件形式保存，读取。



## DH认证协议

Diffie-Hellman是一种密钥协商算法，它允许两方建立安全的通信通道。最初的 Diffie-Hellman 是一种匿名协议，这意味着它没有经过身份验证，因此容易受到中间人攻击。Crypto++ 通过`DH`类公开未经身份验证的协议。对原始 Diffie-Hellman 的扩展包括身份验证，它强化了交换协议以抵御许多中间人攻击。Diffie-Hellman 的认证版本通常称为统一 Diffie-Hellman。Crypto++ 通过其`DH2`类提供统一的 Diffie-Hellman 。

注意，这个密钥交换协议/算法只能用于密钥的交换，而不能进行消息的加密和解密。双方确定要用的密钥后，要使用其他对称密钥操作加密算法实现加密和解密消息。

![image-20211231163007834](https://s2.loli.net/2021/12/31/Xz3UL47ZMiJmhpF.png)



## 接口部分

c++ dll打包接口：
```cpp
std::string enAffine(std::string inData,int addKey,int mulKey) 
std::string deAffine(std::string inData, int addKey, int mulKey)

std::string randomARC4key(int len)
std::string encryRC4(std::string& inData, std::string& strKey, int len)
std::string decryRC4(std::string& inData, std::string& strKey, int len)

std::string enmsgMD5(std::string& msg)
bool checkmsgMD5(std::string& digest, std::string& msg)

std::string randomDesKey()
std::string randomIv()
std::string	encrypt3des(std::string& inData, std::string& strKey, std::string& eniv)
std::string decrypt3des(std::string& inData, std::string& strKey, std::string& eniv)

void getRsaKey(std::string pubfilename,std::string prifilename) 
std::string getRsaSignature(const std::string& prifilename,const std::string& msg)
std::string checkRsaSigature(const std::string& pubfilename, const std::string& signature,const std::string& msg)

void getRSAOAEPkey(std::string pubfilename, std::string prifilename)
std::string encryRSAOAEP(std::string pubfilename, std::string plain)
std::string decryRSAOAEP(std::string prifilename, std::string cipher)

    
```

pybind11打包接口：

```c++
	//Affine
    m.def("encryAffine", &enAffine);
    m.def("decryAffine", &deAffine);
    //ARC4
    m.def("randomARC4key)", &randomARC4key);
    m.def("encryRC4", &encryRC4);
    m.def("decryRC4", &decryRC4);
    //MD5
    m.def("enmsgMD5", &enmsgMD5);
    m.def("checkmsgMD5", &checkmsgMD5);
    //DES
    m.def("randomDesKey", &randomDesKey);
    m.def("randomIv", &randomIv);
    m.def("encrypt3des", &encrypt3des);
    m.def("decrypt3des", &decrypt3des);
    //rsa pss签名
    m.def("getRsaKey", &getRsaKey);
    m.def("getRsaSignature", &getRsaSignature);
    m.def("checkRsaSigature", &checkRsaSigature);
    //rsa oaep加密
    m.def("getRSAOAEPkey", &getRSAOAEPkey);
    m.def("encryRSAOAEP", &encryRSAOAEP);
    m.def("decryRSAOAEP", &decryRSAOAEP);
```



# 界面部分

### 界面效果

![image-20220108144322752](https://s2.loli.net/2022/01/08/Goa2fYiTd9VLr7K.png)

![image-20220108144331220](https://s2.loli.net/2022/01/08/KvMFrj5aD3lgE46.png)

![image-20220108144340061](https://s2.loli.net/2022/01/08/IwQj7EuyFoqTrfU.png)

### 界面实现

使用PyQt5实现，其中DH部分使用cryptography库简单实现。

使用Qt Designer画出界面后，使用uic工具生成py代码。

信号绑定：

```python
#信号绑定
    def init(self):
        #TAB1
        self.encryChooseBox.currentIndexChanged.connect(self.changeMethodStr)
        self.inputClearPush.clicked.connect(self.clearInputTextBox)
        self.outputClearPush.clicked.connect(self.clearOutputTextBox)
        self.enCryPush.clicked.connect(self.enCryptAccess)
        self.affineArgA.textChanged.connect(self.changeAffineArgsA)
        self.affineArgP.textChanged.connect(self.changeAffineArgsP)
        self.arc4KeyLen.textChanged.connect(self.changeARC4KeyLen)
        self.pubkeyFileName.textChanged.connect(self.changeRsaPubFileName)
        self.prikeyFileName.textChanged.connect(self.changeRsaPriFileName)
        #TAB2
        self.decryChooseBox.currentIndexChanged.connect(self.changeDeMethodStr)
        self.inputClearPush_Tab2.clicked.connect(self.clearInputTextBox_2)
        self.outputClearPush_Tab2.clicked.connect(self.clearOutputTextBox_2)
        self.keyClearPush.clicked.connect(self.clearKeyPut)
        self.deCryPush.clicked.connect(self.deCryptAccess)
        self.affineArgA_Tab2.textChanged.connect(self.changeAffineArgsA_2)
        self.affineArgP_Tab2.textChanged.connect(self.changeAffineArgsP_2)
        self.arc4KeyLen_Tab2.textChanged.connect(self.changeARC4KeyLen_2)
        self.pubkeyFileName_Tab2.textChanged.connect(self.changeRsaPubFileName_2)
        self.prikeyFileName_Tab2.textChanged.connect(self.changeRsaPriFileName_2)
        #TAB3
        self.clientIpText.textChanged.connect(self.changeClientIp)
        self.clientPortText.textChanged.connect(self.changeClientPort)
        self.getLocalIpPush.clicked.connect(self.getLocalIp)
        self.openLinkPush.clicked.connect(self.openLink)
        self.closeLinkPush.clicked.connect(self.closeLink)
        self.clearDhInput.clicked.connect(self.clearDhin)
        self.clearDhOutput.clicked.connect(self.clearDhout)
        self.clearMsgOutput.clicked.connect(self.clearMsgout)
        self.signalLinkWrite.connect(self.linkMsgPrint)
        self.sendMsgPush.clicked.connect(self.sendMsg)
        self.serverPubKeyPush.clicked.connect(self.getServerPubKey)
        self.sendServerPubkey.clicked.connect(self.passServerPubKey)
        self.sendClientPubPara.clicked.connect(self.sendPubPara)
        self.creServerSharedKey.clicked.connect(self.getSeverSharedKey)
        self.waitClientPubKey.textChanged.connect(self.getClientPubKey)
```
