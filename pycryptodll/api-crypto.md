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

