// pch.h: 这是预编译标头文件。
// 下方列出的文件仅编译一次，提高了将来生成的生成性能。
// 这还将影响 IntelliSense 性能，包括代码完成和许多代码浏览功能。
// 但是，如果此处列出的文件中的任何一个在生成之间有更新，它们全部都将被重新编译。
// 请勿在此处添加要频繁更新的文件，这将使得性能优势无效。

#ifndef PCH_H
#define PCH_H

// 添加要在此处预编译的标头
#include "framework.h"
#include <string>

extern "C++" _declspec(dllexport) std::string enAffine(std::string inData, int addKey, int mulKey);
extern "C++" _declspec(dllexport) std::string deAffine(std::string inData, int addKey, int mulKey);
extern "C++" _declspec(dllexport) std::string randomARC4key(int len);
extern "C++" _declspec(dllexport)	std::string encryRC4(std::string & inData, std::string & strKey, int len);
extern "C++" _declspec(dllexport) std::string decryRC4(std::string & inData, std::string & strKey, int len);
extern "C++" _declspec(dllexport) std::string enmsgMD5(std::string & msg);
extern "C++" _declspec(dllexport) bool checkmsgMD5(std::string & digest, std::string & msg);
extern "C++" _declspec(dllexport) std::string randomDesKey();
extern "C++" _declspec(dllexport) std::string randomIv();
extern "C++" _declspec(dllexport) std::string	encrypt3des(std::string & inData, std::string & strKey, std::string & eniv);
extern "C++" _declspec(dllexport) std::string decrypt3des(std::string & inData, std::string & strKey, std::string & eniv);
extern "C++" _declspec(dllexport) void getRsaKey(std::string pubfilename, std::string prifilename);
extern "C++" _declspec(dllexport) std::string checkRsaSigature(const std::string & pubfilename, const std::string & signature, const std::string & msg);
extern "C++" _declspec(dllexport) void getRSAOAEPkey(std::string pubfilename, std::string prifilename);
extern "C++" _declspec(dllexport) std::string encryRSAOAEP(std::string pubfilename, std::string plain);
extern "C++" _declspec(dllexport)std::string decryRSAOAEP(std::string prifilename, std::string cipher);


#endif //PCH_H
