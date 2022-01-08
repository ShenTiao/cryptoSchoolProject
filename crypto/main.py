from PyQt5.QtWidgets import QApplication,QMessageBox,QMainWindow
from PyQt5 import QtCore
import stopThreading
from MainWindow import Ui_MainEncryForm
import pycryptodll as pycry
import threading
import socket

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.serialization import ParameterFormat
from cryptography.hazmat.primitives.serialization import PrivateFormat
from cryptography.hazmat.primitives import serialization

# 从客户端接收后传入参数

class States(Ui_MainEncryForm,QMainWindow):
    signalLinkWrite = QtCore.pyqtSignal(str)
    def __init__(self):
        #初始化
        super(States, self).__init__()
        self.setupUi(self)
        self.setWindowTitle("加密工具")

        #加密方式 TAB1
        self.cryMethodStr = 0
        #解密方式 TAB2
        self.deMethodStr = 0

        #加密变量 TAB1
        self.input = ''
        self.output = ''
        self.key = ''
        self.signature = ''
        self.iv = ''
        #仿射加密变量
        self.affineA = 0
        self.affineP = 0
        #RC4加密变量
        self.rc4KeyLen = 0
        #RSA
        self.pubFile = ''
        self.priFile = ''

        #解密变量 TAB2
        self.input_tab2 = ''
        self.output_tab2 = ''
        self.key_tab2 = ''
        self.signature_tab2 = ''
        self.iv_tab2 = ''
        # 仿射加密变量
        self.affineA_tab2 = 0
        self.affineP_tab2 = 0
        # RC4加密变量
        self.rc4KeyLen_tab2 = 0
        # RSA
        self.pubFile_tab2 = ''
        self.priFile_tab2 = ''

        #DH协议
        self.parameters = None
        self.serverPriKey = None
        self.serverPubKey = None
        self.clientPubKey = None
        self.serverSharedKey = None
        self.encodeParameter = None
        self.encodeServerPriKey = None
        self.encodeServerPubKey = None
        self.encodeClientPubKey = None

        #TCP
        self.clientIp = ''
        self.clientPort = None
        self.serverSocket = None
        self.dataSocket = None
        self.clientAddr = None

        self.init()

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

    #TAB1 slot
    def changeMethodStr(self,i):
        self.cryMethodStr = i

    def clearInputTextBox(self):
        self.inputText.clear()

    def clearOutputTextBox(self):
        self.outputText.clear()

    def changeAffineArgsA(self):
        self.affineA = self.affineArgA.text()

    def changeAffineArgsP(self):
        self.affineP = self.affineArgP.text()

    def changeARC4KeyLen(self):
        self.rc4KeyLen = self.arc4KeyLen.text()

    def changeRsaPubFileName(self):
        self.pubFile = self.pubkeyFileName.text()

    def changeRsaPriFileName(self):
        self.priFile = self.prikeyFileName.text()

    def enCryptAccess(self):
        #AFFINE
        if self.cryMethodStr == 0:
            #输入文本转换成字符串
            self.input = self.inputText.toPlainText()
            if self.input == '':
                QMessageBox.critical(
                    self,
                    '输入错误',
                    '待处理文本不能为空'
                )
                return
            if int(self.affineA) <= 0 or int(self.affineP) <=0:
                QMessageBox.critical(
                    self,
                    '密钥错误',
                    '密钥非空或密钥大于0'
                )
                return
            self.outputText.append('------------')
            #调用动态库函数
            self.output = pycry.enAffine(self.input,int(self.affineA),int(self.affineP))
            self.outputText.append('仿射加密值为:')
            self.outputText.append(self.output)

        #ARC4
        if self.cryMethodStr == 1:
            self.input = self.inputText.toPlainText()
            if self.input == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            if int(self.rc4KeyLen) <= 0 or int(self.rc4KeyLen) > 256:
                QMessageBox.critical(
                    self,
                    '密钥错误',
                    '密钥长度规定为1-256'
                )
                return
            self.key = pycry.randomARC4key(int(self.rc4KeyLen))
            self.outputText.append('------------------------')
            self.outputText.append('RC4密钥为:')
            self.outputText.append(self.key)
            self.outputText.append('------------------------')
            self.outputText.append('RC4加密值为:')
            self.output = pycry.encryRC4(self.input,self.key,int(self.rc4KeyLen))
            self.outputText.append(self.output)
        #MD5
        if self.cryMethodStr == 2:
            self.input = self.inputText.toPlainText()
            if self.input == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            self.signature = pycry.enmsgMD5(self.input)
            self.outputText.append('------------------------')
            self.outputText.append('MD5摘要为:')
            self.outputText.append(self.signature)
        #DES
        if self.cryMethodStr == 3:
            self.input = self.inputText.toPlainText()
            if self.input == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            self.outputText.append('------------------------')
            self.outputText.append('随机生成3DES密钥为:')
            self.key = pycry.randomDesKey()
            self.outputText.append(self.key)
            self.outputText.append('------------------------')
            self.outputText.append('随机生成3DES-IV为:')
            self.iv = pycry.randomIv()
            self.outputText.append(self.iv)
            self.output = pycry.encrypt3des(self.input, self.key, self.iv)
            self.outputText.append('------------------------')
            self.outputText.append('3DES加密密文为:')
            self.outputText.append(self.output)
        #RSA-PSS
        if self.cryMethodStr == 4:
            self.input = self.inputText.toPlainText()
            if self.input == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            if self.pubFile == '' or self.priFile == '':
                QMessageBox.critical(
                    self,
                    '文件名',
                    '密钥保存文件名不能为空'
                )
                return
            self.outputText.append('------------------------')
            self.outputText.append('正在生成RSA-PSS密钥')
            pycry.getRsaKey(self.pubFile,self.priFile)
            self.outputText.append('公钥保存目录下'+self.pubFile+'文件,私钥保存目录下'+self.priFile+'文件')
            self.outputText.append('------------------------')
            self.signature = pycry.getRsaSignature(self.priFile,self.input)
            self.outputText.append('RSA-PSS数字签名为')
            self.outputText.append(self.signature)
        #RSA-OAEP
        if self.cryMethodStr == 5:
            self.input = self.inputText.toPlainText()
            if self.input == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            if self.pubFile == '' or self.priFile == '':
                QMessageBox.critical(
                    self,
                    '文件名',
                    '密钥保存文件名不能为空'
                )
                return
            self.outputText.append('------------------------')
            self.outputText.append('正在生成RSA-OAEP密钥')
            pycry.getRsaKey(self.pubFile,self.priFile)
            self.outputText.append('公钥保存目录下' + self.pubFile + '文件,私钥保存目录下' + self.priFile + '文件')
            self.outputText.append('------------------------')
            self.outputText.append('RSA-OAEP加密密文为:')
            self.output = pycry.encryRSAOAEP(self.pubFile,self.input)
            self.outputText.append(self.output)

    #Tab2 slot
    def changeDeMethodStr(self,i):
        self.deMethodStr = i

    def clearInputTextBox_2(self):
        self.inputText_Tab2.clear()

    def clearOutputTextBox_2(self):
        self.outputText_Tab2.clear()

    def clearKeyPut(self):
        self.keyText.clear()

    def changeAffineArgsA_2(self):
        self.affineA_tab2 = self.affineArgA_Tab2.text()

    def changeAffineArgsP_2(self):
        self.affineP_tab2 = self.affineArgP_Tab2.text()

    def changeARC4KeyLen_2(self):
        self.rc4KeyLen_tab2 = self.arc4KeyLen_Tab2.text()

    def changeRsaPubFileName_2(self):
        self.pubFile_tab2 = self.pubkeyFileName_Tab2.text()

    def changeRsaPriFileName_2(self):
        self.priFile_tab2 = self.prikeyFileName_Tab2.text()

    def deCryptAccess(self):
        if self.deMethodStr == 0:
            self.input_tab2 = self.inputText_Tab2.toPlainText()
            if self.input_tab2 == '':
                QMessageBox.critical(
                    self,
                    '输入错误',
                    '待处理文本不能为空'
                )
                return
            if int(self.affineA_tab2) <= 0 or int(self.affineP_tab2) <=0:
                QMessageBox.critical(
                    self,
                    '密钥错误',
                    '密钥非空或密钥大于0'
                )
                return
            self.outputText_Tab2.append('------------')
            self.output_tab2 = pycry.deAffine(self.input_tab2,int(self.affineA_tab2),int(self.affineP_tab2))
            self.outputText_Tab2.append('仿射解密值为')
            self.outputText_Tab2.append(self.output_tab2)

        if self.deMethodStr == 1:
            self.input_tab2 = self.inputText_Tab2.toPlainText()
            self.key_tab2 = self.keyText.toPlainText()
            if self.input_tab2 == '':
                QMessageBox.critical(
                    self,
                    '输入错误',
                    '待处理文本不能为空'
                )
                return
            if self.key_tab2 == '':
                QMessageBox.critical(
                    self,
                    '密钥错误',
                    '解密密钥不能为空'
                )
                return
            if int(self.rc4KeyLen) <= 0 or int(self.rc4KeyLen) > 256:
                QMessageBox.critical(
                    self,
                    '密钥错误',
                    '密钥长度规定为1-256'
                )
                return

            self.outputText_Tab2.append('------------------------')
            self.outputText_Tab2.append('RC4解密值为:')
            self.output_tab2 = pycry.decryRC4(self.input_tab2, self.key_tab2, int(self.rc4KeyLen_tab2))
            self.outputText_Tab2.append(self.output_tab2)

        if self.deMethodStr == 2:
            self.input_tab2 = self.inputText_Tab2.toPlainText()
            self.signature_tab2 = self.keyText.toPlainText()
            if self.input_tab2 == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            if self.signature_tab2 == '':
                QMessageBox.critical(
                    self,
                    '签名错误',
                    '签名不能为空'
                )
                return
            self.outputText_Tab2.append('------------------------')
            self.outputText_Tab2.append('对当前MD5签名进行验证')
            self.output_tab2 = pycry.checkmsgMD5(self.signature_tab2,self.input_tab2)
            print(self.output_tab2)
            if self.output_tab2 == False:
                self.outputText_Tab2.append('消息签名验证失败')
            if self.output_tab2 == True:
                self.outputText_Tab2.append('消息签名验证成功')

        if self.deMethodStr == 3:
            self.input_tab2 = self.inputText_Tab2.toPlainText()
            keyAndIv = self.keyText.toPlainText()
            tmpSplit = keyAndIv.split(' ')
            self.iv_tab2 = tmpSplit[0]
            self.key_tab2 = tmpSplit[1]
            if self.input_tab2 == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            if self.key_tab2 == '':
                QMessageBox.critical(
                    self,
                    '密钥错误',
                    '密钥不能为空'
                )
                return
            self.outputText_Tab2.append('------------------------')
            self.outputText_Tab2.append('3DES解密为:')
            self.output_tab2 = pycry.decrypt3des(self.input_tab2,self.key_tab2,self.iv_tab2)
            self.outputText_Tab2.append(self.output_tab2)

        if self.deMethodStr == 4:
            self.input_tab2 = self.inputText_Tab2.toPlainText()
            self.signature_tab2 = self.keyText.toPlainText()
            if self.input_tab2 == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            if self.signature_tab2 == '':
                QMessageBox.critical(
                    self,
                    '签名错误',
                    '签名不能为空'
                )
            if self.pubFile_tab2 == '' or self.priFile_tab2 == '':
                QMessageBox.critical(
                    self,
                    '文件名',
                    '密钥保存文件名不能为空'
                )
                return
            self.outputText_Tab2.append('------------------------')
            try:
                fd = open(self.pubFile_tab2,"r")
            except IOError:
                QMessageBox.critical(
                    self,
                    '文件名',
                    '打开公钥文件失败!请检查文件名!'
                )
            else:
                self.outputText_Tab2.append('RSA-PSS签名根据公钥文件:'+self.pubFile_tab2+',恢复为:')
                self.output_tab2 = pycry.checkRsaSignature(self.pubFile_tab2,self.signature_tab2,self.input_tab2)
                self.outputText_Tab2.append(self.output_tab2)

        if self.deMethodStr == 5:
            self.input_tab2 = self.inputText_Tab2.toPlainText()
            if self.input_tab2 == '':
                QMessageBox.critical(
                    self,
                    '输入',
                    '待处理文本不能为空'
                )
                return
            if self.pubFile_tab2 == '' or self.priFile_tab2 == '':
                QMessageBox.critical(
                    self,
                    '文件名',
                    '密钥保存文件名不能为空'
                )
                return
            self.outputText_Tab2.append('------------------------')
            try:
                fd = open(self.priFile_tab2,"r")
            except IOError:
                QMessageBox.critical(
                    self,
                    '文件名',
                    '打开私钥文件失败!请检查文件名!'
                )
            else:
                self.outputText_Tab2.append('正在根据公钥文件:'+self.pubFile_tab2+',私钥文件:'+self.priFile_tab2+'解密:')
                try:
                    self.output_tab2 = pycry.decryRSAOAEP(self.priFile_tab2,self.input_tab2)
                except:
                    self.outputText_Tab2.append('解密失败!检查私钥文件或者密文')
                else:
                    self.outputText_Tab2.append(self.output_tab2)

    def clearDhin(self):
        self.linkSendInput.clear()

    def clearDhout(self):
        self.dhMsgOutput.clear()

    def clearMsgout(self):
        self.linkMsgOutput.clear()

    def changeClientIp(self):
        self.clientIp = self.clientIpText.text()

    def changeClientPort(self):
        self.clientPort = self.clientPortText.text()

    def getLocalIp(self):
        self.linkMsgOutput.append("本地IP为:")
        self.linkMsgOutput.append(socket.gethostbyname(socket.gethostname()))

    def linkMsgPrint(self,msg):
        self.linkMsgOutput.append(msg)

    def openLink(self):
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 设定套接字为非阻塞式
        self.serverSocket.setblocking(False)
        try:
            port = int(self.clientPort)
            self.serverSocket.bind((self.clientIp, port))
        except Exception as ret:
            self.linkMsgOutput.append('检查端口号或IP是否正确')
        else:
            self.serverSocket.listen()
            self.serverTh = threading.Thread(target=self.tcpServerConcurrency)
            self.serverTh.start()
            self.linkMsgOutput.append('Tcp服务器正在监听端口' + self.clientPort + '等待Client连接')
            self.openLinkPush.setEnabled(False)
            self.closeLinkPush.setEnabled(True)


    def tcpServerConcurrency(self):
        while True:
            try:
                self.dataSocket,self.clientAddr = self.serverSocket.accept()
            except Exception as ret:
                pass
            else:
                self.dataSocket.setblocking(False)
                msg = '接收到一个客户端连接IP:' + str(self.clientAddr)
                self.signalLinkWrite.emit(msg)
                while True:
                    try:
                        recved = self.dataSocket.recv(512)
                    except Exception as ret:
                        pass
                    else:
                        if recved:
                            info = recved.decode('utf-8')
                            self.signalLinkWrite.emit('收到信息')
                            self.signalLinkWrite.emit(info)
                            self.dataSocket.send('服务端接收信息'.encode())
                        else:
                            self.signalLinkWrite.emit('客户端关闭了连接')
                            self.dataSocket.close()
                            break

    def closeLink(self):
        #关闭Socket与线程
        self.serverSocket.close()
        #回收子线程
        stopThreading.stop_thread(self.serverTh)
        self.linkMsgOutput.append('已关闭TCP连接')

        self.openLinkPush.setEnabled(True)
        self.closeLinkPush.setEnabled(False)

    def sendMsg(self):
        #主线程下，未分离
        try:
            sendmsg = (str(self.linkSendInput.toPlainText())).encode('utf-8')
            self.dataSocket.send(sendmsg)
            info = '服务端已发送消息'
            self.linkMsgOutput.append(info)
        except Exception as ret:
            info = '发送失败，检查网络或是否存在连接'
            self.linkMsgOutput.append(info)

    def getServerPubKey(self):
        try:
            self.parameters = dh.generate_parameters(generator=2,key_size=512)
            self.encodeParameter = self.parameters.parameter_bytes(Encoding.PEM,ParameterFormat.PKCS3)
            self.serverPriKey = self.parameters.generate_private_key()
            self.serverPubKey = self.serverPriKey.public_key()
            self.encodeServerPriKey = self.serverPriKey.private_bytes(
                Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )
            self.dhMsgOutput.append('服务端已生成DH私钥与公开质数')
            self.dhMsgOutput.append('公开质数parameter:')
            self.dhMsgOutput.append(self.encodeParameter.decode())
            self.dhMsgOutput.append('服务端私钥:')
            self.dhMsgOutput.append(self.encodeServerPriKey.decode())
        except Exception as ret:
            self.dhMsgOutput.append('服务端DH私钥生成失败')

    def sendPubPara(self):
        if self.parameters == None:
            self.dhMsgOutput.append('请先生成DH公开参数')
            return
        try:
            self.dataSocket.send(self.encodeParameter)
            self.linkMsgOutput.append('服务端已向客户端发送公开参数')
        except Exception as ret:
            info = '发送失败，检查网络或是否存在连接'
            self.linkMsgOutput.append(info)

    def passServerPubKey(self):
        if self.serverPubKey == None:
            self.dhMsgOutput.append('请先生成服务端DH公钥')
            return
        try:
            self.encodeServerPubKey = self.serverPubKey.public_bytes(
                Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.dataSocket.send(self.encodeServerPubKey)
            self.linkMsgOutput.append('服务端已向客户端发送公钥')
        except Exception as ret:
            info = '发送失败，检查网络或是否存在连接'
            self.linkMsgOutput.append(info)

    def getClientPubKey(self):
        self.encodeClientPubKey = (self.waitClientPubKey.toPlainText())
        self.encodeClientPubKey = self.encodeClientPubKey.encode()

    def getSeverSharedKey(self):
        if self.encodeClientPubKey == None:
            self.dhMsgOutput.append('尚未接收到客户端交换的公钥或客户端公钥不完整')
            return
        try:
            self.clientPubKey = load_pem_public_key(self.encodeClientPubKey)
            isinstance(self.clientPubKey, dh.DHPublicKey)
            self.serverSharedKey = self.serverPriKey.exchange(self.clientPubKey)
            self.dhMsgOutput.append('生成共享密钥成功')
        except Exception as ret:
            self.dhMsgOutput.append('生成服务端共享密钥失败,检查公钥,链接或参数')


app = QApplication([])
stats = States()
stats.show()
app.exec_()
