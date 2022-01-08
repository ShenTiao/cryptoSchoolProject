# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.4
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainEncryForm(object):
    def setupUi(self, MainEncryForm):
        MainEncryForm.setObjectName("MainEncryForm")
        MainEncryForm.resize(949, 650)
        self.tabWidget = QtWidgets.QTabWidget(MainEncryForm)
        self.tabWidget.setGeometry(QtCore.QRect(0, 0, 951, 651))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.layoutWidget = QtWidgets.QWidget(self.tab)
        self.layoutWidget.setGeometry(QtCore.QRect(0, 0, 941, 621))
        self.layoutWidget.setObjectName("layoutWidget")
        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.layoutWidget)
        self.verticalLayout_9.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.inputText = QtWidgets.QTextEdit(self.layoutWidget)
        self.inputText.setMinimumSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(14)
        self.inputText.setFont(font)
        self.inputText.setObjectName("inputText")
        self.verticalLayout_2.addWidget(self.inputText)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.inputClearPush = QtWidgets.QPushButton(self.layoutWidget)
        self.inputClearPush.setObjectName("inputClearPush")
        self.horizontalLayout.addWidget(self.inputClearPush)
        self.outputClearPush = QtWidgets.QPushButton(self.layoutWidget)
        self.outputClearPush.setObjectName("outputClearPush")
        self.horizontalLayout.addWidget(self.outputClearPush)
        self.verticalLayout_2.addLayout(self.horizontalLayout)
        self.horizontalLayout_2.addLayout(self.verticalLayout_2)
        self.verticalLayout_8 = QtWidgets.QVBoxLayout()
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout()
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.verticalLayout_3.addLayout(self.verticalLayout)
        self.groupBox = QtWidgets.QGroupBox(self.layoutWidget)
        self.groupBox.setObjectName("groupBox")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.groupBox)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.label = QtWidgets.QLabel(self.groupBox)
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(14)
        self.label.setFont(font)
        self.label.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label.setObjectName("label")
        self.verticalLayout_7.addWidget(self.label)
        self.encryChooseBox = QtWidgets.QComboBox(self.groupBox)
        self.encryChooseBox.setIconSize(QtCore.QSize(16, 16))
        self.encryChooseBox.setObjectName("encryChooseBox")
        self.encryChooseBox.addItem("")
        self.encryChooseBox.addItem("")
        self.encryChooseBox.addItem("")
        self.encryChooseBox.addItem("")
        self.encryChooseBox.addItem("")
        self.encryChooseBox.addItem("")
        self.verticalLayout_7.addWidget(self.encryChooseBox)
        self.enCryPush = QtWidgets.QPushButton(self.groupBox)
        self.enCryPush.setObjectName("enCryPush")
        self.verticalLayout_7.addWidget(self.enCryPush)
        self.verticalLayout_3.addWidget(self.groupBox)
        self.label_2 = QtWidgets.QLabel(self.layoutWidget)
        self.label_2.setObjectName("label_2")
        self.verticalLayout_3.addWidget(self.label_2)
        self.affineArgA = QtWidgets.QLineEdit(self.layoutWidget)
        self.affineArgA.setObjectName("affineArgA")
        self.verticalLayout_3.addWidget(self.affineArgA)
        self.affineArgP = QtWidgets.QLineEdit(self.layoutWidget)
        self.affineArgP.setObjectName("affineArgP")
        self.verticalLayout_3.addWidget(self.affineArgP)
        self.verticalLayout_6.addLayout(self.verticalLayout_3)
        self.verticalLayout_4 = QtWidgets.QVBoxLayout()
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.label_3 = QtWidgets.QLabel(self.layoutWidget)
        self.label_3.setObjectName("label_3")
        self.verticalLayout_4.addWidget(self.label_3)
        self.arc4KeyLen = QtWidgets.QLineEdit(self.layoutWidget)
        self.arc4KeyLen.setObjectName("arc4KeyLen")
        self.verticalLayout_4.addWidget(self.arc4KeyLen)
        self.verticalLayout_6.addLayout(self.verticalLayout_4)
        self.verticalLayout_5 = QtWidgets.QVBoxLayout()
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.label_4 = QtWidgets.QLabel(self.layoutWidget)
        self.label_4.setObjectName("label_4")
        self.verticalLayout_5.addWidget(self.label_4)
        self.label_5 = QtWidgets.QLabel(self.layoutWidget)
        self.label_5.setObjectName("label_5")
        self.verticalLayout_5.addWidget(self.label_5)
        self.pubkeyFileName = QtWidgets.QLineEdit(self.layoutWidget)
        self.pubkeyFileName.setObjectName("pubkeyFileName")
        self.verticalLayout_5.addWidget(self.pubkeyFileName)
        self.label_6 = QtWidgets.QLabel(self.layoutWidget)
        self.label_6.setObjectName("label_6")
        self.verticalLayout_5.addWidget(self.label_6)
        self.prikeyFileName = QtWidgets.QLineEdit(self.layoutWidget)
        self.prikeyFileName.setObjectName("prikeyFileName")
        self.verticalLayout_5.addWidget(self.prikeyFileName)
        self.verticalLayout_6.addLayout(self.verticalLayout_5)
        self.verticalLayout_8.addLayout(self.verticalLayout_6)
        self.horizontalLayout_2.addLayout(self.verticalLayout_8)
        self.verticalLayout_9.addLayout(self.horizontalLayout_2)
        self.outputText = QtWidgets.QTextBrowser(self.layoutWidget)
        font = QtGui.QFont()
        font.setFamily("等线 Light")
        font.setPointSize(14)
        self.outputText.setFont(font)
        self.outputText.setObjectName("outputText")
        self.verticalLayout_9.addWidget(self.outputText)
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.layoutWidget_2 = QtWidgets.QWidget(self.tab_2)
        self.layoutWidget_2.setGeometry(QtCore.QRect(0, 0, 941, 621))
        self.layoutWidget_2.setObjectName("layoutWidget_2")
        self.verticalLayout_10 = QtWidgets.QVBoxLayout(self.layoutWidget_2)
        self.verticalLayout_10.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout_10.setObjectName("verticalLayout_10")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.verticalLayout_11 = QtWidgets.QVBoxLayout()
        self.verticalLayout_11.setObjectName("verticalLayout_11")
        self.inputText_Tab2 = QtWidgets.QTextEdit(self.layoutWidget_2)
        self.inputText_Tab2.setMinimumSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(14)
        self.inputText_Tab2.setFont(font)
        self.inputText_Tab2.setObjectName("inputText_Tab2")
        self.verticalLayout_11.addWidget(self.inputText_Tab2)
        self.keyText = QtWidgets.QTextEdit(self.layoutWidget_2)
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(14)
        self.keyText.setFont(font)
        self.keyText.setObjectName("keyText")
        self.verticalLayout_11.addWidget(self.keyText)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.outputClearPush_Tab2 = QtWidgets.QPushButton(self.layoutWidget_2)
        self.outputClearPush_Tab2.setObjectName("outputClearPush_Tab2")
        self.horizontalLayout_4.addWidget(self.outputClearPush_Tab2)
        self.keyClearPush = QtWidgets.QPushButton(self.layoutWidget_2)
        self.keyClearPush.setObjectName("keyClearPush")
        self.horizontalLayout_4.addWidget(self.keyClearPush)
        self.inputClearPush_Tab2 = QtWidgets.QPushButton(self.layoutWidget_2)
        self.inputClearPush_Tab2.setObjectName("inputClearPush_Tab2")
        self.horizontalLayout_4.addWidget(self.inputClearPush_Tab2)
        self.verticalLayout_11.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_3.addLayout(self.verticalLayout_11)
        self.verticalLayout_12 = QtWidgets.QVBoxLayout()
        self.verticalLayout_12.setObjectName("verticalLayout_12")
        self.verticalLayout_13 = QtWidgets.QVBoxLayout()
        self.verticalLayout_13.setObjectName("verticalLayout_13")
        self.verticalLayout_14 = QtWidgets.QVBoxLayout()
        self.verticalLayout_14.setObjectName("verticalLayout_14")
        self.verticalLayout_15 = QtWidgets.QVBoxLayout()
        self.verticalLayout_15.setObjectName("verticalLayout_15")
        self.verticalLayout_14.addLayout(self.verticalLayout_15)
        self.groupBox_2 = QtWidgets.QGroupBox(self.layoutWidget_2)
        self.groupBox_2.setObjectName("groupBox_2")
        self.verticalLayout_16 = QtWidgets.QVBoxLayout(self.groupBox_2)
        self.verticalLayout_16.setObjectName("verticalLayout_16")
        self.label_7 = QtWidgets.QLabel(self.groupBox_2)
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(14)
        self.label_7.setFont(font)
        self.label_7.setLayoutDirection(QtCore.Qt.LeftToRight)
        self.label_7.setObjectName("label_7")
        self.verticalLayout_16.addWidget(self.label_7)
        self.decryChooseBox = QtWidgets.QComboBox(self.groupBox_2)
        self.decryChooseBox.setIconSize(QtCore.QSize(16, 16))
        self.decryChooseBox.setObjectName("decryChooseBox")
        self.decryChooseBox.addItem("")
        self.decryChooseBox.addItem("")
        self.decryChooseBox.addItem("")
        self.decryChooseBox.addItem("")
        self.decryChooseBox.addItem("")
        self.decryChooseBox.addItem("")
        self.verticalLayout_16.addWidget(self.decryChooseBox)
        self.deCryPush = QtWidgets.QPushButton(self.groupBox_2)
        self.deCryPush.setObjectName("deCryPush")
        self.verticalLayout_16.addWidget(self.deCryPush)
        self.verticalLayout_14.addWidget(self.groupBox_2)
        self.label_8 = QtWidgets.QLabel(self.layoutWidget_2)
        self.label_8.setObjectName("label_8")
        self.verticalLayout_14.addWidget(self.label_8)
        self.affineArgA_Tab2 = QtWidgets.QLineEdit(self.layoutWidget_2)
        self.affineArgA_Tab2.setObjectName("affineArgA_Tab2")
        self.verticalLayout_14.addWidget(self.affineArgA_Tab2)
        self.affineArgP_Tab2 = QtWidgets.QLineEdit(self.layoutWidget_2)
        self.affineArgP_Tab2.setObjectName("affineArgP_Tab2")
        self.verticalLayout_14.addWidget(self.affineArgP_Tab2)
        self.verticalLayout_13.addLayout(self.verticalLayout_14)
        self.verticalLayout_17 = QtWidgets.QVBoxLayout()
        self.verticalLayout_17.setObjectName("verticalLayout_17")
        self.label_9 = QtWidgets.QLabel(self.layoutWidget_2)
        self.label_9.setObjectName("label_9")
        self.verticalLayout_17.addWidget(self.label_9)
        self.arc4KeyLen_Tab2 = QtWidgets.QLineEdit(self.layoutWidget_2)
        self.arc4KeyLen_Tab2.setObjectName("arc4KeyLen_Tab2")
        self.verticalLayout_17.addWidget(self.arc4KeyLen_Tab2)
        self.verticalLayout_13.addLayout(self.verticalLayout_17)
        self.verticalLayout_18 = QtWidgets.QVBoxLayout()
        self.verticalLayout_18.setObjectName("verticalLayout_18")
        self.label_10 = QtWidgets.QLabel(self.layoutWidget_2)
        self.label_10.setObjectName("label_10")
        self.verticalLayout_18.addWidget(self.label_10)
        self.label_11 = QtWidgets.QLabel(self.layoutWidget_2)
        self.label_11.setObjectName("label_11")
        self.verticalLayout_18.addWidget(self.label_11)
        self.pubkeyFileName_Tab2 = QtWidgets.QLineEdit(self.layoutWidget_2)
        self.pubkeyFileName_Tab2.setObjectName("pubkeyFileName_Tab2")
        self.verticalLayout_18.addWidget(self.pubkeyFileName_Tab2)
        self.label_12 = QtWidgets.QLabel(self.layoutWidget_2)
        self.label_12.setObjectName("label_12")
        self.verticalLayout_18.addWidget(self.label_12)
        self.prikeyFileName_Tab2 = QtWidgets.QLineEdit(self.layoutWidget_2)
        self.prikeyFileName_Tab2.setObjectName("prikeyFileName_Tab2")
        self.verticalLayout_18.addWidget(self.prikeyFileName_Tab2)
        self.verticalLayout_13.addLayout(self.verticalLayout_18)
        self.verticalLayout_12.addLayout(self.verticalLayout_13)
        self.horizontalLayout_3.addLayout(self.verticalLayout_12)
        self.verticalLayout_10.addLayout(self.horizontalLayout_3)
        self.outputText_Tab2 = QtWidgets.QTextBrowser(self.layoutWidget_2)
        font = QtGui.QFont()
        font.setFamily("等线 Light")
        font.setPointSize(14)
        self.outputText_Tab2.setFont(font)
        self.outputText_Tab2.setPlaceholderText("")
        self.outputText_Tab2.setObjectName("outputText_Tab2")
        self.verticalLayout_10.addWidget(self.outputText_Tab2)
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_3 = QtWidgets.QWidget()
        self.tab_3.setObjectName("tab_3")
        self.linkMsgOutput = QtWidgets.QTextBrowser(self.tab_3)
        self.linkMsgOutput.setGeometry(QtCore.QRect(0, 350, 941, 271))
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(14)
        self.linkMsgOutput.setFont(font)
        self.linkMsgOutput.setObjectName("linkMsgOutput")
        self.layoutWidget1 = QtWidgets.QWidget(self.tab_3)
        self.layoutWidget1.setGeometry(QtCore.QRect(0, 140, 941, 171))
        self.layoutWidget1.setObjectName("layoutWidget1")
        self.horizontalLayout_7 = QtWidgets.QHBoxLayout(self.layoutWidget1)
        self.horizontalLayout_7.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_7.setObjectName("horizontalLayout_7")
        self.linkSendInput = QtWidgets.QTextEdit(self.layoutWidget1)
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(14)
        self.linkSendInput.setFont(font)
        self.linkSendInput.setObjectName("linkSendInput")
        self.horizontalLayout_7.addWidget(self.linkSendInput)
        self.dhMsgOutput = QtWidgets.QTextBrowser(self.layoutWidget1)
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(12)
        self.dhMsgOutput.setFont(font)
        self.dhMsgOutput.setObjectName("dhMsgOutput")
        self.horizontalLayout_7.addWidget(self.dhMsgOutput)
        self.layoutWidget2 = QtWidgets.QWidget(self.tab_3)
        self.layoutWidget2.setGeometry(QtCore.QRect(11, 311, 461, 41))
        self.layoutWidget2.setObjectName("layoutWidget2")
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(self.layoutWidget2)
        self.horizontalLayout_8.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.clearDhInput = QtWidgets.QPushButton(self.layoutWidget2)
        self.clearDhInput.setObjectName("clearDhInput")
        self.horizontalLayout_8.addWidget(self.clearDhInput)
        self.clearDhOutput = QtWidgets.QPushButton(self.layoutWidget2)
        self.clearDhOutput.setObjectName("clearDhOutput")
        self.horizontalLayout_8.addWidget(self.clearDhOutput)
        self.clearMsgOutput = QtWidgets.QPushButton(self.layoutWidget2)
        self.clearMsgOutput.setObjectName("clearMsgOutput")
        self.horizontalLayout_8.addWidget(self.clearMsgOutput)
        self.widget = QtWidgets.QWidget(self.tab_3)
        self.widget.setGeometry(QtCore.QRect(10, 0, 921, 141))
        self.widget.setObjectName("widget")
        self.horizontalLayout_10 = QtWidgets.QHBoxLayout(self.widget)
        self.horizontalLayout_10.setContentsMargins(0, 0, 0, 0)
        self.horizontalLayout_10.setObjectName("horizontalLayout_10")
        self.verticalLayout_20 = QtWidgets.QVBoxLayout()
        self.verticalLayout_20.setObjectName("verticalLayout_20")
        self.verticalLayout_19 = QtWidgets.QVBoxLayout()
        self.verticalLayout_19.setObjectName("verticalLayout_19")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.label_13 = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(12)
        self.label_13.setFont(font)
        self.label_13.setObjectName("label_13")
        self.horizontalLayout_5.addWidget(self.label_13)
        self.clientIpText = QtWidgets.QLineEdit(self.widget)
        self.clientIpText.setText("")
        self.clientIpText.setObjectName("clientIpText")
        self.horizontalLayout_5.addWidget(self.clientIpText)
        self.verticalLayout_19.addLayout(self.horizontalLayout_5)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.label_14 = QtWidgets.QLabel(self.widget)
        font = QtGui.QFont()
        font.setFamily("等线")
        font.setPointSize(12)
        self.label_14.setFont(font)
        self.label_14.setObjectName("label_14")
        self.horizontalLayout_6.addWidget(self.label_14)
        self.clientPortText = QtWidgets.QLineEdit(self.widget)
        self.clientPortText.setObjectName("clientPortText")
        self.horizontalLayout_6.addWidget(self.clientPortText)
        self.getLocalIpPush = QtWidgets.QPushButton(self.widget)
        self.getLocalIpPush.setObjectName("getLocalIpPush")
        self.horizontalLayout_6.addWidget(self.getLocalIpPush)
        self.verticalLayout_19.addLayout(self.horizontalLayout_6)
        self.verticalLayout_20.addLayout(self.verticalLayout_19)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName("horizontalLayout_9")
        self.openLinkPush = QtWidgets.QPushButton(self.widget)
        self.openLinkPush.setObjectName("openLinkPush")
        self.horizontalLayout_9.addWidget(self.openLinkPush)
        self.closeLinkPush = QtWidgets.QPushButton(self.widget)
        self.closeLinkPush.setObjectName("closeLinkPush")
        self.horizontalLayout_9.addWidget(self.closeLinkPush)
        self.sendMsgPush = QtWidgets.QPushButton(self.widget)
        self.sendMsgPush.setObjectName("sendMsgPush")
        self.horizontalLayout_9.addWidget(self.sendMsgPush)
        self.verticalLayout_20.addLayout(self.horizontalLayout_9)
        self.horizontalLayout_10.addLayout(self.verticalLayout_20)
        self.waitClientPubKey = QtWidgets.QPlainTextEdit(self.widget)
        self.waitClientPubKey.setObjectName("waitClientPubKey")
        self.horizontalLayout_10.addWidget(self.waitClientPubKey)
        self.verticalLayout_21 = QtWidgets.QVBoxLayout()
        self.verticalLayout_21.setObjectName("verticalLayout_21")
        self.serverPubKeyPush = QtWidgets.QPushButton(self.widget)
        self.serverPubKeyPush.setObjectName("serverPubKeyPush")
        self.verticalLayout_21.addWidget(self.serverPubKeyPush)
        self.sendClientPubPara = QtWidgets.QPushButton(self.widget)
        self.sendClientPubPara.setObjectName("sendClientPubPara")
        self.verticalLayout_21.addWidget(self.sendClientPubPara)
        self.sendServerPubkey = QtWidgets.QPushButton(self.widget)
        self.sendServerPubkey.setObjectName("sendServerPubkey")
        self.verticalLayout_21.addWidget(self.sendServerPubkey)
        self.creServerSharedKey = QtWidgets.QPushButton(self.widget)
        self.creServerSharedKey.setObjectName("creServerSharedKey")
        self.verticalLayout_21.addWidget(self.creServerSharedKey)
        self.horizontalLayout_10.addLayout(self.verticalLayout_21)
        self.tabWidget.addTab(self.tab_3, "")

        self.retranslateUi(MainEncryForm)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainEncryForm)

    def retranslateUi(self, MainEncryForm):
        _translate = QtCore.QCoreApplication.translate
        MainEncryForm.setWindowTitle(_translate("MainEncryForm", "加密工具"))
        self.inputText.setPlaceholderText(_translate("MainEncryForm", "待处理文本"))
        self.inputClearPush.setText(_translate("MainEncryForm", "清空输入框"))
        self.outputClearPush.setText(_translate("MainEncryForm", "清空输出框"))
        self.groupBox.setTitle(_translate("MainEncryForm", "选项栏"))
        self.label.setText(_translate("MainEncryForm", "加密或签名方式"))
        self.encryChooseBox.setItemText(0, _translate("MainEncryForm", "AFFINE"))
        self.encryChooseBox.setItemText(1, _translate("MainEncryForm", "ARC4"))
        self.encryChooseBox.setItemText(2, _translate("MainEncryForm", "MD5"))
        self.encryChooseBox.setItemText(3, _translate("MainEncryForm", "DES"))
        self.encryChooseBox.setItemText(4, _translate("MainEncryForm", "RSA-PSS"))
        self.encryChooseBox.setItemText(5, _translate("MainEncryForm", "RSA-OAEP"))
        self.enCryPush.setText(_translate("MainEncryForm", "加密或签名"))
        self.label_2.setText(_translate("MainEncryForm", "仿射加密参数a,p"))
        self.label_3.setText(_translate("MainEncryForm", "ARC4加密密钥长度"))
        self.arc4KeyLen.setPlaceholderText(_translate("MainEncryForm", "Range:1-256"))
        self.label_4.setText(_translate("MainEncryForm", "RSA签名密钥保存文件名"))
        self.label_5.setText(_translate("MainEncryForm", "公钥"))
        self.label_6.setText(_translate("MainEncryForm", "私钥"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainEncryForm", "加密操作"))
        self.inputText_Tab2.setPlaceholderText(_translate("MainEncryForm", "待处理文本"))
        self.keyText.setPlaceholderText(_translate("MainEncryForm", "输入加密密钥或签名,RSA方式读取文件即可,DES加密按格式输入IV+Key,以空格分隔"))
        self.outputClearPush_Tab2.setText(_translate("MainEncryForm", "清空输出框"))
        self.keyClearPush.setText(_translate("MainEncryForm", "清空密钥框"))
        self.inputClearPush_Tab2.setText(_translate("MainEncryForm", "清空输入框"))
        self.groupBox_2.setTitle(_translate("MainEncryForm", "选项栏"))
        self.label_7.setText(_translate("MainEncryForm", "解密或签名验证方式"))
        self.decryChooseBox.setItemText(0, _translate("MainEncryForm", "AFFINE"))
        self.decryChooseBox.setItemText(1, _translate("MainEncryForm", "ARC4"))
        self.decryChooseBox.setItemText(2, _translate("MainEncryForm", "MD5"))
        self.decryChooseBox.setItemText(3, _translate("MainEncryForm", "DES"))
        self.decryChooseBox.setItemText(4, _translate("MainEncryForm", "RSA-PSS"))
        self.decryChooseBox.setItemText(5, _translate("MainEncryForm", "RSA-OAEP"))
        self.deCryPush.setText(_translate("MainEncryForm", "解密或签名验证"))
        self.label_8.setText(_translate("MainEncryForm", "仿射解密参数a,p"))
        self.affineArgA_Tab2.setPlaceholderText(_translate("MainEncryForm", "注意a,p互质"))
        self.label_9.setText(_translate("MainEncryForm", "ARC4解密密钥长度"))
        self.arc4KeyLen_Tab2.setPlaceholderText(_translate("MainEncryForm", "Range:1-256"))
        self.label_10.setText(_translate("MainEncryForm", "RSA签名密钥保存文件名"))
        self.label_11.setText(_translate("MainEncryForm", "公钥"))
        self.label_12.setText(_translate("MainEncryForm", "私钥"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainEncryForm", "解密操作"))
        self.linkMsgOutput.setPlaceholderText(_translate("MainEncryForm", "消息栏"))
        self.linkSendInput.setPlaceholderText(_translate("MainEncryForm", "输入要向Client发送的消息...."))
        self.dhMsgOutput.setPlaceholderText(_translate("MainEncryForm", "DH协议运行输出窗口"))
        self.clearDhInput.setText(_translate("MainEncryForm", "清空DH输入栏"))
        self.clearDhOutput.setText(_translate("MainEncryForm", "清空DH输出栏"))
        self.clearMsgOutput.setText(_translate("MainEncryForm", "清空消息栏"))
        self.label_13.setText(_translate("MainEncryForm", "Client IP"))
        self.label_14.setText(_translate("MainEncryForm", "端口号"))
        self.getLocalIpPush.setText(_translate("MainEncryForm", "获取本机IP"))
        self.openLinkPush.setText(_translate("MainEncryForm", "打开链接"))
        self.closeLinkPush.setText(_translate("MainEncryForm", "断开链接"))
        self.sendMsgPush.setText(_translate("MainEncryForm", "发送消息"))
        self.waitClientPubKey.setPlaceholderText(_translate("MainEncryForm", "输入客户端交换公钥"))
        self.serverPubKeyPush.setText(_translate("MainEncryForm", "生成服务端DH公钥"))
        self.sendClientPubPara.setText(_translate("MainEncryForm", "向客户端发送公开素数P"))
        self.sendServerPubkey.setText(_translate("MainEncryForm", "向客户端发送DH公钥"))
        self.creServerSharedKey.setText(_translate("MainEncryForm", "生成服务端共享密钥"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_3), _translate("MainEncryForm", "DH"))
