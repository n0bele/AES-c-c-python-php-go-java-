#!/usr/bin/python
#-- coding:utf8 --
from Crypto.Cipher import AES
import base64

class PrpCrypt(object):
    def __init__(self, key):
        self.key = bytes.fromhex(key)
        self.mode = AES.MODE_CBC
        # 这里使用的16个1作为iv,亦可动态生成可变iv
        self.iv = '010101012345abcd'.encode('utf-8')

    def encrypt(self, text):
        text = text.encode('utf-8')
        cryptor = AES.new(self.key, self.mode, self.iv)
        # 这里密钥key 长度必须为16（AES-128）,
        # 24（AES-192）,或者32 （AES-256）Bytes 长度
        # 目前AES-128 足够目前使用
        length = 16
        count = len(text)
        if count < length:
            add = (length - count)
            # \0 backspace
            # text = text + ('\0' * add)
            text = text + ('\01' * add).encode('utf-8')
        elif count > length:
            add = (length - (count % length))
            # text = text + ('\0' * add)
            text = text + ('\01' * add).encode('utf-8')
        a=cryptor.encrypt(text)
        self.ciphertext = self.iv+a
        # 因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题
        # 所以这里统一把加密后的字符串转化为base64
        return str(base64.b64encode(self.ciphertext),'utf-8')

    def decrypt(self, text):
        iv = base64.b64decode(text)[0:16]
        encry_text = base64.b64decode(text)[16:]
        cryptor = AES.new(self.key, self.mode, iv)
        plain_text = cryptor.decrypt(encry_text)
        # return plain_text.rstrip('\0')
        return str(plain_text, 'utf-8').rstrip('\01')