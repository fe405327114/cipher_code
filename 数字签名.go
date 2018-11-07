package main

import (
	"crypto/sha256"
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"crypto/rand"
	"crypto"
)

func SignHash(plainText []byte, fileName string) []byte {
	/*
	1,生成公私秘钥对
	2,将原始数据进行哈希运算得到散列值
	3,读取私钥，反序列化
	4，用私钥对散列值进行签名
	*/
	//2,将原始数据进行哈希运算得到散列值
	myHash := sha256.New()
	myHash.Write(plainText)
	hashNum := myHash.Sum(nil)
	//3,读取私钥，反序列化
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	_, err = f.Read(buf)
	if err != nil {
		panic(err)
	}
	//反序列化
	block, _ := pem.Decode(buf)
	if block == nil {
		panic(block)
	}
	//509反序列化
	privKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	//4，用私钥对散列值进行签名
	cryptoText, errSign := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashNum)
	if errSign != nil {
		panic(errSign)
	}
   return cryptoText
}
func VerifyHash(plainText,cryptoText []byte,fileName string) bool {
	/*
	1,读取公钥，进行反序列化
	2,将原始数据进行哈希运算得到散列值
	3,用公钥对散列值进行验证
	*/
	myHash := sha256.New()
	myHash.Write(plainText)
	hashNum := myHash.Sum(nil)
	//3,读取公钥，反序列化
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	_, err = f.Read(buf)
	if err != nil {
		panic(err)
	}
	//反序列化
	block, _ := pem.Decode(buf)
	if block == nil {
		panic(block)
	}
	//509反序列化
	pubInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	//类型断言
	publicKey:=pubInterface.(*rsa.PublicKey)
	//4，用公钥对散列值进行验证
	verifyErr:=rsa.VerifyPKCS1v15(publicKey,crypto.SHA256,hashNum,cryptoText)
	if verifyErr==nil{
		return true
	}else{
		return false
	}
}
