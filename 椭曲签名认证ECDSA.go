package main

import (
	"crypto/rand"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"crypto/sha256"
	"math/big"
)

//生成ECC公私钥对
func DsaGenerateKey() {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//私钥509序列化
	derPrivateKey, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		panic(err)
	}
	//放置pem块中,存入文件
	var block = pem.Block{
		Type:  "ecdsa private key",
		Bytes: derPrivateKey,
	}
	fileName := "ecdsa_private.pem"
	f, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	err = pem.Encode(f, &block)
	if err != nil {
		panic(err)
	}
	//将公钥存入文件
	DsaPublicKey(privKey)
}
func DsaPublicKey(privKey *ecdsa.PrivateKey) {
	derPublicKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		panic(err)
	}
	//将公钥放置pem块中
	fileName := "ecdsa_public.pem"
	f, err := os.Create(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	var block = pem.Block{
		Type:  "ecdsa public key",
		Bytes: derPublicKey,
	}
	err = pem.Encode(f, &block)
	if err != nil {
		panic(err)
	}

}

//利用ecdsa私钥签名
//与rsa区别：509序列化时使用函数不同
//签名返回的值为r和s(big.int)
func DsaSignKey(plainText []byte, fileName string) ([]byte, []byte) {
	/*
	1,将原始数据生成hash值
	2，打开私钥文件，509反序列化,pem解码
	3，用私钥签名
	4,将返回的r和s转换成[]byte发送
	*/
	myHash := sha256.New()
	myHash.Write(plainText)
	hashNum := myHash.Sum(nil)
	//2,打开私钥文件，509反序列化,pem解码
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fileInfo, _ := os.Stat(fileName)
	buf := make([]byte, fileInfo.Size())
	_, err = f.Read(buf)
	if err != nil {
		panic(err)
	}
	//pem解码
	block, _ := pem.Decode(buf)
	if block == nil {
		panic("block=nil")
	}
	//509 反序列化
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//利用私钥签名
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hashNum)
	if err != nil {
		panic(err)
	}
	//将返回的r和s转换成[]byte发送
	rText, _ := r.MarshalText()
	sText, _ := s.MarshalText()
	return rText, sText
}

//利用ecdsa公钥验证
func DsaVerifyKey(plainText []byte, fileName string, rText, sText []byte, )bool {
	/*
	1，将原始数据生成hash值
	2,打开公钥文件，509反序列化,pem解码
	3，将r和s转换回big.int
	4，用公钥进行验证
	*/
	myHash := sha256.New()
	myHash.Write(plainText)
	hashNum := myHash.Sum(nil)
	//2,打开公钥文件，509反序列化,pem解码
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fileInfo, _ := os.Stat(fileName)
	buf := make([]byte, fileInfo.Size())
	_, err = f.Read(buf)
	if err != nil {
		panic(err)
	}
	//pem解码
	block, _ := pem.Decode(buf)
	if block == nil {
		panic("block=nil")
	}
	//x509反序列化
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey := pubInterface.(*ecdsa.PublicKey)
	//将r，s转回big.int
	var r, s big.Int
	r.UnmarshalText(rText)
	s.UnmarshalText(sText)
	//利用公钥进行解密
	signFlag := ecdsa.Verify(publicKey, hashNum, &r, &s)
	return signFlag

}
