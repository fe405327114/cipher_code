package main

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func RsaPrivateKey(bits int) {
	//生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		panic(err)
	}
	//将私钥进行509序列化
	derKey := x509.MarshalPKCS1PrivateKey(privateKey)
	//将私钥放置在pem块中
	var block = pem.Block{
		Type:  "rsa private key",
		Bytes: derKey,
	}
	f, err := os.Create("rsa_private.pem")
	defer f.Close()
	if err != nil {
		panic(err)
	}
	err = pem.Encode(f, &block)
	if err != nil {
		panic(err)
	}
	RsaPublicKey(privateKey)

}
func RsaPublicKey(privateKey *rsa.PrivateKey) {
	//生成公钥
	publicKey := privateKey.PublicKey
	//将公钥进行509序列化
	key, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		panic(err)
	}
	//将公钥放置在pem块中
	var block = pem.Block{
		Type:  "rsa public key",
		Bytes: key,
	}
	f, err := os.Create("rsa_public.pem")
	defer f.Close()
	err = pem.Encode(f, &block)
	if err != nil {
		panic(err)
	}
}

//公钥加密
func RsaPublicCipher(plainText []byte, fileName string) []byte {
	//读取公钥文件
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fileInfo, err := f.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	_,err= f.Read(buf)
	if err!=nil{
		panic(err)
	}

	//解码pem块
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil
	}
	//509反序列化
	pubInterface,err:=x509.ParsePKIXPublicKey(block.Bytes)
	if err !=nil{
		panic(err)
	}
	//类型断言
   publicKey:=pubInterface.(*rsa.PublicKey)
   //用公钥加密
	cryptoText,err:=rsa.EncryptPKCS1v15(rand.Reader,publicKey,plainText)
	if err!=nil{
		panic(err)
	}
	return cryptoText
}
//私钥解密
func RsaPrivateCipher(cryptoText []byte,fileName string)[]byte{
	//读取私钥文件
	f, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	fileInfo, err := f.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, fileInfo.Size())
	_,err= f.Read(buf)
	if err!=nil{
		panic(err)
	}

	//解码pem块
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil
	}
	//509反序列化
	privateKey,err:=x509.ParsePKCS1PrivateKey(block.Bytes)
	if err !=nil{
		panic(err)
	}
	//用私钥解密
	plainText,err:=rsa.DecryptPKCS1v15(rand.Reader,privateKey,cryptoText)
	if err!=nil{
		panic(err)
	}
	return plainText
}