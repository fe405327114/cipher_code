package main

import (
	"fmt"
)

func main(){
	//aes加解密
	fmt.Println("aesCBC")
	plainText:=[]byte("aesCBC原始数据")
	keyCBC:=[]byte("asdfghjkasdfghjk")
	enResult:=AesEnCrypto(plainText,keyCBC)
	deResult:=AesDeCrypto(enResult,keyCBC)
	fmt.Printf("CBC解密后的数据为:%s\n",deResult)

	fmt.Println("aesCTR")
	plainText=[]byte("aesCTR原始数据")
    keyCTR:=[]byte("asdfghjkasdfghjk")
    enCtrResult:=AesEnCtr(plainText,keyCTR)
	deCtrResult:=AesDeCtr(enCtrResult,keyCTR)
	fmt.Printf("CTR解密后的数据为:%s\n",deCtrResult)

	//rsa秘钥对生成
	bits:=1024
	RsaPrivateKey(bits)
    //rsa公钥加密
    plainText=[]byte("rsa原始数据")
    fileNamePublic:="rsa_public.pem"
	cryptoText:=RsaPublicCipher(plainText,fileNamePublic)
	//rsa私钥解密
	fileNamePrivate:="rsa_private.pem"
	plainText=RsaPrivateCipher(cryptoText,fileNamePrivate)
	fmt.Printf("rsa解密后的数据为：%s\n",plainText)

	//hash函数
	src:=[]byte("hash原始数据")
	resultHash:=HashKey(src)
	fmt.Println(resultHash)
	// 数字签名
	signRsa(fileNamePrivate,fileNamePublic)
	//ecdsa数字签名
	EcdsaSign()
}

func signRsa(fileNamePrivate,fileNamePublic string){
	plainText:=[]byte("数字签名原始数据")
  cryptoText:=SignHash(plainText,fileNamePrivate)
  signFlag:=VerifyHash(plainText,cryptoText,fileNamePublic)
	fmt.Println(signFlag)
}
func EcdsaSign(){
	//生成ecdsa公私钥对
	DsaGenerateKey()
	plainText:=[]byte("ecdsa原始数据")
	fileNamePrivate:="ecdsa_private.pem"
	fileNamePublic:="ecdsa_public.pem"
	rText,sText:=DsaSignKey(plainText,fileNamePrivate)
	signFlag:=DsaVerifyKey(plainText,fileNamePublic,rText,sText)
	fmt.Println(signFlag)
}