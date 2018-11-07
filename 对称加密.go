package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/aes"
)

//填充最后一个密码块
func paddingLastGroup(plainText []byte,blockSize int)[]byte{
	//接收明文和密码块的大小,计算需要填充的位数
	paddingNum:=blockSize-len(plainText)%blockSize
	//进行填充
	paddingText:=bytes.Repeat([]byte{byte(paddingNum)},paddingNum)
	//将填充后的最后一个密码块拼接到明文上
	plainText=append(plainText,paddingText...)
	return plainText
}
//去掉填充的部分
func unPaddingLastGroup(plainText []byte)[]byte{
	//接收解密后 明文,计算出需要去除的填充的位数
	unPaddingNum:=int(plainText[len(plainText)-1])
	//去掉填充
	unPaddingText:=plainText[:len(plainText)-unPaddingNum]
	return unPaddingText
}
//aes加密cbc
func AesEnCrypto(plainText,key []byte)[]byte{
	//生成一个Aes接口
	block,err:=aes.NewCipher(key)
	if err!=nil{
		panic(err)
	}
	//将明文进行填充
	plainText=paddingLastGroup(plainText,block.BlockSize())
	//选择密码分组模式
	iv:=[]byte("12345678asdfghjk")  //初始化向量
	blockMode:=cipher.NewCBCEncrypter(block,iv)
     //进行加密
     //第一个参数为加密/解密后的密文，第二个参数为需要加密/解密的明文,可以指向同一个内存地址
     blockMode.CryptBlocks(plainText,plainText)
     return plainText

}
//aes解密cbc
func AesDeCrypto(cryptoText,key []byte)[]byte{
	//生成一个Aes接口
   block,err:=aes.NewCipher(key)
	if err!=nil{
		panic(err)
	}
	//选择密码分组模式
	iv:=[]byte("12345678asdfghjk")
	blockMode:=cipher.NewCBCDecrypter(block,iv)
	blockMode.CryptBlocks(cryptoText,cryptoText)
	//去掉填充的部分
	cryptoText=unPaddingLastGroup(cryptoText)
	return cryptoText
}
//aes加密ctr
func AesEnCtr(plainText,key []byte)[]byte{
	//生成一个Aes接口
	block,err:=aes.NewCipher(key)
	if err!=nil{
		panic(err)
	}
	iv:=[]byte("12345678asdfghjk")
	//选择密码分组模式
	stream:=cipher.NewCTR(block,iv)
	//加密
	stream.XORKeyStream(plainText,plainText)
	return plainText
}
//aes解密ctr
func AesDeCtr(cryptoText,key []byte)[]byte{
	//生成一个Aes接口
	block,err:=aes.NewCipher(key)
	if err!=nil{
		panic(err)
	}
	iv:=[]byte("12345678asdfghjk")  //此处初始化向量可以理解为随机数种子
	//选择密码分组模式
	stream:=cipher.NewCTR(block,iv)
	//解密
	stream.XORKeyStream(cryptoText,cryptoText)
	return cryptoText


}