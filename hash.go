package main

import (
	"crypto/sha256"
	"encoding/hex"
)

func HashKey(src []byte)string{
	//生成一个hash对象接口
	myHash:=sha256.New()
	//向函数中写入数据
	_,err:=myHash.Write(src)
	if err!=nil{
		panic(err)
	}
	//可以多次调用
	_,err=myHash.Write(src)
	if err!=nil{
		panic(err)
	}
	//生成散列值
	rel:=myHash.Sum(nil)
	//将生成的二进制转化成16进制
	resultHash:=hex.EncodeToString(rel)
	return resultHash
}