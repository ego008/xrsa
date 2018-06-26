# xrsa
OpenSSL RSA Encryption, Decryption, and Key Generation. Large Data Support in Golang

## 示例

```
package main

import (
	"fmt"
	"time"
	"github.com/ego008/xrsa"
)

func main() {
	// example

	keyLen := 2048
	priKT := xrsa.PKCS1

	// 生成密钥对
	pubKey, priKey, err := xrsa.GenRsaKeyPair(keyLen, priKT)
	if err != nil {
		fmt.Println("生成密钥对失败", err)
		return
	}
	fmt.Println("pubkey:\n", string(pubKey))
	fmt.Println("prikey:\n", string(priKey))

	mRsa, err := xrsa.NewXRsa(pubKey, priKey, keyLen, priKT) // 输入密钥对
	mRsa, err = xrsa.NewXRsa(nil, nil, keyLen, priKT)        // 或密钥对留空
	if err != nil {
		fmt.Println("NewRsa 失败", err)
		return
	}

	data := "Hello, World"
	fmt.Println("data:", data)

	t1 := time.Now()

	// 以"实例"方式使用，适用于固定密钥对

	// 公钥加密
	encrypted, err := mRsa.PublicEncrypt(data)
	if err != nil {
		fmt.Println("公钥加密失败", err)
		return
	}
	fmt.Println("encrypted:", encrypted)

	// 私钥解密
	decrypted, err := mRsa.PrivateDecrypt(encrypted)
	if err != nil {
		fmt.Println("私钥解密失败", err)
		return
	}
	fmt.Println("decrypted:", decrypted)

	if data == decrypted {
		fmt.Println("公钥加密、私钥解密成功！")
	} else {
		fmt.Println("公钥加密成功！私钥解密失败！！！")
	}

	// 签名、验签
	sign, err := mRsa.Sign(data)
	if err != nil {
		fmt.Println("签名失败", err)
		return
	}
	fmt.Println("sign:", sign)

	err = mRsa.Verify(data, sign)
	if err != nil {
		fmt.Println("验签失败", err)
	} else {
		fmt.Println("验签成功")
	}

	fmt.Println("time:", time.Now().Sub(t1))

	// 以"函数"方式使用，适用于动态密钥对

	// 函数示例
	fmt.Println("------------函数示例---------")
	pubKeyStr := string(pubKey)
	priKeyStr := string(priKey)

	t1 = time.Now()

	// 公钥加密
	encrypted, err = xrsa.PublicEncrypt(pubKeyStr, data)
	if err != nil {
		fmt.Println("公钥加密失败", err)
		return
	}
	fmt.Println("encrypted:", encrypted)

	// 私钥解密
	decrypted, err = xrsa.PrivateDecrypt(pubKeyStr, priKeyStr, encrypted, xrsa.PKCS1)
	if err != nil {
		fmt.Println("私钥解密失败", err)
		return
	}
	fmt.Println("decrypted:", decrypted)

	if data == decrypted {
		fmt.Println("公钥加密、私钥解密成功！")
	} else {
		fmt.Println("公钥加密成功！私钥解密失败！！！")
	}

	// 签名、验签
	sign, err = xrsa.Sign(priKeyStr, data, xrsa.PKCS1)
	if err != nil {
		fmt.Println("签名失败", err)
		return
	}
	fmt.Println("sign:", sign)

	err = xrsa.Verify(pubKeyStr, data, sign)
	if err != nil {
		fmt.Println("验签失败", err)
	} else {
		fmt.Println("验签成功")
	}

	fmt.Println("time:", time.Now().Sub(t1))
}

```

## 感谢

基于 [https://github.com/liamylian/x-rsa/tree/master/golang/xrsa](https://github.com/liamylian/x-rsa/tree/master/golang/xrsa) 改进
