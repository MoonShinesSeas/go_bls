package bls

import (
	"fmt"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func Test_Main(t *testing.T) {
	msg := []byte("bls")
	//生成私钥
	x := new(fr.Element)
	x.SetRandom() // 从有限域 F_r 中随机生成私钥
	sk := &PrivateKey{X: x.BigInt(new(big.Int))}
	//私钥编码为pem文件
	err := sk.Encode()
	if err != nil {
		fmt.Printf("%v", err)
	}
	//私钥解码
	var private_key PrivateKey
	err = private_key.Decode()
	if err != nil {
		fmt.Printf("%v", err)
	}
	//签名
	sig, err := Sign(&private_key, msg)
	if err != nil {
		fmt.Printf("%v", err)
	}
	//生成公钥
	var publicKey bls12381.G2Affine
	publicKey.ScalarMultiplication(&g2, sk.X) // 公钥 = 私钥 * G2 生成元
	pk := &PublicKey{P: &publicKey}
	//公钥编码为pem文件
	err = pk.Encode()
	if err != nil {
		fmt.Printf("%v", err)
	}
	//公钥解码
	var public_key PublicKey
	public_key.Decode()
	//验证
	res, err := Verify(sig, &public_key, msg)
	if err != nil {
		fmt.Printf("%v", err)
	}
	if res {
		fmt.Println("验证通过")
	} else {
		fmt.Println("验证失败")
	}
}
