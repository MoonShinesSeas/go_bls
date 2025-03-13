package bls

import (
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var (
	g1    bls12381.G1Affine
	g2    bls12381.G2Affine
	order *big.Int
)

func init() {
	_, _, g1, g2 = bls12381.Generators()
	order = fr.Modulus()
}

type PrivateKey struct {
	X *big.Int
}

type PublicKey struct {
	P *bls12381.G2Affine
}

func GenPrivateKey() *PrivateKey {
	//生成私钥
	x := new(fr.Element)
	x.SetRandom() // 从有限域 F_r 中随机生成私钥
	sk := &PrivateKey{X: x.BigInt(new(big.Int))}
	return sk
}
func GenPublicKey(sk *PrivateKey) *PublicKey {
	//生成公钥
	var publicKey bls12381.G2Affine
	publicKey.ScalarMultiplication(&g2, sk.X) // 公钥 = 私钥 * G2 生成元
	pk := &PublicKey{P: &publicKey}
	return pk
}

func Sign(key *PrivateKey, msg []byte) (*bls12381.G1Affine, error) {
	hash := sha256.Sum256(msg)
	h, err := bls12381.HashToG1(hash[:], nil)
	if err != nil {
		return nil, err
	}
	return new(bls12381.G1Affine).ScalarMultiplication(&h, key.X), nil
}

func Verify(sig *bls12381.G1Affine, pk *PublicKey, msg []byte) (bool, error) {
	left, err := bls12381.Pair([]bls12381.G1Affine{*sig}, []bls12381.G2Affine{g2})
	if err != nil {
		return false, err
	}
	hash := sha256.Sum256(msg)
	h, err := bls12381.HashToG1(hash[:], nil)
	if err != nil {
		return false, err
	}
	right, err := bls12381.Pair([]bls12381.G1Affine{h}, []bls12381.G2Affine{*pk.P})
	if err != nil {
		return false, err
	}
	if left.Equal(&right) {
		return true, nil
	}
	return false, nil
}

// ToPEM 将私钥转换为PEM格式
func (sk *PrivateKey) Encode() error {
	// 将私钥编码为ASN.1 DER格式
	derBytes, err := asn1.Marshal(struct {
		X *big.Int
	}{
		X: sk.X,
	})
	if err != nil {
		return err
	}

	// 将DER编码的私钥封装为PEM格式
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	err = os.WriteFile("private_key.pem", pemBytes, 0644)
	if err != nil {
		fmt.Printf("Failed to write PEM file: %v\n", err)
		return err
	}
	return nil
}
func (sk *PrivateKey) Decode() error {
	// 读取PEM文件
	pemBytes, err := os.ReadFile("private_key.pem")
	if err != nil {
		return err
	}

	// 解码PEM块
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// 解码ASN.1 DER格式
	var tmp struct {
		X *big.Int
	}
	_, err = asn1.Unmarshal(pemBlock.Bytes, &tmp)
	if err != nil {
		return err
	}
	sk.X = tmp.X
	return nil
}
func (pk *PublicKey) Encode() error {
	pkBytes := pk.P.Bytes()
	derBytes, err := asn1.Marshal(struct {
		P []byte
	}{
		P: pkBytes[:],
	})
	if err != nil {
		return err
	}
	// 将DER编码的私钥封装为PEM格式
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	err = os.WriteFile("public_key.pem", pemBytes, 0644)
	if err != nil {
		fmt.Printf("Failed to write PEM file: %v\n", err)
		return err
	}
	return nil
}
func (pk *PublicKey) Decode() error {
	// 读取PEM文件
	pemBytes, err := os.ReadFile("public_key.pem")
	if err != nil {
		return err
	}

	// 解码PEM块
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// 解码ASN.1 DER格式
	var tmp struct {
		P []byte
	}
	_, err = asn1.Unmarshal(pemBlock.Bytes, &tmp)
	if err != nil {
		return err
	}

	// 将字节序列转换回 G2Affine 点
	var p bls12381.G2Affine
	_, err = p.SetBytes(tmp.P)
	if err != nil {
		return err
	}
	pk.P = &p
	return nil
}

// func main() {
// 	msg := []byte("bls")
// 	//生成私钥
// 	x := new(fr.Element)
// 	x.SetRandom() // 从有限域 F_r 中随机生成私钥
// 	sk := &PrivateKey{X: x.BigInt(new(big.Int))}
// 	//私钥编码为pem文件
// 	err := sk.Encode()
// 	if err != nil {
// 		fmt.Printf("%v", err)
// 	}
// 	//私钥解码
// 	var private_key PrivateKey
// 	err = private_key.Decode()
// 	if err != nil {
// 		fmt.Printf("%v", err)
// 	}
// 	//签名
// 	sig, err := Sign(&private_key, msg)
// 	if err != nil {
// 		fmt.Printf("%v", err)
// 	}
// 	//生成公钥
// 	var publicKey bls12381.G2Affine
// 	publicKey.ScalarMultiplication(&g2, sk.X) // 公钥 = 私钥 * G2 生成元
// 	pk := &PublicKey{P: &publicKey}
// 	//公钥编码为pem文件
// 	err = pk.Encode()
// 	if err != nil {
// 		fmt.Printf("%v", err)
// 	}
// 	//公钥解码
// 	var public_key PublicKey
// 	public_key.Decode()
// 	//验证
// 	res, err := Verify(sig, &public_key, msg)
// 	if err != nil {
// 		fmt.Printf("%v", err)
// 	}
// 	if res {
// 		fmt.Println("验证通过")
// 	} else {
// 		fmt.Println("验证失败")
// 	}
// }
