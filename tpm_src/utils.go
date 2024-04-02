package tpm

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

// DecodeBase64PublicKey 将 Base64 编码的公钥字符串解码为 *ecdsa.PublicKey 类型
func DecodeBase64PublicKey(publicKeyBase64 string) (*ecdsa.PublicKey, error) {
	// 解码 Base64 编码的公钥字符串
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("解码公钥出错: %v", err)
	}
	// 解析 DER 编码的公钥
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("解析 DER 编码的公钥出错: %v", err)
	}

	// 转换公钥类型为 *ecdsa.PublicKey
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("转换公钥类型出错")
	}

	return ecdsaPublicKey, nil
}
func DecodeBase64Signature(signatureBase64 string) (*big.Int, *big.Int, error) {
	// 解码 Base64 编码的签名字符串
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("解码签名出错: %v", err)
	}

	// 解析 DER 编码的 ECDSA 签名
	var signature struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(signatureBytes, &signature)
	if err != nil {
		return nil, nil, fmt.Errorf("解析签名出错: %v", err)
	}

	return signature.R, signature.S, nil
}
func VerifySignature(publickeyStr, signature string, messageBytes []byte) (bool, error) {
	publicKey, err := DecodeBase64PublicKey(publickeyStr)
	if err != nil {
		return false, err
	}
	// 对签名进行DER解码
	r, s, err := DecodeBase64Signature(signature)
	if err != nil {
		fmt.Println("解码签名出错:", err)
		return false, err
	}
	// 对消息进行哈希处理
	hashed := sha256.Sum256(messageBytes)

	// 验证签名
	if ecdsa.Verify(publicKey, hashed[:], r, s) {
		return true, nil
	} else {
		return false, nil
	}
}
