package xrsa

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

type pkcsType int64

const (
	rsaAlgorithmSign = crypto.SHA256

	PKCS1 pkcsType = iota
	PKCS8
)

type XRsa struct {
	keyLen         int
	privateKeyType pkcsType
	publicKey      *rsa.PublicKey
	privateKey     *rsa.PrivateKey
}

// 生成密钥对
func GenRsaKeyPair(keyLength int, privateKeyType pkcsType) (public, private []byte, err error) {
	buf := bytes.NewBufferString("")

	// 生成私钥文件
	var privateKey *rsa.PrivateKey
	privateKey, err = rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		return
	}

	var derStream []byte

	switch privateKeyType {
	case PKCS1:
		derStream = x509.MarshalPKCS1PrivateKey(privateKey) // PKCS1
	case PKCS8:
		derStream = MarshalPKCS8PrivateKey(privateKey) // PKCS8
		//derStream, err = x509.MarshalPKCS8PrivateKey(privateKey) // PKCS8
		//if err != nil {
		//	return
		//}
	default:
		err = errors.New("unsupported private key type")
		return
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derStream,
	}
	err = pem.Encode(buf, block)
	if err != nil {
		return
	}
	private = buf.Bytes()

	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	buf = bytes.NewBufferString("")
	err = pem.Encode(buf, block)
	if err != nil {
		return nil, nil, err
	}
	public = buf.Bytes()

	return
}

func parsePrivateKey(blockBytes []byte, privateKeyType pkcsType) (private *rsa.PrivateKey, err error) {
	switch privateKeyType {
	case PKCS1:
		private, err = x509.ParsePKCS1PrivateKey(blockBytes)
	case PKCS8:
		var privateKey interface{}
		privateKey, err = x509.ParsePKCS8PrivateKey(blockBytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		private, ok = privateKey.(*rsa.PrivateKey)
		if !ok {
			err = errors.New("private key not supported")
		}
	default:
		err = errors.New("unsupported private key type")
	}
	return
}

func NewXRsa(publicKey []byte, privateKey []byte, keyLen int, privateKeyType pkcsType) (xRsa *XRsa, err error) {
	if publicKey == nil || privateKey == nil {
		publicKey, privateKey, err = GenRsaKeyPair(keyLen, privateKeyType)
		if err != nil {
			return
		}
	}

	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}
	pub := pubInterface.(*rsa.PublicKey)

	block, _ = pem.Decode(privateKey)
	if block == nil {
		err = errors.New("private key error")
		return
	}

	var private *rsa.PrivateKey
	private, err = parsePrivateKey(block.Bytes, privateKeyType)
	if err != nil {
		return
	}

	xRsa = &XRsa{
		keyLen:         keyLen,
		privateKeyType: privateKeyType,
		publicKey:      pub,
		privateKey:     private,
	}

	return
}

// 公钥加密
func PublicEncrypt(publicKey, data string) (string, error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return "", errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub := pubInterface.(*rsa.PublicKey)

	partLen := pub.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := rsa.EncryptPKCS1v15(rand.Reader, pub, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(bts)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// 公钥加密
func (r *XRsa) PublicEncrypt(data string) (string, error) {
	partLen := r.publicKey.N.BitLen()/8 - 11
	chunks := split([]byte(data), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bts, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(bts)
	}

	return base64.RawURLEncoding.EncodeToString(buffer.Bytes()), nil
}

// 私钥解密
func PrivateDecrypt(publicKey, privateKey, encrypted string, privateKeyType pkcsType) (originalData string, err error) {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		err = errors.New("public key error")
		return
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub := pubInterface.(*rsa.PublicKey)

	block, _ = pem.Decode([]byte(privateKey))
	if block == nil {
		err = errors.New("private key error")
		return
	}

	var pri *rsa.PrivateKey
	pri, err = parsePrivateKey(block.Bytes, privateKeyType)

	partLen := pub.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	var decrypted []byte
	for _, chunk := range chunks {
		decrypted, err = rsa.DecryptPKCS1v15(rand.Reader, pri, chunk)
		if err != nil {
			return
		}
		buffer.Write(decrypted)
	}

	originalData = buffer.String()
	return
}

// 私钥解密
func (r *XRsa) PrivateDecrypt(encrypted string) (string, error) {
	partLen := r.publicKey.N.BitLen() / 8
	raw, err := base64.RawURLEncoding.DecodeString(encrypted)
	chunks := split([]byte(raw), partLen)

	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, chunk)
		if err != nil {
			return "", err
		}
		buffer.Write(decrypted)
	}

	return buffer.String(), err
}

// 私钥签名
func Sign(privateKey, data string, privateKeyType pkcsType) (signResult string, err error) {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		err = errors.New("private key error")
		return
	}

	var pri *rsa.PrivateKey

	pri, err = parsePrivateKey(block.Bytes, privateKeyType)
	if err != nil {
		return
	}

	h := rsaAlgorithmSign.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	var sign []byte
	sign, err = rsa.SignPKCS1v15(rand.Reader, pri, rsaAlgorithmSign, hashed)
	if err != nil {
		return
	}

	signResult = base64.RawURLEncoding.EncodeToString(sign)
	return
}

// 私钥签名
func (r *XRsa) Sign(data string) (signResult string, err error) {
	h := rsaAlgorithmSign.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	sign, err := rsa.SignPKCS1v15(rand.Reader, r.privateKey, rsaAlgorithmSign, hashed)
	if err != nil {
		return
	}

	signResult = base64.RawURLEncoding.EncodeToString(sign)
	return
}

// 签名验证
func Verify(publicKey, data string, sign string) error {
	block, _ := pem.Decode([]byte(publicKey))
	if block == nil {
		return errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	pub := pubInterface.(*rsa.PublicKey)

	h := rsaAlgorithmSign.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	decodedSign, err := base64.RawURLEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(pub, rsaAlgorithmSign, hashed, decodedSign)
}

// 签名验证
func (r *XRsa) Verify(data string, sign string) error {
	h := rsaAlgorithmSign.New()
	h.Write([]byte(data))
	hashed := h.Sum(nil)

	decodedSign, err := base64.RawURLEncoding.DecodeString(sign)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(r.publicKey, rsaAlgorithmSign, hashed, decodedSign)
}

// PKCS8
func MarshalPKCS8PrivateKey(key *rsa.PrivateKey) []byte {
	info := struct {
		Version             int
		PrivateKeyAlgorithm []asn1.ObjectIdentifier
		PrivateKey          []byte
	}{}
	info.Version = 0
	info.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
	info.PrivateKeyAlgorithm[0] = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	info.PrivateKey = x509.MarshalPKCS1PrivateKey(key)

	k, _ := asn1.Marshal(info)
	return k
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	bufLen := len(buf)
	if bufLen > 0 {
		chunks = append(chunks, buf[:bufLen])
	}
	return chunks
}
