package certkit

/*
MIT License

Copyright (c) 2026 Shane

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

// Minimal PBES2 (RFC 8018) support for "ENCRYPTED PRIVATE KEY" PEM blocks:
// PBKDF2-HMAC-SHA256 key derivation over AES-256-CBC. The Go standard
// library can marshal/unmarshal plaintext PKCS#8 (crypto/x509) but has no
// support for the encrypted PKCS#8 container, so certkit implements the
// small slice of RFC 8018 it needs using only crypto/pbkdf2, crypto/aes and
// encoding/asn1 -- no external dependency.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

const pkcs8PBKDF2Iterations = 10000

var (
	oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidAES256CBC      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type encryptedPrivateKeyInfo struct {
	Algo          pkix.AlgorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int
	PRF            pkix.AlgorithmIdentifier
}

// encryptPKCS8 wraps a plaintext PKCS#8 PrivateKeyInfo DER blob (as produced
// by x509.MarshalPKCS8PrivateKey) in a PBES2-encrypted PKCS#8
// EncryptedPrivateKeyInfo, returning its DER encoding.
func encryptPKCS8(plaintext []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	key, err := pbkdf2.Key(sha256.New, passphrase, salt, pkcs8PBKDF2Iterations, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	ivRaw, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}

	kdfParams, err := asn1.Marshal(pbkdf2Params{
		Salt:           salt,
		IterationCount: pkcs8PBKDF2Iterations,
		KeyLength:      32,
		PRF:            pkix.AlgorithmIdentifier{Algorithm: oidHMACWithSHA256, Parameters: asn1.NullRawValue},
	})
	if err != nil {
		return nil, err
	}

	pbes2, err := asn1.Marshal(pbes2Params{
		KeyDerivationFunc: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfParams},
		},
		EncryptionScheme: pkix.AlgorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivRaw},
		},
	})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: pbes2},
		},
		EncryptedData: ciphertext,
	})
}

// decryptPKCS8 reverses encryptPKCS8, returning the plaintext PKCS#8
// PrivateKeyInfo DER blob. Any structural mismatch, unsupported algorithm or
// padding failure is reported as ErrWrongPassphrase, since (without an
// integrity tag) a wrong passphrase and a corrupt/foreign file look the
// same.
func decryptPKCS8(data []byte, passphrase string) ([]byte, error) {
	var info encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(data, &info); err != nil {
		return nil, ErrWrongPassphrase
	}
	if !info.Algo.Algorithm.Equal(oidPBES2) {
		return nil, ErrWrongPassphrase
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(info.Algo.Parameters.FullBytes, &params); err != nil {
		return nil, ErrWrongPassphrase
	}
	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, ErrWrongPassphrase
	}
	if !params.EncryptionScheme.Algorithm.Equal(oidAES256CBC) {
		return nil, ErrWrongPassphrase
	}

	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
		return nil, ErrWrongPassphrase
	}

	var iv []byte
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, ErrWrongPassphrase
	}

	keyLen := kdf.KeyLength
	if keyLen == 0 {
		keyLen = 32
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, kdf.Salt, kdf.IterationCount, keyLen)
	if err != nil {
		return nil, ErrWrongPassphrase
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	if len(info.EncryptedData) == 0 || len(info.EncryptedData)%aes.BlockSize != 0 || len(iv) != aes.BlockSize {
		return nil, ErrWrongPassphrase
	}

	plainPadded := make([]byte, len(info.EncryptedData))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plainPadded, info.EncryptedData)

	plaintext, err := pkcs7Unpad(plainPadded, aes.BlockSize)
	if err != nil {
		return nil, ErrWrongPassphrase
	}

	return plaintext, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("certkit: invalid padded data length")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize || padLen > len(data) {
		return nil, errors.New("certkit: invalid padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("certkit: invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}
