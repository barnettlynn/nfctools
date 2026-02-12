package ntag424

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

func aesCBCEncrypt(key, iv, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("CBC encrypt: data not block aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

func aesCBCDecrypt(key, iv, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("CBC decrypt: data not block aligned")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

func aesECBEncrypt(key, blockIn []byte) ([]byte, error) {
	if len(blockIn) != 16 {
		return nil, fmt.Errorf("ECB input must be 16 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 16)
	block.Encrypt(out, blockIn)
	return out, nil
}

func padISO9797M2(data []byte) []byte {
	padLen := 16 - (len(data) % 16)
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	out[len(data)] = 0x80
	return out
}

func unpadISO9797M2(data []byte) ([]byte, error) {
	idx := len(data) - 1
	for idx >= 0 && data[idx] == 0x00 {
		idx--
	}
	if idx < 0 || data[idx] != 0x80 {
		return nil, errors.New("bad padding")
	}
	return data[:idx], nil
}

func rotateLeft1(in []byte) []byte {
	out := make([]byte, len(in))
	if len(in) == 0 {
		return out
	}
	copy(out, in[1:])
	out[len(in)-1] = in[0]
	return out
}

func rotateRight1(in []byte) []byte {
	out := make([]byte, len(in))
	if len(in) == 0 {
		return out
	}
	out[0] = in[len(in)-1]
	copy(out[1:], in[:len(in)-1])
	return out
}

func aesCMAC(key, msg []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	k1, k2 := generateCMACSubkeys(block)

	n := (len(msg) + 15) / 16
	if n == 0 {
		n = 1
	}
	lastComplete := len(msg) != 0 && len(msg)%16 == 0

	last := make([]byte, 16)
	if lastComplete {
		copy(last, msg[(n-1)*16:])
		xorBlock(last, last, k1)
	} else {
		remain := len(msg) - (n-1)*16
		if remain > 0 {
			copy(last, msg[(n-1)*16:])
		}
		last[remain] = 0x80
		xorBlock(last, last, k2)
	}

	x := make([]byte, 16)
	y := make([]byte, 16)
	for i := 0; i < n-1; i++ {
		blockStart := i * 16
		xorBlock(y, x, msg[blockStart:blockStart+16])
		block.Encrypt(x, y)
	}
	xorBlock(y, x, last)
	block.Encrypt(x, y)
	return x, nil
}

func generateCMACSubkeys(block cipherBlock) (k1, k2 []byte) {
	const rb = 0x87
	zero := make([]byte, 16)
	L := make([]byte, 16)
	block.Encrypt(L, zero)

	k1 = make([]byte, 16)
	leftShift1(k1, L)
	if (L[0] & 0x80) != 0 {
		k1[15] ^= rb
	}

	k2 = make([]byte, 16)
	leftShift1(k2, k1)
	if (k1[0] & 0x80) != 0 {
		k2[15] ^= rb
	}
	return k1, k2
}

type cipherBlock interface {
	Encrypt(dst, src []byte)
}

func leftShift1(dst, src []byte) {
	var carry byte
	for i := len(src) - 1; i >= 0; i-- {
		b := src[i]
		dst[i] = (b << 1) | carry
		carry = (b >> 7) & 1
	}
}

func xorBlock(dst, a, b []byte) {
	for i := 0; i < len(a) && i < len(b); i++ {
		dst[i] = a[i] ^ b[i]
	}
}

func truncateOddBytes(cmac []byte) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = cmac[1+i*2]
	}
	return out
}
