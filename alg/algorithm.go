package alg

import "sync"

type Algorithm interface {
	// Name The name of the algorithm
	Name() string
	// Encrypt Only pay attention to how to encrypt, return the encrypted original Signature data.
	// Don't do encoding processing; signing is a string that connects the header and the payload after encoding through the point ".".
	// 只关注如何加密, 返回加密后的原始Signature数据, 不要进行编码; signing为将header和payload编码后的通过点连接起来的字符串.
	Encrypt(signing, secret string) ([]byte, error)
}

var algorithms = &sync.Map{}

func GetAlgorithm(name string) Algorithm {
	alg, _ := algorithms.Load(name)
	return alg.(Algorithm)
}

func RegisterAlgorithm(alg Algorithm) {
	algorithms.Store(alg.Name(), alg)
}
