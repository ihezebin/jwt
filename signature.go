package jwt

import (
	"encoding/base64"
	"fmt"

	"github.com/pkg/errors"
)

type signature struct {
	header    *header
	payload   *Payload
	secret    string
	encodeStr string
}

func newSignature(h *header, p *Payload) *signature {
	return &signature{
		header:  h,
		payload: p,
	}
}

func (s *signature) WithSecret(secret string) *signature {
	s.secret = secret
	return s
}

func (s *signature) Encoding() (string, error) {
	var err error
	headerEncodeStr := s.header.encodeStr
	if headerEncodeStr == "" {
		headerEncodeStr, err = s.header.Encoding()
		if err != nil {
			return "", errors.Wrap(err, "encode header err")
		}
	}

	payloadEncodeStr := s.payload.encodeStr
	if payloadEncodeStr == "" {
		payloadEncodeStr, err = s.payload.Encoding()
		if err != nil {
			return "", errors.Wrap(err, "encode payload err")
		}
	}

	encrypt, err := s.header.algorithm.Encrypt(fmt.Sprintf("%s.%s", headerEncodeStr, payloadEncodeStr), s.secret)
	if err != nil {
		return "", errors.Wrap(err, "encrypt err")
	}

	s.encodeStr = base64.RawURLEncoding.EncodeToString(encrypt)
	return s.encodeStr, nil
}
