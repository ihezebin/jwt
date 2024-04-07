package jwt

import (
	"encoding/base64"
	"encoding/json"

	"github.com/ihezebin/jwt/alg"
	"github.com/pkg/errors"
)

type header struct {
	Encode    string `json:"encode"`
	Typ       string `json:"typ"`
	Alg       string `json:"alg"`
	algorithm alg.Algorithm
	encodeStr string
}

func newHeader(algorithm alg.Algorithm) *header {
	return &header{
		Encode:    "base64rawurl",
		Typ:       "jwt",
		Alg:       algorithm.Name(),
		algorithm: algorithm,
	}
}

func (h *header) Encoding() (string, error) {
	data, err := json.Marshal(h)
	if err != nil {
		return "", errors.Wrap(err, "marshal err")
	}
	h.encodeStr = base64.RawURLEncoding.EncodeToString(data)
	return h.encodeStr, nil
}

func decodingHeader(headerEncodeStr string) (*header, error) {
	data, err := base64.RawURLEncoding.DecodeString(headerEncodeStr)
	if err != nil {
		return nil, errors.Wrap(err, "decode err")
	}

	h := new(header)
	if err = json.Unmarshal(data, h); err != nil {
		return nil, errors.Wrap(err, "unmarshal err")
	}
	algorithm := alg.GetAlgorithm(h.Alg)
	h.algorithm = algorithm
	h.encodeStr = headerEncodeStr

	return h, nil
}
