package jwt

import (
	"fmt"
	"strings"
	"time"

	"github.com/ihezebin/jwt/alg"
	"github.com/pkg/errors"
)

type jwt struct {
	header    *header
	payload   *Payload
	signature *signature
	raw       string
	faked     bool
}

func Default(claims ...Claim) *jwt {
	return NewWithClaims(alg.HSA256(), claims...)
}

func New(algorithm alg.Algorithm) *jwt {
	return NewWithClaims(algorithm)
}

func NewWithClaims(algorithm alg.Algorithm, claims ...Claim) *jwt {
	if algorithm == nil {
		algorithm = alg.HSA256()
	}
	h := newHeader(algorithm)
	p := newPayloadWithClaims(claims...)
	s := newSignature(h, p)

	return &jwt{
		header:    h,
		payload:   p,
		signature: s,
	}
}

func (j *jwt) Payload() *Payload {
	return j.payload
}

func (j *jwt) Signed(secret string) (string, error) {
	h, err := j.header.Encoding()
	if err != nil {
		return "", errors.Wrap(err, "encode header err")
	}

	if j.payload.IssuedAt.IsZero() {
		j.payload.IssuedAt = time.Now()
	}

	p, err := j.payload.Encoding()
	if err != nil {
		return "", errors.Wrap(err, "encode payload err")
	}

	s, err := j.signature.WithSecret(secret).Encoding()
	if err != nil {
		return "", errors.Wrap(err, "encode signature err")
	}

	j.raw = fmt.Sprintf("%s.%s.%s", h, p, s)
	return j.raw, nil
}

func (j *jwt) Expired() bool {
	if j.faked {
		return true
	}

	if j.payload.Expire == 0 {
		return false
	}

	expire := j.payload.IssuedAt.Add(j.payload.Expire)

	return expire.Before(time.Now())
}

func (j *jwt) Faked() (bool, error) {
	if j.header == nil || j.payload == nil || j.signature == nil {
		return true, nil
	}

	if j.raw == "" {
		return true, nil
	}

	if j.header.encodeStr == "" || j.payload.encodeStr == "" || j.signature.encodeStr == "" {
		return true, nil
	}

	// 签发时间大于当前时间
	if j.payload.IssuedAt.After(time.Now()) {
		return true, nil
	}

	originEncodeStr := j.signature.encodeStr
	newEncodeStr, err := j.signature.Encoding()
	if err != nil {
		return true, errors.Wrap(err, "recode signature err")
	}

	if newEncodeStr != originEncodeStr {
		return true, nil
	}

	j.faked = false
	return false, nil
}

func Parse(raw string, secret string) (*jwt, error) {
	segments := strings.Split(raw, ".")
	if len(segments) != 3 {
		return nil, errors.New("the token consists of three segments connected by points like: xxx.yyy.zzz")
	}
	headerEncodeStr, payloadEncodeStr, signatureEncodeStr := segments[0], segments[1], segments[2]

	h, err := decodingHeader(headerEncodeStr)
	if err != nil {
		return nil, errors.Wrap(err, "decode header err")
	}

	p, err := decodingPayload(payloadEncodeStr)
	if err != nil {
		return nil, errors.Wrap(err, "decode payload err")
	}

	s := &signature{
		header:    h,
		payload:   p,
		secret:    secret,
		encodeStr: signatureEncodeStr,
	}

	j := &jwt{
		header:    h,
		payload:   p,
		signature: s,
		raw:       raw,
		faked:     true,
	}

	return j, nil
}
