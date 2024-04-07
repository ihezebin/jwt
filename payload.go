package jwt

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

type Payload struct {
	// 签发者
	Issuer string `json:"issuer,omitempty"`
	// 令牌所有者,存放ID等标识
	Owner string `json:"owner,omitempty"`
	// 用途,默认值authentication表示用于登录认证
	Purpose string `json:"purpose,omitempty"`
	// 接受方,表示申请该令牌的设备来源,如浏览器、Android等
	Recipient string `json:"recipient,omitempty"`
	// 令牌签发时间
	IssuedAt time.Time `json:"issued_at,omitempty"`
	// 过期时间, expire = time + duration
	Expire time.Duration `json:"expire,omitempty"`
	// 其他扩展的自定义参数
	External  External `json:"external,omitempty"`
	encodeStr string
}

type External map[string]interface{}

func (e External) Get(key string) interface{} {
	return e[key]
}

func newPayloadWithClaims(claims ...Claim) *Payload {
	p := &Payload{
		Issuer:   "github.com/ihezebin/jwt",
		Purpose:  "authentication",
		External: make(External),
	}

	for _, claim := range claims {
		claim(p)
	}

	return p
}

func (p *Payload) Encoding() (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", errors.Wrap(err, "marshal err")
	}
	p.encodeStr = base64.RawURLEncoding.EncodeToString(data)
	return p.encodeStr, nil
}

func decodingPayload(payloadEncodeStr string) (*Payload, error) {
	data, err := base64.RawURLEncoding.DecodeString(payloadEncodeStr)
	if err != nil {
		return nil, errors.Wrap(err, "decode err")
	}

	p := new(Payload)
	if err = json.Unmarshal(data, p); err != nil {
		return nil, errors.Wrap(err, "unmarshal err")
	}
	p.encodeStr = payloadEncodeStr

	return p, nil
}
