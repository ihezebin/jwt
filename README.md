# jwt
A Golang Implementation of [JSON Web Token](https://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)

> 基于官方规范的实现,

# 使用

## 安装
```bash
go get github.com/ihezebin/jwt
```

## 生成 Token
```go
const secret = "secret"

func TestGenerateToken(t *testing.T) {
token := Default(WithOwner("hezebin"), WithExternalKV("key", "value"), WithExpire(time.Second*30))
	signed, err := token.Signed(secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(signed)
	t.Log(token.Faked())
	t.Log(token.Expired())
	t.Logf("%+v", token.Payload())
}
```

## 校验解析 Token
```go
const tokenStr = "eyJlbmNvZGUiOiJiYXNlNjRyYXd1cmwiLCJ0eXAiOiJqd3QiLCJhbGciOiJIU0EyNTYifQ.eyJpc3N1ZXIiOiJnaXRodWIuY29tL2loZXplYmluL2p3dCIsIm93bmVyIjoiaGV6ZWJpbiIsInB1cnBvc2UiOiJhdXRoZW50aWNhdGlvbiIsImlzc3VlZF9hdCI6IjIwMjQtMDQtMDdUMTQ6MTk6MTYuNzkxNzE5KzA4OjAwIiwiZXhwaXJlIjozMDAwMDAwMDAwMCwiZXh0ZXJuYWwiOnsia2V5IjoidmFsdWUifX0.gGzRAc-IbrkaBqM_UxXtxxPMye_-MVzRHZt7sg9lTAA"
const fakeStr = "eyJlbmNvZGUiOiJiYXNlNjRyYXd1cmwiLCJ0eXAiOiJqd3QiLCJhbGciOiJIU0EyNTYifQ." +
	"eyJpc3N1ZXIiOiJnaXRodWIuY29tL2loZXplYmluL2p3dCIsIm93bmVyIjoiaGV6ZWJpbiIsInB1cnBvc2UiOiJhdXRoZW50aWNhdGlvbiIsImlzc3VlZF9hdCI6IjIwMjQtMDQtMDdUMTQ6MDU6NTcuNzk3MTgxKzA4OjAwIiwiZXhwaXJlIjozMDAwMDAwMDAwMCwiZXh0ZXJuYWwiOnsia2V5IjoidmFsdWUifX0.KKVwvFwaG8K_KfxHeJVjiAjqA83E0WLiCBLH4FsD3591"

func TestParseToken(t *testing.T) {
	token, err := Parse(tokenStr, secret)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(token.Faked())
	t.Log(token.Expired())
	t.Logf("%+v", token.Payload())
}
func TestParseTokenFake(t *testing.T) {
	token, err := Parse(fakeStr, secret)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(token.Faked())
	t.Log(token.Expired())
	t.Logf("%+v", token.Payload())
}
```

## 自定义加密算法
实现自定义加密算法后需要注册统一管理，以便解析 token 时从 header 中读取对应的算法

```go
import (
	"crypto/hmac"
	"crypto/sha256"
)

type hsa256 struct {
}

func HSA256() Algorithm {
	return &hsa256{}
}

func (alg *hsa256) Name() string {
	return "HSA256"
}

func (alg *hsa256) Encrypt(signing, secret string) ([]byte, error) {
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write([]byte(signing))
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func init() {
	RegisterAlgorithm(HSA256())
}

```

# JWT 原理

## 1.简述
JWT（JSON Web Token）是一种开放标准（RFC 7519），用于在各方之间安全地传输信息作为 JSON 对象。JWT 可以在用户和服务器之间传递安全可靠的信息，因为它使用数字签名（在最简单的情况下也可以是加密）来验证信息的可靠性。下面是 JWT 协议的详细讲解：

## 2.结构：
JWT 由三部分组成，分别是 Header、Payload 和 Signature。这三部分通常使用 Base64 编码后连接在一起，中间用英文句点（.）分隔。

- Header：包含了 Token 类型（即 JWT）、所使用的加密算法等信息。通常是一个 JSON 对象。
- Payload：即 Token 的主体内容，包含了要传输的信息，也是一个 JSON 对象。
- Signature：用于验证 Token 真实性的签名部分，由 Header 和 Payload 使用指定的算法加密后得到的。

因此，jwt 通常的字符结构为：xxxxx.yyyyy.zzzzz

### 2.1 Header
Header 通常由两部分组成：令牌的类型（即 JWT）和正在使用的签名算法，例如 HMAC SHA256 或 RSA。例如：
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
此 JSON 被 Base64Url 编码以形成JWT的第一部分。

### 2.2 Payload
Payload 包含 Claims； Claims 是有关实体（通常是用户）和其他数据的声明，不放用户敏感的信息，如密码。

#### 2.2.1 Claims
Claims 是 JWT 官方规范中定义的名词，用于描述 Token 中包含的声明信息。在 JWT 规范中，Token 是由 Header、Payload 和 Signature 组成的，而 Payload 中包含了 Claims，用于携带各种声明信息，比如用户ID、过期时间、权限等等。这些声明信息由 Token 的颁发者自行定义和添加，以满足具体的需求。

Claims 同样使用Base64编码，分为共有声明和私有声明：

- 公有声明: JWT提供了内置关键字用于描述常见的问题，此部分均为可选项，用户根据自己的需求，按需添加key，常见的公共声明如下：
```bash
{   'exp':xxx,  # Expiration Time，此Token的过期时间的时间戳
    'iss':xxx,  #（Issuer）指明此token的签发者
    'iat':xxx,  # Issued at 指明此创建时间内的时间戳
    'aud':xxx,  # Audience 指明此Token签发面向群体
}
```
>特殊说明： 若 encode 得时候 payload 中添加了 exp 字段；则 exp 字段的值需为 "当前时间戳+此token的有效期时间"，例如希望 token 300秒后过期。

`{"exp":time.time()+300}`在执行 decode 时，若检查到 exp 字段，且 token 过期，则抛出
`jwt.ExpiredSignatureError`

- 私有声明: 用户可根据自己的业务需求，添加自定义的key，如下：
```json
{"username": "hezebin"}
```

公有声明和私有声明均在同一个字典中，转成 json 串并用 base64 编码


### 2.3 Signature

根据 header 中的 alg 确定具体算法，以下用HS256为例： HS256（自定义的key，base64后的header + '.'+base64后的payload）
```bash
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret);
```
最后再将得到的结果进行 base64 编码。

### 2.3.1 签名目的
签名的过程实际上是对头部以及负载内容进行签名，防止内容被窜改。如果有人对头部以及负载的内容解码之后进行修改，
再进行编码，最后加上之前的签名组合形成新的JWT的话，那么服务器端会判断出新的头部和负载形成的签名和JWT附带上的签名是不一样的。 如果要对新的头部和负载进行签名，在不知道服务器加密时用的密钥的话，得出来的签名也是不一样的。

### 2.3.2 信息安全
Base64是一种编码，是可逆的，适合传递一些非敏感信息。请注意，对于签名令牌，此信息虽然受到篡改保护，但任何人都可以读取。不要将机密信息放在 JWT 的有效负载或标头元素中，除非它已加密。


## 3.生成过程：

- 选择合适的加密算法（如 HMAC、RSA 等）和密钥。
- 将要传输的信息写入 Payload。
- 使用选定的加密算法和密钥对 Header 和 Payload 进行加密，生成 Signature。
- 将 Header、Payload 和 Signature 连接起来，生成 JWT。

## 4.验证过程：

- 接收到 JWT 后，将其按照同样的方式拆分成 Header、Payload 和 Signature。
- 使用相同的算法和密钥对 Header 和 Payload 进行加密，得到一个新的 Signature。
- 将新生成的 Signature 与接收到的 Signature 进行比较，如果相同，则验证通过，否则认为 Token 无效。

## 5.使用场景：
认证：用于验证用户身份，比如用户登录后颁发一个包含用户信息的 JWT。
授权：在用户身份验证通过后，可以根据用户权限颁发特定权限的 JWT，用于访问特定资源。