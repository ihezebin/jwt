package jwt

import (
	"testing"
	"time"
)

const secret = "secret"

func TestGenerateToken(t *testing.T) {
	token := Default(WithOwner("hezebin"), WithExternalKV("key", "value"))
	signed, err := token.Signed(secret)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(signed)
	t.Log(token.Faked())
	t.Log(token.Expired())
	t.Logf("%+v", token.Payload())
}
func TestTokenExpired(t *testing.T) {
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
