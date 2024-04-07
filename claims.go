package jwt

import "time"

type Claim func(*Payload)

func WithIssuer(issuer string) Claim {
	return func(payload *Payload) {
		payload.Issuer = issuer
	}
}

func WithOwner(owner string) Claim {
	return func(payload *Payload) {
		payload.Owner = owner
	}
}

func WithPurpose(purpose string) Claim {
	return func(payload *Payload) {
		payload.Purpose = purpose
	}
}

func WithRecipient(recipient string) Claim {
	return func(payload *Payload) {
		payload.Recipient = recipient
	}
}

func WithIssuedAt(issuedAt time.Time) Claim {
	return func(payload *Payload) {
		payload.IssuedAt = issuedAt
	}
}

func WithExpire(ttl time.Duration) Claim {
	return func(payload *Payload) {
		payload.Expire = ttl
	}
}

func WithExternalKV(key string, value interface{}) Claim {
	return func(payload *Payload) {
		payload.External[key] = value
	}
}

func WithExternal(external External) Claim {
	return func(payload *Payload) {
		payload.External = external
	}
}
