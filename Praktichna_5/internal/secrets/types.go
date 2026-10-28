// Package secrets містить чисту бізнес-логіку Zero-Trust Secrets Operator:
// перевірку доступу, обчислення TTL, ротацію та видачу ephemeral-токенів.
package secrets

import (
	"context"
	"errors"
	"time"
)

// GrantStatus — стан надання доступу (сутність AccessGrant з Пр 03).
type GrantStatus string

const (
	GrantActive  GrantStatus = "Active"
	GrantExpired GrantStatus = "Expired"
	GrantRevoked GrantStatus = "Revoked"
)

// Помилки доменного рівня.
var (
	ErrAccessDenied = errors.New("access denied")
	ErrGrantExpired = errors.New("access grant expired or too short-lived")
	ErrInvalidTTL   = errors.New("invalid ttl")
	ErrTTLExceeded  = errors.New("requested ttl exceeds policy maximum")
	ErrInvalidPath  = errors.New("invalid secret path")
)

// AccessGrant — дозвіл ServiceAccount на використання джерела секрету.
type AccessGrant struct {
	ID               string
	ServiceAccountID string
	SourceID         string
	Status           GrantStatus
	ExpiresAt        time.Time
}

// Policy — політика секретів (SecretPolicy).
type Policy struct {
	MaxTTL       time.Duration
	RotateBefore time.Duration
}

// TokenRequest — запит на видачу токена.
type TokenRequest struct {
	ServiceAccountID string
	SourceID         string
	SecretPath       string
	TTL              time.Duration
}

// Token — виданий ephemeral-токен (значення секрету тут не зберігається).
type Token struct {
	ID        string
	GrantID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IssuedSecret — результат видачі: метадані токена + значення, яке йде лише в пам'ять Pod.
type IssuedSecret struct {
	Token Token
	Value []byte
}

// AuditEvent — подія аудиту (сутність AuditEvent з Пр 03).
type AuditEvent struct {
	Time             time.Time
	ServiceAccountID string
	SourceID         string
	Action           string
	Result           string
}

// Залежності, які в unit-тестах підміняються Mock-об'єктами.
type (
	// GrantRepository — доступ до даних про надані права (реально: Kubernetes API / БД).
	GrantRepository interface {
		FindGrant(ctx context.Context, serviceAccountID, sourceID string) (*AccessGrant, error)
	}
	// SecretProvider — зовнішнє сховище секретів (Vault, AWS, GCP).
	SecretProvider interface {
		FetchSecret(ctx context.Context, path string) ([]byte, error)
	}
	// AuditLogger — запис подій аудиту.
	AuditLogger interface {
		Record(ctx context.Context, event AuditEvent) error
	}
)
