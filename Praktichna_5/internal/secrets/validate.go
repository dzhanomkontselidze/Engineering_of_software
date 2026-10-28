package secrets

import (
	"strings"
	"time"
)

// ValidateTTL перевіряє, що запитаний TTL додатний і не перевищує максимум політики.
func ValidateTTL(requested, policyMax time.Duration) error {
	if requested <= 0 {
		return ErrInvalidTTL
	}
	if requested > policyMax {
		return ErrTTLExceeded
	}
	return nil
}

// CheckAccess перевіряє, що надання доступу існує, активне, не прострочене
// і належить саме цьому ServiceAccount та джерелу секрету.
func CheckAccess(g *AccessGrant, serviceAccountID, sourceID string, now time.Time) error {
	switch {
	case g == nil:
		return ErrAccessDenied
	case g.Status != GrantActive:
		return ErrAccessDenied
	case g.ServiceAccountID != serviceAccountID || g.SourceID != sourceID:
		return ErrAccessDenied
	case !now.Before(g.ExpiresAt):
		return ErrAccessDenied
	}
	return nil
}

// ShouldRotate повертає true, коли до завершення TTL залишилось не більше,
// ніж RotateBefore (FR-5: ротація до завершення TTL).
func ShouldRotate(expiresAt, now time.Time, rotateBefore time.Duration) bool {
	return expiresAt.Sub(now) <= rotateBefore
}

// ValidateSecretPath відхиляє порожні, абсолютні шляхи та спроби path traversal.
func ValidateSecretPath(path string) error {
	if path == "" || strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return ErrInvalidPath
	}
	return nil
}
