package secrets

import (
	"errors"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

// UT-01: перевірка TTL проти політики.
func TestValidateTTL(t *testing.T) {
	tests := []struct {
		name      string
		requested time.Duration
		want      error
	}{
		{"within policy", 15 * time.Minute, nil},
		{"equal to maximum", time.Hour, nil},
		{"exceeds maximum", 61 * time.Minute, ErrTTLExceeded},
		{"zero", 0, ErrInvalidTTL},
		{"negative", -time.Minute, ErrInvalidTTL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			err := ValidateTTL(tc.requested, time.Hour)
			// Assert
			if !errors.Is(err, tc.want) {
				t.Errorf("ValidateTTL(%v) = %v, want %v", tc.requested, err, tc.want)
			}
		})
	}
}

// UT-02: перевірка прав доступу ServiceAccount до джерела.
func TestCheckAccess(t *testing.T) {
	active := &AccessGrant{ServiceAccountID: "sa-1", SourceID: "src-1", Status: GrantActive, ExpiresAt: fixedNow.Add(time.Hour)}
	tests := []struct {
		name  string
		grant *AccessGrant
		sa    string
		want  error
	}{
		{"active grant", active, "sa-1", nil},
		{"no grant", nil, "sa-1", ErrAccessDenied},
		{"another service account", active, "sa-2", ErrAccessDenied},
		{"revoked", &AccessGrant{ServiceAccountID: "sa-1", SourceID: "src-1", Status: GrantRevoked, ExpiresAt: fixedNow.Add(time.Hour)}, "sa-1", ErrAccessDenied},
		{"expired by time", &AccessGrant{ServiceAccountID: "sa-1", SourceID: "src-1", Status: GrantActive, ExpiresAt: fixedNow.Add(-time.Second)}, "sa-1", ErrAccessDenied},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAccess(tc.grant, tc.sa, "src-1", fixedNow)
			if !errors.Is(err, tc.want) {
				t.Errorf("CheckAccess() = %v, want %v", err, tc.want)
			}
		})
	}
}

// UT-03: момент ротації «за N до завершення TTL».
func TestShouldRotate(t *testing.T) {
	expires := fixedNow.Add(15 * time.Minute)
	rotateBefore := 2 * time.Minute
	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"fresh token", fixedNow, false},
		{"3 minutes left", expires.Add(-3 * time.Minute), false},
		{"exactly at threshold", expires.Add(-2 * time.Minute), true},
		{"1 minute left", expires.Add(-time.Minute), true},
		{"already expired", expires.Add(time.Second), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRotate(expires, tc.now, rotateBefore); got != tc.want {
				t.Errorf("ShouldRotate() = %v, want %v", got, tc.want)
			}
		})
	}
}

// UT-04: валідація шляху до секрету (захист від path traversal).
func TestValidateSecretPath(t *testing.T) {
	tests := []struct {
		name string
		path string
		want error
	}{
		{"valid relative path", "prod/db/password", nil},
		{"empty", "", ErrInvalidPath},
		{"absolute path", "/etc/passwd", ErrInvalidPath},
		{"path traversal", "prod/../../admin", ErrInvalidPath},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSecretPath(tc.path); !errors.Is(err, tc.want) {
				t.Errorf("ValidateSecretPath(%q) = %v, want %v", tc.path, err, tc.want)
			}
		})
	}
}
