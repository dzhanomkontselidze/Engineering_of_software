package secrets

import (
	"testing"
	"time"
)

func TestEffectiveTTL_LimitedByGrantExpiry(t *testing.T) {
	// Arrange
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	grantExpires := now.Add(10 * time.Minute)
	requested := 30 * time.Minute

	// Act
	got, err := EffectiveTTL(now, requested, grantExpires)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := 10 * time.Minute; got != want {
		t.Errorf("EffectiveTTL() = %v, want %v", got, want)
	}
}

func TestEffectiveTTL_ShorterRequestIsKept(t *testing.T) {
	// Arrange
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	grantExpires := now.Add(time.Hour)

	// Act
	got, err := EffectiveTTL(now, 5*time.Minute, grantExpires)

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := 5 * time.Minute; got != want {
		t.Errorf("EffectiveTTL() = %v, want %v", got, want)
	}
}

func TestEffectiveTTL_ExpiredOrAlmostExpiredGrant(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	cases := map[string]time.Time{
		"already expired":       now.Add(-time.Minute),
		"expires in 10 seconds": now.Add(10 * time.Second),
	}
	for name, grantExpires := range cases {
		t.Run(name, func(t *testing.T) {
			// Act
			_, err := EffectiveTTL(now, 15*time.Minute, grantExpires)

			// Assert
			if err != ErrGrantExpired {
				t.Errorf("err = %v, want ErrGrantExpired", err)
			}
		})
	}
}
