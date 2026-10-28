package secrets

import "time"

// MinTokenTTL — мінімальний залишок дії доступу, за якого ще має сенс видавати токен.
const MinTokenTTL = 30 * time.Second

// EffectiveTTL повертає TTL токена: запитаний TTL, але не довший за залишок
// дії AccessGrant. Якщо доступ вичерпано (залишок менший за MinTokenTTL) —
// повертає ErrGrantExpired.
func EffectiveTTL(now time.Time, requested time.Duration, grantExpiresAt time.Time) (time.Duration, error) {
	remaining := grantExpiresAt.Sub(now)
	if remaining < MinTokenTTL {
		return 0, ErrGrantExpired
	}
	return min(requested, remaining), nil
}
