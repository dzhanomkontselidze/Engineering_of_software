package secrets

import (
	"context"
	"fmt"
	"time"
)

// Service реалізує операцію «видати ephemeral-токен».
type Service struct {
	Grants   GrantRepository
	Provider SecretProvider
	Audit    AuditLogger
	Policy   Policy
	Now      func() time.Time
	NewID    func() string
}

// IssueToken — критична бізнес-операція: перевіряє доступ і TTL, отримує секрет
// від провайдера та рівно один раз записує подію аудиту.
func (s *Service) IssueToken(ctx context.Context, req TokenRequest) (IssuedSecret, error) {
	now := s.Now()

	event := AuditEvent{
		Time:             now,
		ServiceAccountID: req.ServiceAccountID,
		SourceID:         req.SourceID,
		Action:           "issue",
	}
	fail := func(result string, err error) (IssuedSecret, error) {
		event.Result = result
		_ = s.Audit.Record(ctx, event)
		return IssuedSecret{}, err
	}

	if err := ValidateSecretPath(req.SecretPath); err != nil {
		return fail("denied", err)
	}
	if err := ValidateTTL(req.TTL, s.Policy.MaxTTL); err != nil {
		return fail("denied", err)
	}

	grant, err := s.Grants.FindGrant(ctx, req.ServiceAccountID, req.SourceID)
	if err != nil {
		return fail("error", fmt.Errorf("find grant: %w", err))
	}
	if err := CheckAccess(grant, req.ServiceAccountID, req.SourceID, now); err != nil {
		return fail("denied", err)
	}

	ttl, err := EffectiveTTL(now, req.TTL, grant.ExpiresAt)
	if err != nil {
		return fail("denied", err)
	}

	value, err := s.Provider.FetchSecret(ctx, req.SecretPath)
	if err != nil {
		return fail("error", fmt.Errorf("fetch secret: %w", err))
	}

	event.Result = "success"
	if err := s.Audit.Record(ctx, event); err != nil {
		return IssuedSecret{}, fmt.Errorf("audit: %w", err)
	}
	return IssuedSecret{
		Token: Token{ID: s.NewID(), GrantID: grant.ID, IssuedAt: now, ExpiresAt: now.Add(ttl)},
		Value: value,
	}, nil
}
