package secrets

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ---------- Mock / Stub-об'єкти (жодної бази й мережі) ----------

type stubGrants struct {
	grant *AccessGrant
	err   error
}

func (s *stubGrants) FindGrant(context.Context, string, string) (*AccessGrant, error) {
	return s.grant, s.err
}

// mockProvider підміняє зовнішнє сховище (Vault/AWS/GCP) і рахує виклики.
type mockProvider struct {
	calls   int
	gotPath string
	value   []byte
	err     error
}

func (m *mockProvider) FetchSecret(_ context.Context, path string) ([]byte, error) {
	m.calls++
	m.gotPath = path
	return m.value, m.err
}

// mockAudit підміняє журнал аудиту і запам'ятовує події.
type mockAudit struct {
	calls  int
	events []AuditEvent
}

func (m *mockAudit) Record(_ context.Context, e AuditEvent) error {
	m.calls++
	m.events = append(m.events, e)
	return nil
}

// verifyCalls — аналог Verify(..., Times.Once) / mock.AssertNumberOfCalls.
func verifyCalls(t *testing.T, name string, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("%s викликано %d раз(и), очікувалось %d", name, got, want)
	}
}

func newService(grants GrantRepository, p SecretProvider, a AuditLogger) *Service {
	return &Service{
		Grants:   grants,
		Provider: p,
		Audit:    a,
		Policy:   Policy{MaxTTL: time.Hour, RotateBefore: 2 * time.Minute},
		Now:      func() time.Time { return fixedNow },
		NewID:    func() string { return "tok-1" },
	}
}

func newGrant(status GrantStatus) *AccessGrant {
	return &AccessGrant{
		ID: "g-1", ServiceAccountID: "sa-1", SourceID: "src-1",
		Status: status, ExpiresAt: fixedNow.Add(time.Hour),
	}
}

func validRequest() TokenRequest {
	return TokenRequest{
		ServiceAccountID: "sa-1", SourceID: "src-1",
		SecretPath: "prod/db/password", TTL: 15 * time.Minute,
	}
}

// ---------- Тести за патерном AAA ----------

func TestIssueToken_Success_FetchesSecretOnceAndAudits(t *testing.T) {
	// Arrange
	grants := &stubGrants{grant: newGrant(GrantActive)}
	provider := &mockProvider{value: []byte("s3cr3t")}
	audit := &mockAudit{}
	svc := newService(grants, provider, audit)

	// Act
	got, err := svc.IssueToken(context.Background(), validRequest())

	// Assert
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got.Value) != "s3cr3t" {
		t.Errorf("Value = %q, want %q", got.Value, "s3cr3t")
	}
	if want := fixedNow.Add(15 * time.Minute); !got.Token.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", got.Token.ExpiresAt, want)
	}
	verifyCalls(t, "Provider.FetchSecret", provider.calls, 1) // Verify: рівно 1 раз
	verifyCalls(t, "Audit.Record", audit.calls, 1)            // Verify: рівно 1 раз
	if provider.gotPath != "prod/db/password" {
		t.Errorf("provider path = %q, want %q", provider.gotPath, "prod/db/password")
	}
	if audit.events[0].Result != "success" {
		t.Errorf("audit result = %q, want success", audit.events[0].Result)
	}
}

func TestIssueToken_RevokedGrant_DeniedAndProviderNeverCalled(t *testing.T) {
	// Arrange
	grants := &stubGrants{grant: newGrant(GrantRevoked)}
	provider := &mockProvider{value: []byte("s3cr3t")}
	audit := &mockAudit{}
	svc := newService(grants, provider, audit)

	// Act
	_, err := svc.IssueToken(context.Background(), validRequest())

	// Assert
	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("err = %v, want ErrAccessDenied", err)
	}
	verifyCalls(t, "Provider.FetchSecret", provider.calls, 0) // секрет не запитувався
	verifyCalls(t, "Audit.Record", audit.calls, 1)            // відмову зафіксовано рівно 1 раз
	if audit.events[0].Result != "denied" {
		t.Errorf("audit result = %q, want denied", audit.events[0].Result)
	}
}

func TestIssueToken_ProviderFailure_ReturnsErrorAndAuditsOnce(t *testing.T) {
	// Arrange
	errBoom := errors.New("vault unavailable")
	grants := &stubGrants{grant: newGrant(GrantActive)}
	provider := &mockProvider{err: errBoom}
	audit := &mockAudit{}
	svc := newService(grants, provider, audit)

	// Act
	_, err := svc.IssueToken(context.Background(), validRequest())

	// Assert
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want wrapped %v", err, errBoom)
	}
	verifyCalls(t, "Provider.FetchSecret", provider.calls, 1)
	verifyCalls(t, "Audit.Record", audit.calls, 1)
	if audit.events[0].Result != "error" {
		t.Errorf("audit result = %q, want error", audit.events[0].Result)
	}
}
