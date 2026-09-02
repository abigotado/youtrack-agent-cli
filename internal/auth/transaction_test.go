package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/abigotado/youtrack-agent-cli/internal/profile"
)

type memoryCredentialStore struct {
	values       map[string]Credential
	migrateCalls int
}

func (s *memoryCredentialStore) Exists(_ context.Context, name string) (bool, error) {
	_, ok := s.values[name]
	return ok, nil
}

func (s *memoryCredentialStore) Load(_ context.Context, name string) (Credential, error) {
	value, ok := s.values[name]
	if !ok {
		return Credential{}, ErrNotFound
	}
	return value, nil
}

func (s *memoryCredentialStore) Save(_ context.Context, name string, value Credential) error {
	s.values[name] = value
	return nil
}

func (s *memoryCredentialStore) Delete(_ context.Context, name string) error {
	delete(s.values, name)
	return nil
}

func (s *memoryCredentialStore) MigrateKeychain(context.Context, string) error {
	s.migrateCalls++
	return nil
}

func TestLoginInitialBindingAndReplacementConfirmation(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	intent, err := authTestProfile(t).LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(ctx, intent); err != nil {
		t.Fatal(err)
	}
	store := &memoryCredentialStore{values: map[string]Credential{}}
	credential := Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"}
	if _, err := Login(ctx, store, registry, intent, credential, false); err != nil {
		t.Fatalf("initial binding required confirmation: %v", err)
	}
	rotated, err := registry.Get(ctx, intent.Name)
	if err != nil {
		t.Fatal(err)
	}
	nextIntent, err := rotated.LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Login(ctx, store, registry, nextIntent, credential, false); !errors.Is(err, ErrOverwriteConfirmationRequired) {
		t.Fatalf("replacement error=%v, want confirmation", err)
	}
	if _, err := Login(ctx, store, registry, nextIntent, credential, true); err != nil {
		t.Fatalf("confirmed replacement failed: %v", err)
	}
	if store.migrateCalls != 0 {
		t.Fatalf("ordinary login implicitly migrated Keychain ACL %d times", store.migrateCalls)
	}
}

func TestLoginRejectsProfileTopologyDrift(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	original, err := authTestProfile(t).LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Add(ctx, original); err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.ExpectedLogin = "bob"
	if err := registry.Put(ctx, changed); err != nil {
		t.Fatal(err)
	}
	store := &memoryCredentialStore{values: map[string]Credential{}}
	credential := Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"}
	if _, err := Login(ctx, store, registry, original, credential, true); !errors.Is(err, ErrProfileChangedDuringLogin) {
		t.Fatalf("drift error=%v, want ErrProfileChangedDuringLogin", err)
	}
	if len(store.values) != 0 {
		t.Fatal("credential was stored after topology drift")
	}
}

func TestLoginRejectsProfileDeletedDuringVerification(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry := profile.NewRegistry(filepath.Join(directory, "profiles.json"))
	loginIntent, err := authTestProfile(t).LoginIntent()
	if err != nil {
		t.Fatal(err)
	}
	store := &memoryCredentialStore{values: map[string]Credential{}}
	credential := Credential{Kind: CredentialPermanentToken, PermanentToken: "sentinel"}
	if _, err := Login(ctx, store, registry, loginIntent, credential, true); !errors.Is(err, ErrProfileChangedDuringLogin) {
		t.Fatalf("deleted profile error=%v, want ErrProfileChangedDuringLogin", err)
	}
	if len(store.values) != 0 {
		t.Fatal("credential was stored after profile deletion")
	}
}
