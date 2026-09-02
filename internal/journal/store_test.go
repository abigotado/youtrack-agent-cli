package journal

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/abigotado/youtrack-agent-cli/internal/errx"
	"github.com/abigotado/youtrack-agent-cli/internal/intent"
)

type fixedID string

func (f fixedID) NewPlanID() (string, error) { return string(f), nil }

func journalPlan(t *testing.T) intent.Plan {
	t.Helper()
	plan, err := intent.PrepareWithSource(
		intent.ProfileSnapshot{Name: "work", Instance: "https://acme.youtrack.cloud", RESTBaseURL: "https://acme.youtrack.cloud/api", OAuthIssuerURL: "https://hub.example.test", IdentitySHA256: strings.Repeat("a", 64), CredentialGeneration: "gen-1", Account: intent.AccountBinding{ID: "1-2", Login: "alice"}},
		intent.ProjectPolicy{Project: intent.ProjectBinding{ID: "0-1", Key: "APP"}, PolicyRevision: 1, PolicySHA256: strings.Repeat("b", 64), SchemaSHA256: strings.Repeat("c", 64), ExecutorAssurance: "rest-best-effort", AuthorizedCapability: "issue-update", NotificationPolicy: "youtrack-default", ReconciliationStrategy: "bounded-exact-and-marker"},
		intent.KindIssueUpdate,
		[]byte(`{"issue_id":"APP-1","set":{"summary":"new"}}`),
		[]byte(`{"issue_id":"APP-1","issue_state_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","touched_fields_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"}`),
		fixedID("YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func dispatchedRecord(t *testing.T) Record {
	t.Helper()
	now := time.Now().UTC()
	plan := journalPlan(t)
	return Record{
		Version: recordVersion, Revision: 3, State: StateInFlight, Plan: plan,
		Receipt: &ReceiptBinding{
			ReceiptID: "YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA", Nonce: "YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB",
			PlanSHA256: plan.IntentSHA256, ExpiresAt: now.Add(time.Minute),
			KeyGeneration: "key-1", ReceiptSHA256: strings.Repeat("f", 64),
		},
		MutationAttempts: 1, CreatedAt: now.Add(-time.Minute), UpdatedAt: now,
	}
}

func TestStoreCASReplayAndCrashSemantics(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "journal"))
	store.now = func() time.Time { return now }
	plan := journalPlan(t)

	record, err := store.Create(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != StatePrepared || record.Revision != 1 {
		t.Fatalf("created record = %#v", record)
	}
	info, err := os.Stat(filepath.Join(store.directory, plan.PlanID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("record permissions = %o", info.Mode().Perm())
	}

	receipt := &ReceiptBinding{
		ReceiptID: "YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA", Nonce: "YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB",
		PlanSHA256: plan.IntentSHA256, ExpiresAt: now.Add(5 * time.Minute),
		KeyGeneration: "key-1", ReceiptSHA256: strings.Repeat("f", 64),
	}
	confirmed, err := store.CompareAndSwap(context.Background(), plan.PlanID, 1, Transition{To: StateConfirmed, Receipt: receipt})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CompareAndSwap(context.Background(), plan.PlanID, 1, Transition{To: StateCanceled})
	var typed *errx.Error
	if !errors.As(err, &typed) || typed.Reason != "JOURNAL_REVISION_CONFLICT" {
		t.Fatalf("stale CAS error = %#v", err)
	}
	inFlight, err := store.CompareAndSwap(context.Background(), plan.PlanID, confirmed.Revision, Transition{To: StateInFlight})
	if err != nil {
		t.Fatal(err)
	}
	if !inFlight.NonReplayable() || !inFlight.RequiresReconciliation() || inFlight.MutationAttempts != 1 {
		t.Fatalf("in-flight record = %#v", inFlight)
	}
	recovered, err := store.Get(context.Background(), plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != StateInFlight || !recovered.NonReplayable() {
		t.Fatalf("crash recovery made record replayable: %#v", recovered)
	}
	_, err = store.CompareAndSwap(context.Background(), plan.PlanID, recovered.Revision, Transition{To: StateInFlight})
	if !errors.As(err, &typed) || typed.Reason != "INVALID_JOURNAL_TRANSITION" {
		t.Fatalf("receipt replay error = %#v", err)
	}
}

func TestStoreDistinguishesPreAndPostRenameFailures(t *testing.T) {
	plan := journalPlan(t)
	t.Run("rename failed before commit", func(t *testing.T) {
		store := New(filepath.Join(t.TempDir(), "journal"))
		store.rename = func(string, string) error { return errors.New("rename sentinel") }
		record, err := store.Create(context.Background(), plan)
		if err == nil || WasCommitted(err) || record.Plan.PlanID != plan.PlanID {
			t.Fatalf("record=%#v err=%v committed=%t", record, err, WasCommitted(err))
		}
	})
	t.Run("directory open failed after commit", func(t *testing.T) {
		store := New(filepath.Join(t.TempDir(), "journal"))
		store.openDir = func(string) (*os.File, error) { return nil, errors.New("open directory sentinel") }
		record, err := store.Create(context.Background(), plan)
		if !WasCommitted(err) || record.Plan.PlanID != plan.PlanID {
			t.Fatalf("record=%#v err=%v committed=%t", record, err, WasCommitted(err))
		}
		if _, statErr := os.Stat(filepath.Join(store.directory, plan.PlanID+".json")); statErr != nil {
			t.Fatalf("committed record missing: %v", statErr)
		}
		store.openDir = nil
		if recovered, getErr := store.Get(context.Background(), plan.PlanID); getErr != nil || recovered.Plan.PlanID != plan.PlanID {
			t.Fatalf("recovered=%#v err=%v", recovered, getErr)
		}
	})
	t.Run("directory sync failed after commit", func(t *testing.T) {
		store := New(filepath.Join(t.TempDir(), "journal"))
		store.openDir = func(path string) (*os.File, error) {
			file, err := os.Open(path)
			if err == nil {
				err = file.Close()
			}
			return file, err
		}
		record, err := store.Create(context.Background(), plan)
		if !WasCommitted(err) || record.Plan.PlanID != plan.PlanID {
			t.Fatalf("record=%#v err=%v committed=%t", record, err, WasCommitted(err))
		}
	})
}

func TestGetRejectsMisnamedValidRecord(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	plan := journalPlan(t)
	if _, err := store.Create(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	otherID := "YTAP-BBBBBBBBBBBBBBBBBBBBBBBBBB"
	raw, err := os.ReadFile(filepath.Join(store.directory, plan.PlanID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.directory, otherID+".json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), otherID); err == nil {
		t.Fatal("misnamed journal record was accepted")
	}
}

func TestCompleteStateTable(t *testing.T) {
	allowed := map[State][]State{
		StatePrepared:                   {StateConfirmed, StateCanceled, StateExpired},
		StateConfirmed:                  {StateInFlight, StateCanceled, StateExpired},
		StateInFlight:                   {StateFailedBeforeMutation, StateApplied, StateAmbiguous},
		StateApplied:                    {StateReconciled, StateOperatorResolutionRequired},
		StateAmbiguous:                  {StateReconciled, StateResolvedNotApplied, StateOperatorResolutionRequired},
		StateOperatorResolutionRequired: {StateResolvedApplied, StateResolvedNotApplied},
	}
	all := []State{StatePrepared, StateConfirmed, StateCanceled, StateExpired, StateInFlight, StateFailedBeforeMutation, StateApplied, StateAmbiguous, StateReconciled, StateOperatorResolutionRequired, StateResolvedApplied, StateResolvedNotApplied}
	for _, from := range all {
		for _, to := range all {
			want := false
			for _, candidate := range allowed[from] {
				if candidate == to {
					want = true
				}
			}
			if got := allowedTransition(from, to); got != want {
				t.Fatalf("%s -> %s = %v, want %v", from, to, got, want)
			}
		}
	}
}

func TestResolvedFlowRequiresBoundedEvidence(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "journal"))
	store.now = func() time.Time { return now }
	plan := journalPlan(t)
	record, err := store.Create(context.Background(), plan)
	if err != nil {
		t.Fatal(err)
	}
	receipt := &ReceiptBinding{ReceiptID: "YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA", Nonce: "YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB", PlanSHA256: plan.IntentSHA256, ExpiresAt: now.Add(time.Minute), KeyGeneration: "key-1", ReceiptSHA256: strings.Repeat("f", 64)}
	record, err = store.CompareAndSwap(context.Background(), plan.PlanID, record.Revision, Transition{To: StateConfirmed, Receipt: receipt})
	if err != nil {
		t.Fatal(err)
	}
	record, err = store.CompareAndSwap(context.Background(), plan.PlanID, record.Revision, Transition{To: StateInFlight})
	if err != nil {
		t.Fatal(err)
	}
	record, err = store.CompareAndSwap(context.Background(), plan.PlanID, record.Revision, Transition{To: StateAmbiguous, Outcome: &Outcome{Code: string(StateAmbiguous)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompareAndSwap(context.Background(), plan.PlanID, record.Revision, Transition{To: StateOperatorResolutionRequired}); err == nil {
		t.Fatal("transition without evidence succeeded")
	}
	evidence := &Evidence{SHA256: strings.Repeat("1", 64), Summary: "bounded evidence was non-unique", CollectedAt: now}
	record, err = store.CompareAndSwap(context.Background(), plan.PlanID, record.Revision, Transition{To: StateOperatorResolutionRequired, Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	resolution := &Evidence{SHA256: strings.Repeat("2", 64), Summary: "operator reviewed exact issue", CollectedAt: now}
	record, err = store.CompareAndSwap(context.Background(), plan.PlanID, record.Revision, Transition{To: StateResolvedApplied, Evidence: resolution})
	if err != nil {
		t.Fatal(err)
	}
	if record.State != StateResolvedApplied || len(record.Evidence) != 2 {
		t.Fatalf("resolved record = %#v", record)
	}
}

func TestDispatchOutcomeMustMatchStateAndShape(t *testing.T) {
	tests := []struct {
		name    string
		state   State
		outcome Outcome
	}{
		{"empty", StateAmbiguous, Outcome{}},
		{"wrong code", StateApplied, Outcome{Code: string(StateAmbiguous)}},
		{"applied missing remote id", StateApplied, Outcome{Code: string(StateApplied)}},
		{"ambiguous claims remote id", StateAmbiguous, Outcome{Code: string(StateAmbiguous), RemoteID: "APP-2"}},
		{"malformed evidence digest", StateFailedBeforeMutation, Outcome{Code: string(StateFailedBeforeMutation), EvidenceSHA256: "bad"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			current := dispatchedRecord(t)
			if _, err := applyTransition(current, Transition{To: test.state, Outcome: &test.outcome}, time.Now().UTC()); err == nil {
				t.Fatalf("accepted outcome=%#v for state=%s", test.outcome, test.state)
			}
		})
	}
}

func TestGetRejectsImpossibleDurableDispatchRecords(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "journal"))
	if err := store.ensureDirectory(); err != nil {
		t.Fatal(err)
	}
	evidence := Evidence{SHA256: strings.Repeat("a", 64), Summary: "bounded", CollectedAt: time.Now().UTC()}
	tests := []struct {
		name   string
		mutate func(*Record)
	}{
		{"applied without remote ID", func(record *Record) {
			record.State = StateApplied
			record.Outcome = &Outcome{Code: string(StateApplied)}
		}},
		{"in flight with evidence", func(record *Record) { record.Evidence = []Evidence{evidence} }},
		{"dispatch state with premature evidence", func(record *Record) {
			record.State = StateAmbiguous
			record.Outcome = &Outcome{Code: string(StateAmbiguous)}
			record.Evidence = []Evidence{evidence}
		}},
		{"resolved after failed-before-mutation", func(record *Record) {
			record.State = StateReconciled
			record.Outcome = &Outcome{Code: string(StateFailedBeforeMutation)}
			record.Evidence = []Evidence{evidence}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := dispatchedRecord(t)
			test.mutate(&record)
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.directory, record.Plan.PlanID+".json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Get(context.Background(), record.Plan.PlanID); err == nil {
				t.Fatalf("journal accepted impossible record: %#v", record)
			}
		})
	}
}
