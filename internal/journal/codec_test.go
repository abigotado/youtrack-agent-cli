package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var codecTime = time.Date(2026, 9, 28, 15, 0, 0, 0, time.UTC)

// Captured from the shipped v1 MarshalIndent-plus-LF writer. This is deliberately
// independent of Record, Plan, their JSON tags, and journalPlan's constructor.
const historicalV1Prepared = `{
  "version": 1,
  "revision": 1,
  "state": "prepared",
  "plan": {
    "schema_version": 1,
    "plan_id": "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA",
    "kind": "issue.update",
    "profile": {
      "name": "work",
      "instance": "https://acme.youtrack.cloud",
      "rest_base_url": "https://acme.youtrack.cloud/api",
      "oauth_issuer_url": "https://hub.example.test",
      "identity_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "credential_generation": "gen-1",
      "account": {
        "id": "1-2",
        "login": "alice"
      }
    },
    "policy": {
      "project": {
        "id": "0-1",
        "key": "APP"
      },
      "policy_revision": 1,
      "policy_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "schema_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "executor_assurance": "rest-best-effort",
      "authorized_capability": "issue-update",
      "notification_policy": "youtrack-default",
      "reconciliation_strategy": "bounded-exact-and-marker"
    },
    "operation": {
      "issue_update": {
        "request": {
          "issue_id": "APP-1",
          "set": {
            "summary": "new"
          }
        },
        "expected": {
          "issue_id": "APP-1",
          "issue_state_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          "touched_fields_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }
      }
    },
    "request_sha256": "9b4a6652ef2500c4d1e59669cadf6dcc8dc2e77224684cd7433c8d49d844955b",
    "expected_sha256": "f17747d18c996141cb33aeba203a6635cffa8bd4fb178e14fb592af283ff77c9",
    "intent_sha256": "56635c16b12d2b5b4849a76fa936fc8f04550509c9afc4afa1fbd06a568da341"
  },
  "mutation_attempts": 0,
  "created_at": "2026-09-28T15:00:00Z",
  "updated_at": "2026-09-28T15:00:00Z"
}
`

const historicalV1PreparedSHA256 = "04ed555a3d69ee327afc1d1c645e8e11d062091f300d71ed4a978466810a9743"

func legacyCodecRecord(t *testing.T, state State) Record {
	t.Helper()
	plan := journalPlan(t)
	record := Record{
		Version: recordVersion, Revision: 1, State: state, Plan: plan,
		CreatedAt: codecTime, UpdatedAt: codecTime,
	}
	receipt := &ReceiptBinding{
		ReceiptID:     "YTAR-AAAAAAAAAAAAAAAAAAAAAAAAAA",
		Nonce:         "YTAN-BBBBBBBBBBBBBBBBBBBBBBBBBB",
		PlanSHA256:    plan.IntentSHA256,
		ExpiresAt:     codecTime.Add(time.Minute),
		KeyGeneration: "key-1",
		ReceiptSHA256: strings.Repeat("f", 64),
	}
	switch state {
	case StatePrepared, StateCanceled, StateExpired:
	case StateConfirmed:
		record.Receipt = receipt
	case StateInFlight:
		record.Receipt = receipt
		record.MutationAttempts = 1
	case StateFailedBeforeMutation, StateApplied, StateAmbiguous,
		StateReconciled, StateOperatorResolutionRequired, StateResolvedApplied, StateResolvedNotApplied:
		record.Receipt = receipt
		record.MutationAttempts = 1
		code := string(state)
		if state == StateReconciled || state == StateOperatorResolutionRequired ||
			state == StateResolvedApplied || state == StateResolvedNotApplied {
			code = string(StateApplied)
			record.Evidence = []Evidence{{
				SHA256: strings.Repeat("e", 64), Summary: "bounded readback", CollectedAt: codecTime,
			}}
		}
		record.Outcome = &Outcome{Code: code}
		if code == string(StateApplied) {
			record.Outcome.RemoteID = "APP-1"
		}
	default:
		t.Fatalf("unsupported test state %q", state)
	}
	if err := validateRecord(record); err != nil {
		t.Fatalf("test fixture for %s is invalid: %v", state, err)
	}
	return record
}

func legacyCodecBytes(t *testing.T, record Record) []byte {
	t.Helper()
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func codecReplaceOnce(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	if count := bytes.Count(raw, []byte(old)); count != 1 {
		t.Fatalf("probe %q occurs %d times, want exactly one", old, count)
	}
	return bytes.Replace(raw, []byte(old), []byte(replacement), 1)
}

func codecRemoveTopLevelField(t *testing.T, raw []byte, name string) []byte {
	t.Helper()
	start := bytes.Index(raw, []byte(`  "`+name+`":`))
	if start < 0 {
		t.Fatalf("fixture missing top-level field %s", name)
	}
	next := bytes.Index(raw[start+1:], []byte("\n  \""))
	var result []byte
	if next >= 0 {
		// Keep the next member's indentation and the previous member's LF.
		result = append(append([]byte(nil), raw[:start]...), raw[start+1+next+1:]...)
	} else {
		// Last member: remove the preceding comma as well.
		if start < 2 || raw[start-2] != ',' {
			t.Fatalf("last member %s has no preceding comma", name)
		}
		result = append(append([]byte(nil), raw[:start-2]...), raw[len(raw)-2:]...)
	}
	if !json.Valid(result) {
		t.Fatalf("removing %s did not preserve valid JSON", name)
	}
	return result
}

func codecDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func TestClassifyLegacyV1EveryValidState(t *testing.T) {
	states := []State{
		StatePrepared, StateConfirmed, StateCanceled, StateExpired, StateInFlight,
		StateFailedBeforeMutation, StateApplied, StateAmbiguous, StateReconciled,
		StateOperatorResolutionRequired, StateResolvedApplied, StateResolvedNotApplied,
	}
	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			record := legacyCodecRecord(t, state)
			raw := legacyCodecBytes(t, record)
			classified, err := ClassifyLegacyV1(raw)
			if err != nil {
				t.Fatal(err)
			}
			want := LegacyV1Quarantine
			if state == StatePrepared {
				want = LegacyV1Migratable
			}
			if classified.Disposition != want || classified.SHA256 != codecDigest(raw) ||
				classified.Record.State != state || classified.Record.Plan.IntentSHA256 != record.Plan.IntentSHA256 {
				t.Fatalf("classification of %s = %#v, want disposition %q and exact source digest", state, classified, want)
			}
		})
	}
}

func TestClassifyLegacyV1FrozenHistoricalPrepared(t *testing.T) {
	raw := []byte(historicalV1Prepared)
	if got := codecDigest(raw); got != historicalV1PreparedSHA256 {
		t.Fatalf("historical v1 fixture changed: digest %s", got)
	}
	classified, err := ClassifyLegacyV1(raw)
	if err != nil {
		t.Fatalf("shipped v1 prepared record no longer recognized: %v", err)
	}
	if classified.Disposition != LegacyV1Migratable || classified.SHA256 != historicalV1PreparedSHA256 ||
		classified.Record.State != StatePrepared || classified.Record.Plan.PlanID != "YTAP-AAAAAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("historical v1 classification changed: %#v", classified)
	}
}

func TestClassifyLegacyV1RequiresPristinePrepared(t *testing.T) {
	base := legacyCodecRecord(t, StatePrepared)
	for name, mutate := range map[string]func(*Record){
		"revision greater than one": func(r *Record) { r.Revision = 2 },
		"unequal timestamps":        func(r *Record) { r.UpdatedAt = r.CreatedAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			record := base
			mutate(&record)
			raw := legacyCodecBytes(t, record)
			classified, err := ClassifyLegacyV1(raw)
			if err != nil || classified.Disposition != LegacyV1Quarantine || classified.SHA256 != codecDigest(raw) {
				t.Fatalf("non-pristine valid prepared state = %#v, %v", classified, err)
			}
		})
	}
	t.Run("same instant different timestamp spelling", func(t *testing.T) {
		raw := legacyCodecBytes(t, base)
		changed := codecReplaceOnce(t, raw, `"updated_at": "2026-09-28T15:00:00Z"`, `"updated_at": "2026-09-28T12:00:00-03:00"`)
		classified, err := ClassifyLegacyV1(changed)
		if err != nil || classified.Disposition != LegacyV1Quarantine {
			t.Fatalf("same instant with altered historical timestamp bytes = %#v, %v", classified, err)
		}
	})
	invalid := map[string]func(*Record){
		"revision zero":    func(r *Record) { r.Revision = 0 },
		"receipt":          func(r *Record) { r.Receipt = legacyCodecRecord(t, StateConfirmed).Receipt },
		"mutation attempt": func(r *Record) { r.MutationAttempts = 1 },
		"outcome":          func(r *Record) { r.Outcome = &Outcome{Code: string(StateApplied), RemoteID: "APP-1"} },
		"evidence": func(r *Record) {
			r.Evidence = []Evidence{{SHA256: strings.Repeat("e", 64), Summary: "readback", CollectedAt: codecTime}}
		},
		"invalid plan":       func(r *Record) { r.Plan.IntentSHA256 = strings.Repeat("0", 64) },
		"backward timestamp": func(r *Record) { r.UpdatedAt = r.CreatedAt.Add(-time.Second) },
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			record := base
			mutate(&record)
			if classified, err := ClassifyLegacyV1(legacyCodecBytes(t, record)); err == nil {
				t.Fatalf("invalid prepared record classified as %#v", classified)
			}
		})
	}
}

func TestClassifyLegacyV1RejectsNoncanonicalInput(t *testing.T) {
	raw := legacyCodecBytes(t, legacyCodecRecord(t, StatePrepared))
	plan := journalPlan(t)
	invalid := map[string][]byte{
		"empty":                  nil,
		"oversize before decode": bytes.Repeat([]byte{'x'}, maxLegacyV1Bytes+1),
		"BOM":                    append([]byte{0xef, 0xbb, 0xbf}, raw...),
		"invalid UTF8":           append([]byte{0xff}, raw...),
		"trailing JSON":          append(append([]byte(nil), raw...), []byte(`{}`)...),
		"missing LF":             bytes.TrimSuffix(raw, []byte{'\n'}),
		"leading whitespace":     append([]byte{' '}, raw...),
		"duplicate version":      codecReplaceOnce(t, raw, `"version": 1,`, "\"version\": 1,\n  \"version\": 1,"),
		"unknown field":          codecReplaceOnce(t, raw, `"version": 1,`, "\"version\": 1,\n  \"extra\": null,"),
		"reordered fields":       codecReplaceOnce(t, raw, "  \"version\": 1,\n  \"revision\": 1,", "  \"revision\": 1,\n  \"version\": 1,"),
		"wrong version":          codecReplaceOnce(t, raw, `"version": 1`, `"version": 2`),
		"wrong revision type":    codecReplaceOnce(t, raw, `"revision": 1`, `"revision": "1"`),
		"wrong plan":             codecReplaceOnce(t, raw, `"plan_id": "`+plan.PlanID+`"`, `"plan_id": "YTAP-BBBBBBBBBBBBBBBBBBBBBBBBBB"`),
	}
	for name, candidate := range invalid {
		t.Run(name, func(t *testing.T) {
			if classified, err := ClassifyLegacyV1(candidate); err == nil {
				t.Fatalf("accepted invalid v1 candidate: %#v", classified)
			}
		})
	}
}

func TestPreparedV2ExactFreshAndMigratedBytes(t *testing.T) {
	plan := journalPlan(t)
	planJSON, err := json.MarshalIndent(plan, "  ", "  ")
	if err != nil {
		t.Fatal(err)
	}
	created := "2026-09-28T15:00:00Z"
	updated := "2026-09-28T15:00:01Z"
	legacyDigest := historicalV1PreparedSHA256
	for _, tc := range []struct {
		name       string
		value      PreparedV2Record
		revision   string
		legacyJSON string
		updated    string
		sha256     string
	}{
		{"fresh", PreparedV2Record{Revision: 1, Plan: plan, CreatedAt: codecTime, UpdatedAt: codecTime}, "1", "null", created, "b514318862f94724403a9a99355fb84edf5916145cb2a3da0d2f33e3d3d6037b"},
		{"migrated", PreparedV2Record{Revision: 2, Plan: plan, LegacyV1RecordSHA256: &legacyDigest, CreatedAt: codecTime, UpdatedAt: codecTime.Add(time.Second)}, "2", `"` + legacyDigest + `"`, updated, "73db6b04881a1822b145d0b41f38fe4a0418bf912cae292e1478b55bfd959a16"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := EncodePreparedV2(tc.value)
			if err != nil {
				t.Fatal(err)
			}
			want := "{\n" +
				"  \"version\": 2,\n" +
				"  \"revision\": " + tc.revision + ",\n" +
				"  \"state\": \"prepared\",\n" +
				"  \"plan\": " + string(planJSON) + ",\n" +
				"  \"receipt\": null,\n" +
				"  \"authority_evidence\": null,\n" +
				"  \"coordinator_evidence\": null,\n" +
				"  \"mutation_attempts\": 0,\n" +
				"  \"outcome\": null,\n" +
				"  \"evidence\": null,\n" +
				"  \"legacy_v1_record_sha256\": " + tc.legacyJSON + ",\n" +
				"  \"created_at\": \"" + created + "\",\n" +
				"  \"updated_at\": \"" + tc.updated + "\"\n" +
				"}\n"
			if string(raw) != want {
				t.Fatalf("v2 %s canonical bytes differ\nwant:\n%s\ngot:\n%s", tc.name, want, raw)
			}
			if got := codecDigest(raw); got != tc.sha256 {
				t.Fatalf("v2 %s digest = %s, want %s", tc.name, got, tc.sha256)
			}
			decoded, err := DecodePreparedV2(raw)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Revision != tc.value.Revision || decoded.Plan.IntentSHA256 != plan.IntentSHA256 ||
				(decoded.LegacyV1RecordSHA256 == nil) != (tc.value.LegacyV1RecordSHA256 == nil) {
				t.Fatalf("decoded v2 %s changed bindings: %#v", tc.name, decoded)
			}
			if tc.value.LegacyV1RecordSHA256 != nil && *decoded.LegacyV1RecordSHA256 != legacyDigest {
				t.Fatalf("decoded migrated source digest = %q", *decoded.LegacyV1RecordSHA256)
			}
			if encodedAgain, err := EncodePreparedV2(decoded); err != nil || !bytes.Equal(encodedAgain, raw) {
				t.Fatalf("v2 %s round trip changed bytes: %v", tc.name, err)
			}
		})
	}
}

func TestPreparedV2RejectsNoncanonicalOrUnsafeInput(t *testing.T) {
	plan := journalPlan(t)
	raw, err := EncodePreparedV2(PreparedV2Record{Revision: 1, Plan: plan, CreatedAt: codecTime, UpdatedAt: codecTime})
	if err != nil {
		t.Fatal(err)
	}
	invalid := map[string][]byte{
		"empty":                    nil,
		"oversize before decode":   bytes.Repeat([]byte{'x'}, maxPreparedV2Bytes+1),
		"BOM":                      append([]byte{0xef, 0xbb, 0xbf}, raw...),
		"invalid UTF8":             append([]byte{0xff}, raw...),
		"trailing JSON":            append(append([]byte(nil), raw...), []byte(`{}`)...),
		"leading whitespace":       append([]byte{' '}, raw...),
		"missing LF":               bytes.TrimSuffix(raw, []byte{'\n'}),
		"duplicate field":          codecReplaceOnce(t, raw, `"version": 2,`, "\"version\": 2,\n  \"version\": 2,"),
		"unknown field":            codecReplaceOnce(t, raw, `"version": 2,`, "\"version\": 2,\n  \"unknown\": null,"),
		"reordered fields":         codecReplaceOnce(t, raw, "  \"version\": 2,\n  \"revision\": 1,", "  \"revision\": 1,\n  \"version\": 2,"),
		"wrong version":            codecReplaceOnce(t, raw, `"version": 2`, `"version": 1`),
		"wrong version type":       codecReplaceOnce(t, raw, `"version": 2`, `"version": "2"`),
		"wrong revision":           codecReplaceOnce(t, raw, `"revision": 1`, `"revision": 2`),
		"wrong revision type":      codecReplaceOnce(t, raw, `"revision": 1`, `"revision": "1"`),
		"wrong state":              codecReplaceOnce(t, raw, `"state": "prepared"`, `"state": "confirmed"`),
		"wrong receipt null":       codecReplaceOnce(t, raw, `"receipt": null`, `"receipt": {}`),
		"wrong authority null":     codecReplaceOnce(t, raw, `"authority_evidence": null`, `"authority_evidence": {}`),
		"wrong coordinator null":   codecReplaceOnce(t, raw, `"coordinator_evidence": null`, `"coordinator_evidence": {}`),
		"wrong attempts":           codecReplaceOnce(t, raw, `"mutation_attempts": 0`, `"mutation_attempts": 1`),
		"wrong outcome null":       codecReplaceOnce(t, raw, `"outcome": null`, `"outcome": {}`),
		"wrong evidence null":      codecReplaceOnce(t, raw, `"evidence": null`, `"evidence": []`),
		"wrong source digest type": codecReplaceOnce(t, raw, `"legacy_v1_record_sha256": null`, `"legacy_v1_record_sha256": true`),
		"wrong timestamp":          codecReplaceOnce(t, raw, `"updated_at": "2026-09-28T15:00:00Z"`, `"updated_at": "2026-09-28T14:59:59Z"`),
		"wrong timestamp type":     codecReplaceOnce(t, raw, `"updated_at": "2026-09-28T15:00:00Z"`, `"updated_at": null`),
		"wrong plan":               codecReplaceOnce(t, raw, `"plan_id": "`+plan.PlanID+`"`, `"plan_id": "YTAP-BBBBBBBBBBBBBBBBBBBBBBBBBB"`),
	}
	planStart := bytes.Index(raw, []byte(`  "plan": {`))
	receiptStart := bytes.Index(raw, []byte(`  "receipt":`))
	if planStart < 0 || receiptStart <= planStart {
		t.Fatal("v2 fixture has no bounded plan field")
	}
	invalid["null plan"] = append(append([]byte(nil), raw[:planStart]...), append([]byte("  \"plan\": null,\n"), raw[receiptStart:]...)...)
	if !json.Valid(invalid["null plan"]) {
		t.Fatal("null-plan probe must remain valid JSON")
	}
	for name, candidate := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePreparedV2(candidate); err == nil {
				t.Fatalf("accepted unsafe v2 candidate (%d bytes)", len(candidate))
			}
		})
	}
	for _, name := range []string{"version", "revision", "state", "plan", "receipt", "authority_evidence", "coordinator_evidence", "mutation_attempts", "outcome", "evidence", "legacy_v1_record_sha256", "created_at", "updated_at"} {
		t.Run("missing "+name, func(t *testing.T) {
			candidate := codecRemoveTopLevelField(t, raw, name)
			if _, err := DecodePreparedV2(candidate); err == nil {
				t.Fatalf("accepted v2 without %s", name)
			}
		})
	}
}

func TestQuarantineMarkerExactBytesAndStrictDecode(t *testing.T) {
	rawV1 := legacyCodecBytes(t, legacyCodecRecord(t, StateConfirmed))
	digest := codecDigest(rawV1)
	marker := QuarantineMarker{RecordSHA256: digest, State: StateConfirmed, DetectedAt: codecTime}
	raw, err := EncodeQuarantineMarker(marker)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n" +
		"  \"schema_version\": 1,\n" +
		"  \"record_sha256\": \"" + digest + "\",\n" +
		"  \"state\": \"confirmed\",\n" +
		"  \"reason\": \"unsafe_v1_authority_state\",\n" +
		"  \"detected_at\": \"2026-09-28T15:00:00Z\"\n" +
		"}\n"
	if string(raw) != want {
		t.Fatalf("quarantine marker bytes differ\nwant:\n%s\ngot:\n%s", want, raw)
	}
	if got := codecDigest(raw); got != "1864ce1f3ff1e2720ed03b33228782b2c6c5539cc7ca6a1f799ad256ed60f101" {
		t.Fatalf("marker digest = %s", got)
	}
	decoded, err := DecodeQuarantineMarker(raw)
	if err != nil || decoded != marker {
		t.Fatalf("marker round trip = %#v, %v", decoded, err)
	}
	preparedMarker := QuarantineMarker{RecordSHA256: digest, State: StatePrepared, DetectedAt: codecTime}
	preparedRaw, err := EncodeQuarantineMarker(preparedMarker)
	if err != nil {
		t.Fatalf("non-pristine prepared v1 must permit a quarantine marker: %v", err)
	}
	preparedDecoded, err := DecodeQuarantineMarker(preparedRaw)
	if err != nil || preparedDecoded != preparedMarker {
		t.Fatalf("prepared quarantine marker round trip = %#v, %v", preparedDecoded, err)
	}
	invalid := map[string][]byte{
		"missing digest":  codecReplaceOnce(t, raw, "  \"record_sha256\": \""+digest+"\",\n", ""),
		"duplicate state": codecReplaceOnce(t, raw, `"state": "confirmed",`, "\"state\": \"confirmed\",\n  \"state\": \"confirmed\","),
		"unknown":         codecReplaceOnce(t, raw, `"state": "confirmed",`, "\"state\": \"confirmed\",\n  \"extra\": 1,"),
		"wrong version":   codecReplaceOnce(t, raw, `"schema_version": 1`, `"schema_version": 2`),
		"wrong reason":    codecReplaceOnce(t, raw, `"reason": "unsafe_v1_authority_state"`, `"reason": "safe"`),
		"wrong state":     codecReplaceOnce(t, raw, `"state": "confirmed"`, `"state": "bogus"`),
		"wrong digest":    codecReplaceOnce(t, raw, `"record_sha256": "`+digest+`"`, `"record_sha256": "nope"`),
		"wrong timestamp": codecReplaceOnce(t, raw, `"detected_at": "2026-09-28T15:00:00Z"`, `"detected_at": null`),
		"BOM":             append([]byte{0xef, 0xbb, 0xbf}, raw...),
		"trailing":        append(append([]byte(nil), raw...), []byte(`{}`)...),
		"oversize":        bytes.Repeat([]byte{'x'}, maxQuarantineBytes+1),
	}
	for name, candidate := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeQuarantineMarker(candidate); err == nil {
				t.Fatal("accepted invalid quarantine marker")
			}
		})
	}
}

func TestJournalCodecRedactsDecoderDiagnostic(t *testing.T) {
	plan := journalPlan(t)
	v2, err := EncodePreparedV2(PreparedV2Record{Revision: 1, Plan: plan, CreatedAt: codecTime, UpdatedAt: codecTime})
	if err != nil {
		t.Fatal(err)
	}
	v1 := legacyCodecBytes(t, legacyCodecRecord(t, StatePrepared))
	marker, err := EncodeQuarantineMarker(QuarantineMarker{RecordSHA256: codecDigest(v1), State: StateConfirmed, DetectedAt: codecTime})
	if err != nil {
		t.Fatal(err)
	}
	const sentinel = "987654321098765432109876543210987654321"
	for _, tc := range []struct {
		name        string
		raw         []byte
		old         string
		replacement string
		parse       func([]byte) error
	}{
		{"legacy", v1, `"revision": 1`, `"revision": ` + sentinel, func(raw []byte) error { _, err := ClassifyLegacyV1(raw); return err }},
		{"v2", v2, `"revision": 1`, `"revision": ` + sentinel, func(raw []byte) error { _, err := DecodePreparedV2(raw); return err }},
		{"marker", marker, `"schema_version": 1`, `"schema_version": ` + sentinel, func(raw []byte) error { _, err := DecodeQuarantineMarker(raw); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := codecReplaceOnce(t, tc.raw, tc.old, tc.replacement)
			if !json.Valid(raw) {
				t.Fatal("redaction probe must remain valid JSON")
			}
			var control struct {
				Revision int `json:"revision"`
				Version  int `json:"schema_version"`
			}
			controlErr := json.Unmarshal(raw, &control)
			var decoderErr *json.UnmarshalTypeError
			if !errors.As(controlErr, &decoderErr) || !strings.Contains(controlErr.Error(), sentinel) {
				t.Fatal("probe did not reach an echoing Go JSON decoder error")
			}
			err := tc.parse(raw)
			if err == nil || strings.Contains(err.Error(), sentinel) || errors.As(err, &decoderErr) {
				t.Fatalf("codec leaked untrusted decoder input: %v", err)
			}
		})
	}
}

func TestPreparedV2AcceptsLargeLegalPlan(t *testing.T) {
	plan := largeJournalPlan(t)
	raw, err := EncodePreparedV2(PreparedV2Record{Revision: 1, Plan: plan, CreatedAt: codecTime, UpdatedAt: codecTime})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 256<<10 || len(raw) > maxPreparedV2Bytes {
		t.Fatalf("large legal v2 record size = %d", len(raw))
	}
	if _, err := DecodePreparedV2(raw); err != nil {
		t.Fatalf("large legal v2 record rejected: %v", err)
	}
}

func TestJournalCodecDistinctPredecodeCaps(t *testing.T) {
	if maxQuarantineBytes >= maxPreparedV2Bytes || maxPreparedV2Bytes >= maxLegacyV1Bytes {
		t.Fatalf("codec caps must be distinct and ordered: marker=%d v2=%d v1=%d", maxQuarantineBytes, maxPreparedV2Bytes, maxLegacyV1Bytes)
	}
	for _, tc := range []struct {
		name  string
		limit int
		parse func([]byte) error
	}{
		{"legacy v1", maxLegacyV1Bytes, func(raw []byte) error { _, err := ClassifyLegacyV1(raw); return err }},
		{"prepared v2", maxPreparedV2Bytes, func(raw []byte) error { _, err := DecodePreparedV2(raw); return err }},
		{"quarantine marker", maxQuarantineBytes, func(raw []byte) error { _, err := DecodeQuarantineMarker(raw); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.parse([]byte("x")); err != errInvalidJournalWire {
				t.Fatalf("malformed in-cap input returned %v, want syntax rejection", err)
			}
			atLimit := bytes.Repeat([]byte{'x'}, tc.limit)
			if err := tc.parse(atLimit); err != errInvalidJournalWire {
				t.Fatalf("malformed input exactly at %d-byte cap returned %v, want decode rejection", tc.limit, err)
			}
			raw := bytes.Repeat([]byte{'x'}, tc.limit+1)
			if len(raw) != tc.limit+1 {
				t.Fatal("test probe is not exactly one byte over the codec cap")
			}
			if err := tc.parse(raw); !errors.Is(err, errJournalWireTooLarge) {
				t.Fatalf("one-byte-over-cap input returned %v, want size rejection", err)
			}
		})
	}
}

func TestJournalCodecAcceptsBoundaryYears(t *testing.T) {
	plan := journalPlan(t)
	for _, tc := range []struct {
		name string
		year int
	}{
		{"year 0001", 1},
		{"year 9999", 9999},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Second 1 avoids Go's time.Time zero value at year 1, Jan 1.
			stamp := time.Date(tc.year, 1, 1, 0, 0, 1, 0, time.UTC)
			v2, err := EncodePreparedV2(PreparedV2Record{Revision: 1, Plan: plan, CreatedAt: stamp, UpdatedAt: stamp})
			if err != nil {
				t.Fatalf("encode v2 at valid year boundary: %v", err)
			}
			if decoded, err := DecodePreparedV2(v2); err != nil || !decoded.CreatedAt.Equal(stamp) || !decoded.UpdatedAt.Equal(stamp) {
				t.Fatalf("decode v2 at valid year boundary: %#v, %v", decoded, err)
			}
			marker, err := EncodeQuarantineMarker(QuarantineMarker{
				RecordSHA256: historicalV1PreparedSHA256, State: StateConfirmed, DetectedAt: stamp,
			})
			if err != nil {
				t.Fatalf("encode marker at valid year boundary: %v", err)
			}
			if decoded, err := DecodeQuarantineMarker(marker); err != nil || !decoded.DetectedAt.Equal(stamp) {
				t.Fatalf("decode marker at valid year boundary: %#v, %v", decoded, err)
			}
		})
	}
}

func TestJournalCodecRejectsOutOfRangeYearsOnEncodeAndDecode(t *testing.T) {
	plan := journalPlan(t)
	validV2, err := EncodePreparedV2(PreparedV2Record{
		Revision: 1, Plan: plan, CreatedAt: codecTime, UpdatedAt: codecTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	validMarker, err := EncodeQuarantineMarker(QuarantineMarker{
		RecordSHA256: historicalV1PreparedSHA256, State: StateConfirmed, DetectedAt: codecTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		year int
		wire string
	}{
		{"year 10000", 10000, "10000-01-01T00:00:00Z"},
		{"year zero", 0, "0000-01-01T00:00:00Z"},
		{"negative year", -1, "-0001-01-01T00:00:00Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			invalidTime := time.Date(tc.year, 1, 1, 0, 0, 0, 0, time.UTC)
			if invalidTime.IsZero() {
				t.Fatal("probe accidentally tests Go's zero time")
			}
			if _, err := EncodePreparedV2(PreparedV2Record{
				Revision: 1, Plan: plan, CreatedAt: invalidTime, UpdatedAt: invalidTime,
			}); err == nil {
				t.Fatal("encoded v2 with an out-of-range UTC year")
			}
			if _, err := EncodeQuarantineMarker(QuarantineMarker{
				RecordSHA256: historicalV1PreparedSHA256, State: StateConfirmed, DetectedAt: invalidTime,
			}); err == nil {
				t.Fatal("encoded quarantine marker with an out-of-range UTC year")
			}
			for _, field := range []string{"created_at", "updated_at"} {
				candidate := codecReplaceOnce(t, validV2, `"`+field+`": "2026-09-28T15:00:00Z"`, `"`+field+`": "`+tc.wire+`"`)
				if !json.Valid(candidate) {
					t.Fatal("out-of-range v2 timestamp probe must be valid JSON")
				}
				if _, err := DecodePreparedV2(candidate); err == nil {
					t.Fatalf("decoded v2 with out-of-range %s", field)
				}
			}
			markerCandidate := codecReplaceOnce(t, validMarker, `"detected_at": "2026-09-28T15:00:00Z"`, `"detected_at": "`+tc.wire+`"`)
			if !json.Valid(markerCandidate) {
				t.Fatal("out-of-range marker timestamp probe must be valid JSON")
			}
			if _, err := DecodeQuarantineMarker(markerCandidate); err == nil {
				t.Fatal("decoded marker with an out-of-range UTC year")
			}
		})
	}
}
