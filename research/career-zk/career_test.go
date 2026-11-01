package careerzk

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	mathrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	nativeeddsa "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

var shared struct {
	sync.Once
	setup *Setup
	err   error
}

func testSetup(t *testing.T) *Setup {
	t.Helper()
	shared.Do(func() { shared.setup, shared.err = NewSetup() })
	if shared.err != nil {
		t.Fatal(shared.err)
	}
	return shared.setup
}

func testFixtures(t *testing.T) (IssuerKey, Holder, []Fixture) {
	t.Helper()
	id, err := SetupID(testSetup(t).VK)
	if err != nil {
		t.Fatal(err)
	}
	key, holder, fixtures, err := Fixtures(id)
	if err != nil {
		t.Fatal(err)
	}
	return key, holder, fixtures
}

func solve(s *Setup, c *Circuit) error {
	w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	_, err = s.CS.Solve(w)
	return err
}

func assignment(t *testing.T, f Fixture, holder Holder) *Circuit {
	t.Helper()
	c, _, err := makeAssignment(f.Credential, holder, f.Request)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Re-sign deliberately invalid data to distinguish circuit checks from the
// host-side schema validation and from signature-integrity checks.
func resign(t *testing.T, c *Circuit, key IssuerKey) {
	t.Helper()
	digest, err := hashNative(c.signedValues()...)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(key.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var priv nativeeddsa.PrivateKey
	if _, err := priv.SetBytes(raw); err != nil {
		t.Fatal(err)
	}
	raw, err = priv.Sign(fieldBytes(digest), mimc.NewMiMC())
	if err != nil {
		t.Fatal(err)
	}
	var sig nativeeddsa.Signature
	if _, err := sig.SetBytes(raw); err != nil {
		t.Fatal(err)
	}
	c.Signature.R.X = sig.R.X.BigInt(new(big.Int))
	c.Signature.R.Y = sig.R.Y.BigInt(new(big.Int))
	c.Signature.S = new(big.Int).SetBytes(sig.S[:])
	c.Commitment, err = hashNative(domainCommit, digest, c.Blind, c.RequestID)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRealProofsAndStatementBinding(t *testing.T) {
	s := testSetup(t)
	_, holder, fixtures := testFixtures(t)
	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			response, err := s.Prove(f.Credential, holder, f.Request)
			if err != nil {
				t.Fatal(err)
			}
			if response.Answer != f.Expected {
				t.Fatalf("answer = %s, want %s", response.Answer, f.Expected)
			}
			if err := Verify(s.VK, f.Request, response); err != nil {
				t.Fatal(err)
			}
			for name, change := range map[string]func(*Request){
				"threshold":    func(q *Request) { q.MinDays++ },
				"window_start": func(q *Request) { q.WindowStart = "2024-01-02" },
				"window_end":   func(q *Request) { q.WindowEnd = "2024-12-31" },
				"as_of":        func(q *Request) { q.AsOf = "2025-01-02" },
				"audience":     func(q *Request) { q.Audience = "another-verifier" },
				"nonce":        func(q *Request) { q.Nonce = strings.Repeat("ab", 16) },
				"policy":       func(q *Request) { q.Policy = "python-production-days/v2" },
				"setup":        func(q *Request) { q.SetupID = strings.Repeat("ab", 32) },
				"issuer": func(q *Request) {
					_, pub, err := NewIssuer()
					if err != nil {
						t.Fatal(err)
					}
					q.IssuerPublicKey = pub
				},
			} {
				t.Run(name, func(t *testing.T) {
					q := f.Request
					change(&q)
					if err := Verify(s.VK, q, response); err == nil {
						t.Fatal("accepted substituted request")
					}
				})
			}
			for _, answer := range []Answer{Yes, No, Undetermined, "MAYBE"} {
				if answer == response.Answer {
					continue
				}
				r := response
				r.Answer = answer
				if err := Verify(s.VK, f.Request, r); err == nil {
					t.Fatalf("accepted answer %s", answer)
				}
			}
			r := response
			v, _ := scalar(r.Commitment, false)
			r.Commitment = new(big.Int).Mod(new(big.Int).Add(v, big.NewInt(1)), ecc.BN254.ScalarField()).String()
			if err := Verify(s.VK, f.Request, r); err == nil {
				t.Fatal("accepted changed commitment")
			}
			raw, _ := base64.StdEncoding.DecodeString(response.Proof)
			for name, bad := range map[string][]byte{
				"bit_flip":              append([]byte(nil), raw...),
				"truncated":             raw[:len(raw)-1],
				"trailing":              append(append([]byte(nil), raw...), 0),
				"zero_points":           make([]byte, len(raw)),
				"huge_commitment_count": append([]byte(nil), raw...),
			} {
				t.Run(name, func(t *testing.T) {
					if name == "bit_flip" {
						bad[12] ^= 1
					}
					if name == "huge_commitment_count" {
						copy(bad[128:132], []byte{255, 255, 255, 255})
					}
					r := response
					r.Proof = base64.StdEncoding.EncodeToString(bad)
					if err := Verify(s.VK, f.Request, r); err == nil {
						t.Fatal("accepted malformed proof")
					}
				})
			}
			r = response
			r.Proof += "\n"
			if err := Verify(s.VK, f.Request, r); err == nil {
				t.Fatal("accepted noncanonical base64")
			}
			r = response
			r.Format = "mock"
			if err := Verify(s.VK, f.Request, r); err == nil {
				t.Fatal("accepted different proof format")
			}
			rawJSON, _ := json.Marshal(response)
			for _, secret := range []string{holder.Secret, f.Credential.Bundle.Subject, f.Credential.Signature, f.Credential.Bundle.Records[0].Start} {
				if bytes.Contains(rawJSON, []byte(secret)) {
					t.Fatal("response contains private evidence")
				}
			}
		})
	}
	t.Run("randomized_commitments", func(t *testing.T) {
		a, err := s.Prove(fixtures[0].Credential, holder, fixtures[0].Request)
		if err != nil {
			t.Fatal(err)
		}
		b, err := s.Prove(fixtures[0].Credential, holder, fixtures[0].Request)
		if err != nil {
			t.Fatal(err)
		}
		if a.Commitment == b.Commitment || a.Proof == b.Proof {
			t.Fatal("reused commitment or proof randomness")
		}
	})
	t.Run("different_setup", func(t *testing.T) {
		_, otherVK, err := groth16.Setup(s.CS)
		if err != nil {
			t.Fatal(err)
		}
		response, err := s.Prove(fixtures[0].Credential, holder, fixtures[0].Request)
		if err != nil {
			t.Fatal(err)
		}
		if err := Verify(otherVK, fixtures[0].Request, response); err == nil {
			t.Fatal("accepted another setup")
		}
		q := fixtures[0].Request
		q.SetupID, _ = SetupID(otherVK)
		if err := Verify(otherVK, q, response); err == nil {
			t.Fatal("accepted substituted setup and request")
		}
	})
}

func TestCircuitRejectsMaliciousWitnesses(t *testing.T) {
	s := testSetup(t)
	key, holder, fixtures := testFixtures(t)
	for name, change := range map[string]func(*Circuit){
		"forged_yes_omits_unfavorable_interpretations": func(c *Circuit) { c.Answer = 1 },
		"forged_no_omits_favorable_interpretations":    func(c *Circuit) { c.Answer = 0 },
		"changed_record":      func(c *Circuit) { c.Records[2].Production = 1 },
		"omitted_record":      func(c *Circuit) { c.Count = 2; c.Records[2] = circuitRecord{0, 0, 0, 0, 0} },
		"forged_completeness": func(c *Circuit) { c.Complete = 0 },
		"signature_scalar":    func(c *Circuit) { c.Signature.S = 1 },
		"signature_point":     func(c *Circuit) { c.Signature.R.X = 0; c.Signature.R.Y = 0 },
		"holder_secret":       func(c *Circuit) { c.HolderSecret = 1 },
		"zero_holder_secret":  func(c *Circuit) { c.HolderSecret = 0 },
		"zero_blind":          func(c *Circuit) { c.Blind = 0 },
		"policy":              func(c *Circuit) { c.PolicyID = 2 },
		"answer_domain":       func(c *Circuit) { c.Answer = 3 },
		"zero_threshold":      func(c *Circuit) { c.MinDays = 0 },
		"threshold_overflow":  func(c *Circuit) { c.MinDays = MaxDay + 1 },
		"future_window":       func(c *Circuit) { c.WindowEnd = c.AsOf.(int) + 1 },
		"empty_window":        func(c *Circuit) { c.WindowEnd = c.WindowStart },
		"wrapped_date":        func(c *Circuit) { c.WindowStart = new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1)) },
		"expired":             func(c *Circuit) { c.AsOf = c.ExpiresAt },
		"before_issue":        func(c *Circuit) { c.AsOf = c.IssuedAt.(int) - 1 },
	} {
		t.Run(name, func(t *testing.T) {
			c := assignment(t, fixtures[2], holder)
			change(c)
			if err := solve(s, c); err == nil {
				t.Fatal("circuit accepted malicious witness")
			}
		})
	}
	// A valid signature does not bypass the policy's input constraints.
	for name, change := range map[string]func(*Circuit){
		"mixed_subjects": func(c *Circuit) { c.Records[0].Subject = new(big.Int).Add(c.Subject.(*big.Int), big.NewInt(1)) },
		"empty_records": func(c *Circuit) {
			c.Count = 0
			for i := range c.Records {
				c.Records[i] = circuitRecord{0, 0, 0, 0, 0}
			}
		},
		"count_overflow":              func(c *Circuit) { c.Count = 4 },
		"nonzero_padding":             func(c *Circuit) { c.Count = 2 },
		"python_non_boolean":          func(c *Circuit) { c.Records[0].Python = 2 },
		"invalid_interpretation_flag": func(c *Circuit) { c.Records[0].Production = 3 },
		"record_date_overflow":        func(c *Circuit) { c.Records[0].End = MaxDay + 1 },
		"empty_record":                func(c *Circuit) { c.Records[0].End = c.Records[0].Start },
		"outside_coverage":            func(c *Circuit) { c.CoverageStart = c.Records[0].Start.(int) + 1 },
		"completeness_non_boolean":    func(c *Circuit) { c.Complete = 2 },
		"reversed_validity":           func(c *Circuit) { c.ExpiresAt = c.IssuedAt },
	} {
		t.Run("signed_"+name, func(t *testing.T) {
			c := assignment(t, fixtures[2], holder)
			change(c)
			resign(t, c, key)
			if err := solve(s, c); err == nil {
				t.Fatal("circuit accepted signed invalid data")
			}
		})
	}
	t.Run("incomplete_cannot_prove_no", func(t *testing.T) {
		c := assignment(t, fixtures[3], holder)
		c.Answer = 0
		if err := solve(s, c); err == nil {
			t.Fatal("incomplete evidence accepted as NO")
		}
		// Also invoke the real prover directly, bypassing makeAssignment.
		w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := groth16.Prove(s.CS, s.PK, w); err == nil {
			t.Fatal("generated proof for false statement")
		}
	})
}

func TestReferenceAndCircuitBoundaries(t *testing.T) {
	key, holder, fixtures := testFixtures(t)
	base := fixtures[0]
	subject := base.Credential.Bundle.Subject
	record := func(a, b, role string) Record { return Record{subject, a, b, true, role} }
	tests := []struct {
		name     string
		records  []Record
		days     int
		complete bool
		answer   Answer
	}{
		{"leap_day_equal", []Record{record("2024-02-28", "2024-03-01", "yes")}, 2, true, Yes},
		{"end_exclusive", []Record{record("2024-02-28", "2024-03-01", "yes")}, 3, true, No},
		{"overlap_not_sum", base.Credential.Bundle.Records[:2], 122, true, No},
		{"overlap_equal", base.Credential.Bundle.Records[:2], 121, true, Yes},
		{"triple_overlap", []Record{record("2024-01-01", "2024-02-01", "yes"), record("2024-01-05", "2024-01-20", "yes"), record("2024-01-10", "2024-02-02", "yes")}, 32, true, Yes},
		{"triple_overlap_boundary", []Record{record("2024-01-01", "2024-02-01", "yes"), record("2024-01-05", "2024-01-20", "yes"), record("2024-01-10", "2024-02-02", "yes")}, 33, true, No},
		{"adjacent_intervals", []Record{record("2024-01-01", "2024-02-01", "yes"), record("2024-02-01", "2024-03-01", "yes")}, 60, true, Yes},
		{"all_unknown", []Record{record("2024-01-01", "2024-04-01", "unknown")}, 30, true, Undetermined},
		{"eight_distinct_interpretations", []Record{record("2024-01-01", "2024-02-01", "unknown"), record("2024-03-01", "2024-04-01", "unknown"), record("2024-05-01", "2024-06-01", "unknown")}, 40, true, Undetermined},
		{"unknown_irrelevant_to_yes", base.Credential.Bundle.Records, 120, false, Yes},
		{"none_qualify_complete", []Record{record("2024-01-01", "2024-04-01", "no")}, 1, true, No},
		{"none_qualify_incomplete", []Record{record("2024-01-01", "2024-04-01", "no")}, 1, false, Undetermined},
		{"threshold_max", base.Credential.Bundle.Records, MaxDay, true, No},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := base.Credential.Bundle
			b.Records = tc.records
			b.Complete = tc.complete
			q := base.Request
			q.MinDays = tc.days
			got, err := Evaluate(b, q)
			if err != nil || got != tc.answer {
				t.Fatalf("got %s, err %v; want %s", got, err, tc.answer)
			}
			cred, err := Issue(key, b)
			if err != nil {
				t.Fatal(err)
			}
			c, _, err := makeAssignment(cred, holder, q)
			if err != nil {
				t.Fatal(err)
			}
			if err := solve(testSetup(t), c); err != nil {
				t.Fatal(err)
			}
		})
	}
	for name, transform := range map[string]func(*Bundle, *Request){
		"clipped_window": func(b *Bundle, q *Request) {
			b.Records = []Record{record("2024-01-01", "2024-04-01", "yes")}
			q.WindowStart = "2024-02-28"
			q.WindowEnd = "2024-03-01"
			q.MinDays = 2
		},
		"non_python": func(b *Bundle, q *Request) {
			b.Records = []Record{record("2024-01-01", "2024-04-01", "yes")}
			b.Records[0].Python = false
			q.MinDays = 1
		},
		"partial_scope": func(b *Bundle, q *Request) {
			b.Records = []Record{record("2024-02-01", "2024-04-01", "no")}
			b.CoverageStart = "2024-02-01"
			q.MinDays = 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, q := base.Credential.Bundle, base.Request
			transform(&b, &q)
			want := Yes
			if name == "non_python" {
				want = No
			}
			if name == "partial_scope" {
				want = Undetermined
			}
			got, err := Evaluate(b, q)
			if err != nil || got != want {
				t.Fatalf("got %s, %v", got, err)
			}
			cred, err := Issue(key, b)
			if err != nil {
				t.Fatal(err)
			}
			c, _, err := makeAssignment(cred, holder, q)
			if err != nil {
				t.Fatal(err)
			}
			if err := solve(testSetup(t), c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A third, day-by-day oracle avoids sharing either interval algorithm.
func calendarOracle(b Bundle, q Request) Answer {
	start, _ := day(q.WindowStart)
	end, _ := day(q.WindowEnd)
	passes := 0
	for mask := 0; mask < 8; mask++ {
		n := 0
		for date := start; date < end; date++ {
			for i, r := range b.Records {
				a, _ := day(r.Start)
				z, _ := day(r.End)
				if r.Python && (r.Production == "yes" || r.Production == "unknown" && mask&(1<<i) != 0) && a <= date && date < z {
					n++
					break
				}
			}
		}
		if n >= q.MinDays {
			passes++
		}
	}
	if passes == 8 {
		return Yes
	}
	cs, _ := day(b.CoverageStart)
	ce, _ := day(b.CoverageEnd)
	if passes == 0 && b.Complete && cs <= start && end <= ce {
		return No
	}
	return Undetermined
}

func TestRandomIntervalsAgainstCalendarOracle(t *testing.T) {
	key, holder, fixtures := testFixtures(t)
	rng := mathrand.New(mathrand.NewSource(20261101))
	date := func(n int) string { return time.Date(2024, 1, 1+n, 0, 0, 0, 0, time.UTC).Format("2006-01-02") }
	for iteration := 0; iteration < 40; iteration++ {
		b, q := fixtures[0].Credential.Bundle, fixtures[0].Request
		b.Records = nil
		b.Complete = rng.Intn(2) == 1
		for n := 1 + rng.Intn(3); n > 0; n-- {
			a := rng.Intn(29)
			z := a + 1 + rng.Intn(30-a)
			b.Records = append(b.Records, Record{b.Subject, date(a), date(z), rng.Intn(2) == 1, []string{"no", "yes", "unknown"}[rng.Intn(3)]})
		}
		a := rng.Intn(15)
		z := a + 1 + rng.Intn(31-a)
		q.WindowStart = date(a)
		q.WindowEnd = date(z)
		q.MinDays = 1 + rng.Intn(32)
		want := calendarOracle(b, q)
		got, err := Evaluate(b, q)
		if err != nil || got != want {
			t.Fatalf("case %d: oracle %s, got %s: %v", iteration, want, got, err)
		}
		cred, err := Issue(key, b)
		if err != nil {
			t.Fatal(err)
		}
		c, _, err := makeAssignment(cred, holder, q)
		if err != nil {
			t.Fatal(err)
		}
		if err := solve(testSetup(t), c); err != nil {
			t.Fatalf("case %d: %v", iteration, err)
		}
	}
}

func TestInvalidInputsAreErrors(t *testing.T) {
	key, holder, fixtures := testFixtures(t)
	for name, change := range map[string]func(*Bundle){
		"empty":                func(b *Bundle) { b.Records = nil },
		"too_many":             func(b *Bundle) { b.Records = append(b.Records, b.Records[0]) },
		"mixed":                func(b *Bundle) { b.Records[0].Subject = "1" },
		"invalid_date":         func(b *Bundle) { b.Records[0].Start = "2024-02-30" },
		"invalid_role":         func(b *Bundle) { b.Records[0].Production = "maybe" },
		"reversed_interval":    func(b *Bundle) { b.Records[0].End = b.Records[0].Start },
		"record_outside_scope": func(b *Bundle) { b.CoverageStart = "2024-02-01" },
		"noncanonical_subject": func(b *Bundle) { b.Subject = "01" },
		"invalid_validity":     func(b *Bundle) { b.ExpiresAt = b.IssuedAt },
	} {
		t.Run(name, func(t *testing.T) {
			b := fixtures[0].Credential.Bundle
			b.Records = append([]Record(nil), b.Records...)
			change(&b)
			if answer, err := Evaluate(b, fixtures[0].Request); err == nil || answer != "" {
				t.Fatal("invalid evidence became an answer")
			}
			if _, err := Issue(key, b); err == nil {
				t.Fatal("issued invalid credential")
			}
		})
	}
	for name, change := range map[string]func(*Request){
		"unsupported":        func(q *Request) { q.Policy = "natural-language" },
		"zero_threshold":     func(q *Request) { q.MinDays = 0 },
		"overflow_threshold": func(q *Request) { q.MinDays = MaxDay + 1 },
		"negative_threshold": func(q *Request) { q.MinDays = -1 },
		"future_window":      func(q *Request) { q.WindowEnd = "2025-01-02" },
		"date_before_epoch":  func(q *Request) { q.WindowStart = "1999-12-31" },
		"empty_window":       func(q *Request) { q.WindowEnd = q.WindowStart },
		"invalid_date":       func(q *Request) { q.WindowStart = "2023-02-29" },
		"empty_audience":     func(q *Request) { q.Audience = "" },
		"empty_nonce":        func(q *Request) { q.Nonce = "" },
		"zero_nonce":         func(q *Request) { q.Nonce = strings.Repeat("0", 32) },
		"invalid_key":        func(q *Request) { q.IssuerPublicKey = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			q := fixtures[0].Request
			change(&q)
			if answer, err := Evaluate(fixtures[0].Credential.Bundle, q); err == nil || answer != "" {
				t.Fatal("invalid request became an answer")
			}
		})
	}
	t.Run("untrusted_issuer", func(t *testing.T) {
		q := fixtures[0].Request
		_, q.IssuerPublicKey, _ = NewIssuer()
		if _, _, err := makeAssignment(fixtures[0].Credential, holder, q); !errors.Is(err, ErrEvidence) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("other_holder", func(t *testing.T) {
		other, _ := NewHolder()
		if _, _, err := makeAssignment(fixtures[0].Credential, other, fixtures[0].Request); !errors.Is(err, ErrEvidence) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("tampered_signed_evidence", func(t *testing.T) {
		f := fixtures[0]
		f.Credential.Bundle.Complete = false
		if _, _, err := makeAssignment(f.Credential, holder, f.Request); !errors.Is(err, ErrEvidence) {
			t.Fatalf("got %v", err)
		}
	})
	for _, date := range []string{"2024-12-30", "2026-01-01"} {
		t.Run("invalid_as_of_"+date, func(t *testing.T) {
			q := fixtures[0].Request
			q.AsOf = date
			q.WindowEnd = "2024-12-01"
			if a, err := Evaluate(fixtures[0].Credential.Bundle, q); !errors.Is(err, ErrEvidence) || a != "" {
				t.Fatalf("got %s, %v", a, err)
			}
		})
	}
}

func TestStrictJSONAndFileProtection(t *testing.T) {
	for _, raw := range []string{
		`{"answer":"YES","answer":"NO"}`,
		`{"answer":"YES","Answer":"NO"}`,
		`{"answer":"YES","interpretations":[7]}`,
		`{} {}`,
		`{"x":{"a":1,"a":2}}`,
		strings.Repeat("[", 18) + strings.Repeat("]", 18),
		strings.Repeat(" ", maxJSONBytes+1),
	} {
		var r Response
		if err := DecodeJSON([]byte(raw), &r); err == nil {
			t.Fatal("accepted ambiguous or unsupported JSON")
		}
	}
	var r Response
	if err := DecodeJSON([]byte(`{"format":"x","answer":"YES","commitment":"1","proof":"x"}`), &r); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "private.json")
	if err := WriteJSON(path, Holder{"123"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, Holder{"456"}); err == nil {
		t.Fatal("overwrote existing secret")
	}
	var holder Holder
	if err := ReadJSON(path, &holder); err != nil || holder.Secret != "123" {
		t.Fatal("original secret not preserved")
	}
	if stat, err := os.Stat(path); err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("private file permissions")
	}
}

func TestCLISeparateProverAndVerifier(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "career-zk")
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/career-zk")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	s := testSetup(t)
	_, holder, fixtures := testFixtures(t)
	f := fixtures[2]
	setupDir := filepath.Join(dir, "setup")
	if err := s.Save(setupDir); err != nil {
		t.Fatal(err)
	}
	credPath, holderPath, qPath, proofPath := filepath.Join(dir, "credential.json"), filepath.Join(dir, "holder.json"), filepath.Join(dir, "request.json"), filepath.Join(dir, "proof.json")
	for _, item := range []struct {
		path  string
		value any
	}{{credPath, f.Credential}, {holderPath, holder}, {qPath, f.Request}} {
		if err := WriteJSON(item.path, item.value); err != nil {
			t.Fatal(err)
		}
	}
	cmd = exec.Command(binary, "prove", "-setup", setupDir, "-credential", credPath, "-holder", holderPath, "-request", qPath, "-out", proofPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("prove: %v\n%s", err, output)
	}
	// The verifier working directory contains only the verification key,
	// expected request, and response. It has no need to load any private file.
	verifierDir := filepath.Join(dir, "verifier")
	if err := os.Mkdir(verifierDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ source, dest string }{{filepath.Join(setupDir, "verifying.key"), "verifying.key"}, {qPath, "request.json"}, {proofPath, "proof.json"}} {
		raw, err := os.ReadFile(item.source)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeNew(filepath.Join(verifierDir, item.dest), raw); err != nil {
			t.Fatal(err)
		}
	}
	verifyArgs := []string{"verify", "-vk", "verifying.key", "-request", "request.json", "-proof", "proof.json"}
	cmd = exec.Command(binary, verifyArgs...)
	cmd.Dir = verifierDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("verify: %v\n%s", err, output)
	}
	var result struct {
		Verified bool   `json:"verified"`
		Answer   Answer `json:"answer"`
	}
	if err := json.Unmarshal(output, &result); err != nil || !result.Verified || result.Answer != Undetermined {
		t.Fatalf("bad CLI result: %s", output)
	}
	q := f.Request
	q.MinDays = 1
	if err := WriteJSON(filepath.Join(verifierDir, "changed.json"), q); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(binary, "verify", "-vk", "verifying.key", "-request", "changed.json", "-proof", "proof.json")
	cmd.Dir = verifierDir
	output, err = cmd.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte(`"error":"verification_failed"`)) || bytes.Contains(output, []byte(`"verified":true`)) {
		t.Fatalf("invalid CLI success: %s, %v", output, err)
	}
}
