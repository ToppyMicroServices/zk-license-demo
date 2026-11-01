package careerzk

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"
)

type Fixture struct {
	Name       string
	Credential Credential
	Request    Request
	Expected   Answer
}

// Fixtures contain only generated secrets and synthetic dates/attributes.
func Fixtures(setupID string) (IssuerKey, Holder, []Fixture, error) {
	issuer, pub, err := NewIssuer()
	if err != nil {
		return IssuerKey{}, Holder{}, nil, err
	}
	holder, err := NewHolder()
	if err != nil {
		return IssuerKey{}, Holder{}, nil, err
	}
	subject, err := holder.Subject()
	if err != nil {
		return IssuerKey{}, Holder{}, nil, err
	}
	b := Bundle{
		Subject: subject, IssuedAt: "2024-12-31", ExpiresAt: "2026-01-01",
		CoverageStart: "2024-01-01", CoverageEnd: "2025-01-01", Complete: true,
		Records: []Record{
			{subject, "2024-01-01", "2024-04-01", true, "yes"},
			{subject, "2024-02-01", "2024-05-01", true, "yes"},
			{subject, "2024-06-01", "2024-07-01", true, "unknown"},
		},
	}
	var fixtures []Fixture
	for _, spec := range []struct {
		name     string
		days     int
		complete bool
		answer   Answer
	}{{"yes", 120, true, Yes}, {"no", 152, true, No},
		{"undetermined", 140, true, Undetermined},
		{"incomplete", 152, false, Undetermined}} {
		b.Complete = spec.complete
		cred, err := Issue(issuer, b)
		if err != nil {
			return IssuerKey{}, Holder{}, nil, err
		}
		q, err := NewRequest(pub, setupID, "2024-01-01", "2025-01-01",
			"2025-01-01", spec.days, "local-career-zk-demo")
		if err != nil {
			return IssuerKey{}, Holder{}, nil, err
		}
		fixtures = append(fixtures, Fixture{spec.name, cred, q, spec.answer})
	}
	return issuer, holder, fixtures, nil
}

func SaveFixtures(dir, setupID string) (Holder, []Fixture, error) {
	issuer, holder, fixtures, err := Fixtures(setupID)
	if err != nil {
		return Holder{}, nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return Holder{}, nil, err
	}
	for _, item := range []struct {
		name  string
		value any
	}{{"issuer.private.json", issuer}, {"holder.private.json", holder}} {
		if err := WriteJSON(filepath.Join(dir, item.name), item.value); err != nil {
			return Holder{}, nil, err
		}
	}
	for _, f := range fixtures {
		if err := WriteJSON(filepath.Join(dir, f.Name+".credential.private.json"), f.Credential); err != nil {
			return Holder{}, nil, err
		}
		if err := WriteJSON(filepath.Join(dir, f.Name+".request.json"), f.Request); err != nil {
			return Holder{}, nil, err
		}
	}
	return holder, fixtures, nil
}

type Measurement struct {
	Case          string  `json:"case"`
	Run           int     `json:"run"`
	Answer        Answer  `json:"answer"`
	ProveMS       float64 `json:"prove_with_host_checks_and_self_verify_ms"`
	VerifyMS      float64 `json:"verify_ms"`
	ProofBytes    int     `json:"proof_bytes"`
	ResponseBytes int     `json:"response_json_bytes"`
}

type Report struct {
	Schema          string            `json:"schema"`
	CreatedUTC      string            `json:"created_utc"`
	Go              string            `json:"go"`
	OS              string            `json:"os"`
	Arch            string            `json:"arch"`
	LogicalCPUs     int               `json:"logical_cpus"`
	GOMAXPROCS      int               `json:"gomaxprocs"`
	Dependencies    map[string]string `json:"dependencies"`
	Policy          string            `json:"policy"`
	SetupID         string            `json:"setup_id"`
	RecordsMax      int               `json:"max_records"`
	Interpretations int               `json:"interpretations"`
	Constraints     int               `json:"constraints"`
	SetupMS         float64           `json:"compile_and_setup_ms"`
	PeakMemory      string            `json:"peak_memory"`
	Measurements    []Measurement     `json:"measurements"`
}

// Demo performs real setup, signing, proving and verification. A failed run
// returns an error and never writes a successful benchmark report.
func Demo(dir string, runs int) (*Report, error) {
	if runs < 1 || runs > 20 {
		return nil, fmt.Errorf("%w: runs must be 1..20", ErrInput)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	started := time.Now()
	setup, err := NewSetup()
	if err != nil {
		return nil, err
	}
	setupMS := float64(time.Since(started).Microseconds()) / 1000
	if err := setup.Save(filepath.Join(dir, "setup")); err != nil {
		return nil, err
	}
	id, err := SetupID(setup.VK)
	if err != nil {
		return nil, err
	}
	holder, fixtures, err := SaveFixtures(filepath.Join(dir, "fixtures"), id)
	if err != nil {
		return nil, err
	}
	report := &Report{
		Schema: "career-zk/benchmark/v1", CreatedUTC: time.Now().UTC().Format(time.RFC3339),
		Go: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		LogicalCPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0),
		Dependencies: map[string]string{}, Policy: Policy, SetupID: id,
		RecordsMax: MaxRecords, Interpretations: 1 << MaxRecords,
		Constraints: setup.CS.GetNbConstraints(), SetupMS: setupMS,
		PeakMemory: "not measured internally; use /usr/bin/time -l on macOS or -v on Linux",
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			report.Dependencies[dep.Path] = dep.Version
		}
	}
	for _, fixture := range fixtures {
		for run := 1; run <= runs; run++ {
			started = time.Now()
			response, err := setup.Prove(fixture.Credential, holder, fixture.Request)
			if err != nil {
				return nil, err
			}
			proveMS := float64(time.Since(started).Microseconds()) / 1000
			started = time.Now()
			err = Verify(setup.VK, fixture.Request, response)
			verifyMS := float64(time.Since(started).Microseconds()) / 1000
			if err != nil {
				return nil, err
			}
			if response.Answer != fixture.Expected {
				return nil, fmt.Errorf("fixture %s: unexpected answer", fixture.Name)
			}
			name := filepath.Join(dir, fmt.Sprintf("%s-%d.response.json", fixture.Name, run))
			if err := WriteJSON(name, response); err != nil {
				return nil, err
			}
			stat, err := os.Stat(name)
			if err != nil {
				return nil, err
			}
			report.Measurements = append(report.Measurements, Measurement{
				fixture.Name, run, response.Answer, proveMS, verifyMS, 164, int(stat.Size()),
			})
		}
	}
	if err := WriteJSON(filepath.Join(dir, "report.json"), report); err != nil {
		return nil, err
	}
	return report, nil
}
