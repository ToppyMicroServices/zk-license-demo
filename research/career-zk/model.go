package careerzk

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	nativeeddsa "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark/frontend"
)

var (
	ErrInput        = errors.New("invalid_input")
	ErrEvidence     = errors.New("invalid_evidence")
	ErrUnsupported  = errors.New("unsupported_policy")
	ErrVerification = errors.New("verification_failed")
)

type Answer string

const (
	No           Answer = "NO"
	Yes          Answer = "YES"
	Undetermined Answer = "UNDETERMINED"
)

func (a Answer) code() (int, error) {
	switch a {
	case No:
		return 0, nil
	case Yes:
		return 1, nil
	case Undetermined:
		return 2, nil
	}
	return 0, fmt.Errorf("%w: answer", ErrInput)
}

type Record struct {
	Subject    string `json:"subject"`
	Start      string `json:"start"`
	End        string `json:"end"`
	Python     bool   `json:"python"`
	Production string `json:"production"`
}

// One trusted synthetic issuer attests to the entire record set and its scope.
// This is intentionally not a multi-employer credential aggregation protocol.
type Bundle struct {
	Subject       string   `json:"subject"`
	IssuedAt      string   `json:"issued_at"`
	ExpiresAt     string   `json:"expires_at"`
	CoverageStart string   `json:"coverage_start"`
	CoverageEnd   string   `json:"coverage_end"`
	Complete      bool     `json:"complete"`
	Records       []Record `json:"records"`
}

type Credential struct {
	Bundle    Bundle `json:"bundle"`
	PublicKey string `json:"issuer_public_key"`
	Signature string `json:"signature"`
}

type Holder struct {
	Secret string `json:"secret"`
}

type IssuerKey struct {
	Secret string `json:"secret"`
}

// The verifier retains this request independently of the prover's response.
type Request struct {
	Policy          string `json:"policy"`
	WindowStart     string `json:"window_start"`
	WindowEnd       string `json:"window_end"`
	AsOf            string `json:"as_of"`
	MinDays         int    `json:"min_days"`
	Audience        string `json:"audience"`
	Nonce           string `json:"nonce"`
	IssuerPublicKey string `json:"issuer_public_key"`
	SetupID         string `json:"setup_id"`
}

var epoch = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func day(s string) (int, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil || t.Format("2006-01-02") != s {
		return 0, fmt.Errorf("%w: date must be YYYY-MM-DD", ErrInput)
	}
	n := int((t.Unix() - epoch.Unix()) / 86400)
	if n < 0 || n > MaxDay {
		return 0, fmt.Errorf("%w: date outside supported range", ErrInput)
	}
	return n, nil
}

func scalar(s string, nonzero bool) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.String() != s || v.Sign() < 0 || v.Cmp(ecc.BN254.ScalarField()) >= 0 || (nonzero && v.Sign() == 0) {
		return nil, fmt.Errorf("%w: noncanonical field element", ErrInput)
	}
	return v, nil
}

func randomScalar() (*big.Int, error) {
	for {
		v, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
		if err != nil || v.Sign() != 0 {
			return v, err
		}
	}
}

func fieldBytes(v *big.Int) []byte {
	return v.FillBytes(make([]byte, 32))
}

func hashNative(values ...frontend.Variable) (*big.Int, error) {
	h := mimc.NewMiMC()
	for _, value := range values {
		var v *big.Int
		switch n := value.(type) {
		case int:
			v = big.NewInt(int64(n))
		case *big.Int:
			v = n
		default:
			return nil, fmt.Errorf("%w: unexpected hash input type", ErrInput)
		}
		if v == nil || v.Sign() < 0 || v.Cmp(ecc.BN254.ScalarField()) >= 0 {
			return nil, fmt.Errorf("%w: hash input outside field", ErrInput)
		}
		if _, err := h.Write(fieldBytes(v)); err != nil {
			return nil, err
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

func NewHolder() (Holder, error) {
	v, err := randomScalar()
	if err != nil {
		return Holder{}, err
	}
	return Holder{Secret: v.String()}, nil
}

func (h Holder) Subject() (string, error) {
	s, err := scalar(h.Secret, true)
	if err != nil {
		return "", err
	}
	v, err := hashNative(domainHolder, s)
	if err != nil {
		return "", err
	}
	return v.String(), nil
}

func NewIssuer() (IssuerKey, string, error) {
	key, err := nativeeddsa.GenerateKey(rand.Reader)
	if err != nil {
		return IssuerKey{}, "", err
	}
	return IssuerKey{Secret: hex.EncodeToString(key.Bytes())}, hex.EncodeToString(key.Public().Bytes()), nil
}

func decodeHex(s string, size int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != size || hex.EncodeToString(b) != s {
		return nil, fmt.Errorf("%w: noncanonical hex encoding", ErrInput)
	}
	return b, nil
}

func publicKey(s string) (*nativeeddsa.PublicKey, error) {
	b, err := decodeHex(s, 32)
	if err != nil {
		return nil, err
	}
	var key nativeeddsa.PublicKey
	n, err := key.SetBytes(b)
	if err != nil || n != len(b) || hex.EncodeToString(key.Bytes()) != s {
		return nil, fmt.Errorf("%w: issuer public key", ErrInput)
	}
	return &key, nil
}

func flag(b bool) int {
	if b {
		return 1
	}
	return 0
}

func production(s string) (int, error) {
	switch s {
	case "no":
		return 0, nil
	case "yes":
		return 1, nil
	case "unknown":
		return 2, nil
	}
	return 0, fmt.Errorf("%w: production must be no, yes or unknown", ErrInput)
}

// Fill also validates all host inputs. The circuit repeats the security
// constraints, since a malicious prover can bypass this function.
func (b Bundle) fill(c *Circuit) error {
	if len(b.Records) < 1 || len(b.Records) > MaxRecords {
		return fmt.Errorf("%w: requires one to three records", ErrInput)
	}
	subject, err := scalar(b.Subject, true)
	if err != nil {
		return err
	}
	dates := make([]int, 4)
	for i, s := range []string{b.IssuedAt, b.ExpiresAt, b.CoverageStart, b.CoverageEnd} {
		if dates[i], err = day(s); err != nil {
			return err
		}
	}
	if dates[0] >= dates[1] || dates[2] >= dates[3] {
		return fmt.Errorf("%w: empty validity or coverage interval", ErrInput)
	}
	c.Subject, c.IssuedAt, c.ExpiresAt = subject, dates[0], dates[1]
	c.CoverageStart, c.CoverageEnd = dates[2], dates[3]
	c.Complete, c.Count = flag(b.Complete), len(b.Records)
	for i := range c.Records {
		c.Records[i] = circuitRecord{Subject: 0, Start: 0, End: 0, Python: 0, Production: 0}
	}
	for i, r := range b.Records {
		if r.Subject != b.Subject {
			return fmt.Errorf("%w: mixed subjects", ErrEvidence)
		}
		start, err := day(r.Start)
		if err != nil {
			return err
		}
		end, err := day(r.End)
		if err != nil {
			return err
		}
		role, err := production(r.Production)
		if err != nil {
			return err
		}
		if start >= end || start < dates[2] || end > dates[3] {
			return fmt.Errorf("%w: record outside coverage or empty interval", ErrInput)
		}
		c.Records[i] = circuitRecord{subject, start, end, flag(r.Python), role}
	}
	return nil
}

func Issue(key IssuerKey, bundle Bundle) (Credential, error) {
	var c Circuit
	if err := bundle.fill(&c); err != nil {
		return Credential{}, err
	}
	digest, err := hashNative(c.signedValues()...)
	if err != nil {
		return Credential{}, err
	}
	raw, err := decodeHex(key.Secret, 96)
	if err != nil {
		return Credential{}, err
	}
	var priv nativeeddsa.PrivateKey
	if n, err := priv.SetBytes(raw); err != nil || n != len(raw) {
		return Credential{}, fmt.Errorf("%w: issuer private key", ErrInput)
	}
	signature, err := priv.Sign(fieldBytes(digest), mimc.NewMiMC())
	if err != nil {
		return Credential{}, err
	}
	return Credential{bundle, hex.EncodeToString(priv.Public().Bytes()), hex.EncodeToString(signature)}, nil
}

func NewRequest(pub, setupID, start, end, asOf string, minDays int, audience string) (Request, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Request{}, err
	}
	q := Request{Policy, start, end, asOf, minDays, audience, hex.EncodeToString(nonce), pub, setupID}
	return q, q.Validate()
}

func (q Request) Validate() error {
	if q.Policy != Policy {
		return ErrUnsupported
	}
	start, err := day(q.WindowStart)
	if err != nil {
		return err
	}
	end, err := day(q.WindowEnd)
	if err != nil {
		return err
	}
	asOf, err := day(q.AsOf)
	if err != nil {
		return err
	}
	if start >= end || end > asOf || q.MinDays < 1 || q.MinDays > MaxDay {
		return fmt.Errorf("%w: query interval or threshold", ErrInput)
	}
	if strings.TrimSpace(q.Audience) != q.Audience || len(q.Audience) < 1 || len(q.Audience) > 256 {
		return fmt.Errorf("%w: audience", ErrInput)
	}
	nonce, err := decodeHex(q.Nonce, 16)
	if err != nil || new(big.Int).SetBytes(nonce).Sign() == 0 {
		return fmt.Errorf("%w: nonce", ErrInput)
	}
	if _, err := decodeHex(q.SetupID, 32); err != nil {
		return err
	}
	_, err = publicKey(q.IssuerPublicKey)
	return err
}

func (q Request) requestID() *big.Int {
	// Struct encoding fixes field order; input JSON whitespace/order is irrelevant.
	raw, _ := json.Marshal(q)
	sum := sha256.Sum256(append([]byte("career-zk/request/v1\x00"), raw...))
	return new(big.Int).Mod(new(big.Int).SetBytes(sum[:]), ecc.BN254.ScalarField())
}

func publicAssignment(q Request, answer Answer, commitment string) (*Circuit, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	code, err := answer.code()
	if err != nil {
		return nil, err
	}
	comm, err := scalar(commitment, false)
	if err != nil {
		return nil, err
	}
	key, err := publicKey(q.IssuerPublicKey)
	if err != nil {
		return nil, err
	}
	start, _ := day(q.WindowStart)
	end, _ := day(q.WindowEnd)
	asOf, _ := day(q.AsOf)
	c := &Circuit{PolicyID: 1, WindowStart: start, WindowEnd: end, AsOf: asOf,
		MinDays: q.MinDays, RequestID: q.requestID(), Commitment: comm, Answer: code}
	c.Key.A.X = key.A.X.BigInt(new(big.Int))
	c.Key.A.Y = key.A.Y.BigInt(new(big.Int))
	return c, nil
}

// Evaluate is an independent reference implementation using sorted intervals.
// It does not check the issuer signature; the prover and the ZK circuit do.
func Evaluate(b Bundle, q Request) (Answer, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}
	var c Circuit
	if err := b.fill(&c); err != nil {
		return "", err
	}
	start, _ := day(q.WindowStart)
	end, _ := day(q.WindowEnd)
	asOf, _ := day(q.AsOf)
	if asOf < c.IssuedAt.(int) || asOf >= c.ExpiresAt.(int) {
		return "", fmt.Errorf("%w: credential not valid as of requested date", ErrEvidence)
	}
	passes := 0
	for mask := 0; mask < 1<<MaxRecords; mask++ {
		var intervals [][2]int
		for i := 0; i < len(b.Records); i++ {
			r := c.Records[i]
			role := r.Production.(int)
			if r.Python.(int) == 1 && (role == 1 || (role == 2 && mask&(1<<i) != 0)) {
				a, z := max(start, r.Start.(int)), min(end, r.End.(int))
				if a < z {
					intervals = append(intervals, [2]int{a, z})
				}
			}
		}
		sort.Slice(intervals, func(i, j int) bool { return intervals[i][0] < intervals[j][0] })
		days, coveredUntil := 0, start
		for _, r := range intervals {
			if r[1] > coveredUntil {
				days += r[1] - max(coveredUntil, r[0])
				coveredUntil = r[1]
			}
		}
		if days >= q.MinDays {
			passes++
		}
	}
	if passes == 1<<MaxRecords {
		return Yes, nil
	}
	if passes == 0 && b.Complete && c.CoverageStart.(int) <= start && c.CoverageEnd.(int) >= end {
		return No, nil
	}
	return Undetermined, nil
}

func makeAssignment(cred Credential, holder Holder, q Request) (*Circuit, Answer, error) {
	answer, err := Evaluate(cred.Bundle, q)
	if err != nil {
		return nil, "", err
	}
	if cred.PublicKey != q.IssuerPublicKey {
		return nil, "", fmt.Errorf("%w: untrusted issuer", ErrEvidence)
	}
	c, err := publicAssignment(q, answer, "0")
	if err != nil {
		return nil, "", err
	}
	if err := cred.Bundle.fill(c); err != nil {
		return nil, "", err
	}
	secret, err := scalar(holder.Secret, true)
	if err != nil {
		return nil, "", err
	}
	subject, err := holder.Subject()
	if err != nil || subject != cred.Bundle.Subject {
		return nil, "", fmt.Errorf("%w: holder binding", ErrEvidence)
	}
	blind, err := randomScalar()
	if err != nil {
		return nil, "", err
	}
	c.HolderSecret, c.Blind = secret, blind
	digest, err := hashNative(c.signedValues()...)
	if err != nil {
		return nil, "", err
	}
	sigBytes, err := decodeHex(cred.Signature, 64)
	if err != nil {
		return nil, "", err
	}
	var sig nativeeddsa.Signature
	if n, err := sig.SetBytes(sigBytes); err != nil || n != len(sigBytes) {
		return nil, "", fmt.Errorf("%w: signature encoding", ErrEvidence)
	}
	pub, _ := publicKey(q.IssuerPublicKey)
	valid, err := pub.Verify(sigBytes, fieldBytes(digest), mimc.NewMiMC())
	if err != nil || !valid {
		return nil, "", fmt.Errorf("%w: issuer signature", ErrEvidence)
	}
	c.Signature.R.X = sig.R.X.BigInt(new(big.Int))
	c.Signature.R.Y = sig.R.Y.BigInt(new(big.Int))
	c.Signature.S = new(big.Int).SetBytes(sig.S[:])
	c.Commitment, err = hashNative(domainCommit, digest, blind, c.RequestID)
	return c, answer, err
}
