package careerzk

import (
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/signature/eddsa"
)

const (
	MaxRecords   = 3
	MaxDay       = 65535
	Policy       = "python-production-days/v1"
	domainBundle = 101
	domainHolder = 102
	domainCommit = 103
)

type circuitRecord struct {
	Subject, Start, End, Python, Production frontend.Variable
}

// Public values are constructed by the verifier from its own request.
// Neither the signature nor the signed manifest digest is public.
type Circuit struct {
	Key         eddsa.PublicKey   `gnark:",public"`
	PolicyID    frontend.Variable `gnark:",public"`
	WindowStart frontend.Variable `gnark:",public"`
	WindowEnd   frontend.Variable `gnark:",public"`
	AsOf        frontend.Variable `gnark:",public"`
	MinDays     frontend.Variable `gnark:",public"`
	RequestID   frontend.Variable `gnark:",public"`
	Commitment  frontend.Variable `gnark:",public"`
	Answer      frontend.Variable `gnark:",public"`

	Subject, HolderSecret, Blind frontend.Variable
	IssuedAt, ExpiresAt          frontend.Variable
	CoverageStart, CoverageEnd   frontend.Variable
	Complete, Count              frontend.Variable
	Records                      [MaxRecords]circuitRecord
	Signature                    eddsa.Signature
}

func hashCircuit(api frontend.API, values ...frontend.Variable) (frontend.Variable, error) {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return nil, err
	}
	h.Write(values...)
	return h.Sum(), nil
}

func (c *Circuit) signedValues() []frontend.Variable {
	v := []frontend.Variable{domainBundle, c.Subject, c.IssuedAt, c.ExpiresAt,
		c.CoverageStart, c.CoverageEnd, c.Complete, c.Count}
	for _, r := range c.Records {
		v = append(v, r.Subject, r.Start, r.End, r.Python, r.Production)
	}
	return v
}

func (c *Circuit) Define(api frontend.API) error {
	// Every comparison operand is constrained below. The extra unit covers
	// the comparator's a <= b transformation into a < b+1.
	cmp16 := cmp.NewBoundedComparator(api, big.NewInt(MaxDay+1), false)
	for _, v := range []frontend.Variable{c.WindowStart, c.WindowEnd, c.AsOf,
		c.MinDays, c.IssuedAt, c.ExpiresAt, c.CoverageStart, c.CoverageEnd} {
		api.ToBinary(v, 16)
	}
	api.AssertIsEqual(c.PolicyID, 1)
	cmp16.AssertIsLess(c.WindowStart, c.WindowEnd)
	cmp16.AssertIsLessEq(c.WindowEnd, c.AsOf)
	cmp16.AssertIsLess(0, c.MinDays)
	cmp16.AssertIsLessEq(c.IssuedAt, c.AsOf)
	cmp16.AssertIsLess(c.AsOf, c.ExpiresAt)
	cmp16.AssertIsLess(c.IssuedAt, c.ExpiresAt)
	cmp16.AssertIsLess(c.CoverageStart, c.CoverageEnd)
	api.AssertIsBoolean(c.Complete)
	api.ToBinary(c.Count, 2)
	cmp16.AssertIsLess(0, c.Count)
	api.AssertIsDifferent(c.HolderSecret, 0)
	api.AssertIsDifferent(c.Blind, 0)

	subject, err := hashCircuit(api, domainHolder, c.HolderSecret)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Subject, subject)
	api.AssertIsDifferent(c.Subject, 0)

	var active [MaxRecords]frontend.Variable
	for i, r := range c.Records {
		active[i] = cmp16.IsLess(i, c.Count)
		api.ToBinary(r.Start, 16)
		api.ToBinary(r.End, 16)
		api.AssertIsBoolean(r.Python)
		api.AssertIsEqual(api.Mul(r.Production, api.Sub(r.Production, 1), api.Sub(r.Production, 2)), 0)
		// Unused slots have exactly one encoding; count and every slot are signed.
		for _, v := range []frontend.Variable{r.Subject, r.Start, r.End, r.Python, r.Production} {
			api.AssertIsEqual(api.Mul(api.Sub(1, active[i]), v), 0)
		}
		api.AssertIsEqual(api.Mul(active[i], api.Sub(r.Subject, c.Subject)), 0)
		api.AssertIsEqual(api.Mul(active[i], api.Sub(1, cmp16.IsLess(r.Start, r.End))), 0)
		api.AssertIsEqual(api.Mul(active[i], api.Sub(1, cmp16.IsLessEq(c.CoverageStart, r.Start))), 0)
		api.AssertIsEqual(api.Mul(active[i], api.Sub(1, cmp16.IsLessEq(r.End, c.CoverageEnd))), 0)
	}

	digest, err := hashCircuit(api, c.signedValues()...)
	if err != nil {
		return err
	}
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	curve.AssertIsOnCurve(c.Key.A)
	curve.AssertIsOnCurve(c.Signature.R)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	if err := eddsa.Verify(curve, c.Signature, digest, c.Key, &h); err != nil {
		return err
	}
	commitment, err := hashCircuit(api, domainCommit, digest, c.Blind, c.RequestID)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Commitment, commitment)

	// Geometry is independent of the interpretation. Inclusion-exclusion
	// gives the union of at most three clipped half-open intervals.
	var spans [1 << MaxRecords]frontend.Variable
	for subset := 1; subset < len(spans); subset++ {
		start, end := c.WindowStart, c.WindowEnd
		for i, r := range c.Records {
			if subset&(1<<i) != 0 {
				start = api.Select(cmp16.IsLess(start, r.Start), r.Start, start)
				end = cmp16.Min(end, r.End)
			}
		}
		spans[subset] = api.Mul(cmp16.IsLess(start, end), api.Sub(end, start))
	}
	allYes, allNo := frontend.Variable(1), frontend.Variable(1)
	// This is a compile-time exhaustive loop, not a prover-supplied list.
	// Bits for unambiguous or unused records only repeat an interpretation.
	for interpretation := 0; interpretation < 1<<MaxRecords; interpretation++ {
		var qualifies [MaxRecords]frontend.Variable
		for i, r := range c.Records {
			role := api.Add(api.IsZero(api.Sub(r.Production, 1)),
				api.Mul((interpretation>>i)&1, api.IsZero(api.Sub(r.Production, 2))))
			qualifies[i] = api.Mul(active[i], r.Python, role)
		}
		days := frontend.Variable(0)
		for subset := 1; subset < len(spans); subset++ {
			term := spans[subset]
			for i := 0; i < MaxRecords; i++ {
				if subset&(1<<i) != 0 {
					term = api.Mul(term, qualifies[i])
				}
			}
			if bits.OnesCount(uint(subset))%2 == 1 {
				days = api.Add(days, term)
			} else {
				days = api.Sub(days, term)
			}
		}
		api.ToBinary(days, 16)
		pass := cmp16.IsLessEq(c.MinDays, days)
		allYes = api.Mul(allYes, pass)
		allNo = api.Mul(allNo, api.Sub(1, pass))
	}
	covered := api.Mul(c.Complete,
		cmp16.IsLessEq(c.CoverageStart, c.WindowStart),
		cmp16.IsLessEq(c.WindowEnd, c.CoverageEnd))
	answer := api.Select(allYes, 1, api.Select(api.Mul(allNo, covered), 0, 2))
	api.AssertIsEqual(c.Answer, answer)
	return nil
}

func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
