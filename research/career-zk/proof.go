package careerzk

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

const ProofFormat = "career-zk/groth16-bn254/v1"

// No private record, holder identifier, signature, or deterministic manifest
// digest is included in the response.
type Response struct {
	Format     string `json:"format"`
	Answer     Answer `json:"answer"`
	Commitment string `json:"commitment"`
	Proof      string `json:"proof"`
}

type Setup struct {
	CS constraint.ConstraintSystem
	PK groth16.ProvingKey
	VK groth16.VerifyingKey
}

func NewSetup() (*Setup, error) {
	cs, err := Compile()
	if err != nil {
		return nil, err
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, err
	}
	return &Setup{cs, pk, vk}, nil
}

func marshalBinary(value io.WriterTo) ([]byte, error) {
	var b bytes.Buffer
	_, err := value.WriteTo(&b)
	return b.Bytes(), err
}

func SetupID(vk groth16.VerifyingKey) (string, error) {
	b, err := marshalBinary(vk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func checkSetup(vk groth16.VerifyingKey, q Request) error {
	id, err := SetupID(vk)
	if err != nil {
		return err
	}
	if id != q.SetupID {
		return fmt.Errorf("%w: trusted setup does not match request", ErrVerification)
	}
	return nil
}

func (s *Setup) Prove(cred Credential, holder Holder, q Request) (Response, error) {
	if err := checkSetup(s.VK, q); err != nil {
		return Response{}, err
	}
	c, answer, err := makeAssignment(cred, holder, q)
	if err != nil {
		return Response{}, err
	}
	w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		return Response{}, err
	}
	proof, err := groth16.Prove(s.CS, s.PK, w)
	if err != nil {
		return Response{}, fmt.Errorf("proof generation: %w", err)
	}
	b, err := marshalBinary(proof)
	if err != nil {
		return Response{}, err
	}
	response := Response{ProofFormat, answer, c.Commitment.(*big.Int).String(), base64.StdEncoding.EncodeToString(b)}
	// Catch mismatched/corrupt local setup artifacts before returning a result.
	if err := Verify(s.VK, q, response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func Verify(vk groth16.VerifyingKey, expected Request, response Response) error {
	if err := expected.Validate(); err != nil {
		return err
	}
	if err := checkSetup(vk, expected); err != nil {
		return err
	}
	if response.Format != ProofFormat {
		return fmt.Errorf("%w: unsupported proof format", ErrVerification)
	}
	c, err := publicAssignment(expected, response.Answer, response.Commitment)
	if err != nil {
		return err
	}
	// This fixed circuit has no gnark commitment gadgets. Its compressed proof
	// is 32+64+32 bytes, a zero uint32 commitment count, and a 32-byte point.
	// Check framing BEFORE deserialization, which otherwise reads slice lengths
	// from untrusted input. Dependency changes must revalidate this format.
	b, err := base64.StdEncoding.Strict().DecodeString(response.Proof)
	if err != nil || len(b) != 164 || base64.StdEncoding.EncodeToString(b) != response.Proof ||
		!bytes.Equal(b[128:132], []byte{0, 0, 0, 0}) {
		return fmt.Errorf("%w: proof encoding", ErrVerification)
	}
	proof := groth16.NewProof(ecc.BN254)
	reader := bytes.NewReader(b)
	if _, err := proof.ReadFrom(reader); err != nil || reader.Len() != 0 {
		return fmt.Errorf("%w: invalid proof points", ErrVerification)
	}
	canonical, err := marshalBinary(proof)
	if err != nil || !bytes.Equal(canonical, b) {
		return fmt.Errorf("%w: noncanonical proof", ErrVerification)
	}
	public, err := frontend.NewWitness(c, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		return fmt.Errorf("%w: proof does not match expected statement", ErrVerification)
	}
	return nil
}

// Setup files are locally trusted artifacts, not inputs supplied by a prover.
// Fresh directories and exclusive writes avoid overwriting existing keys.
func (s *Setup) Save(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	for _, item := range []struct {
		name  string
		value io.WriterTo
	}{{"circuit.r1cs", s.CS}, {"proving.key", s.PK}, {"verifying.key", s.VK}} {
		b, err := marshalBinary(item.value)
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(dir, item.name), b); err != nil {
			return err
		}
	}
	return nil
}

func readBinary(path string, value io.ReaderFrom) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// These files must come from the verifier's trusted local setup.
	if _, err := value.ReadFrom(f); err != nil {
		return err
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); n != 0 || err != io.EOF {
		return fmt.Errorf("%w: trailing setup data", ErrInput)
	}
	return nil
}

func LoadVerifier(path string) (groth16.VerifyingKey, error) {
	vk := groth16.NewVerifyingKey(ecc.BN254)
	if err := readBinary(path, vk); err != nil {
		return nil, err
	}
	return vk, nil
}

func LoadSetup(dir string) (*Setup, error) {
	s := &Setup{groth16.NewCS(ecc.BN254), groth16.NewProvingKey(ecc.BN254), nil}
	if err := readBinary(filepath.Join(dir, "circuit.r1cs"), s.CS); err != nil {
		return nil, err
	}
	if err := readBinary(filepath.Join(dir, "proving.key"), s.PK); err != nil {
		return nil, err
	}
	var err error
	s.VK, err = LoadVerifier(filepath.Join(dir, "verifying.key"))
	return s, err
}
