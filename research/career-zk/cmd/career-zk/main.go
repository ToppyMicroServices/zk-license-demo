package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	zk "github.com/ToppyMicroServices/zk-license-demo/research/career-zk"
	"github.com/consensys/gnark/logger"
)

func run(args []string) (any, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("%w: command: setup, fixtures, prove, verify, demo", zk.ErrInput)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	out := flags.String("out", "", "new output file or directory")
	setupDir := flags.String("setup", "", "trusted setup directory")
	vkPath := flags.String("vk", "", "trusted verification key")
	credPath := flags.String("credential", "", "signed private credential JSON")
	holderPath := flags.String("holder", "", "private holder JSON")
	requestPath := flags.String("request", "", "verifier-owned request JSON")
	proofPath := flags.String("proof", "", "response JSON")
	runs := flags.Int("runs", 3, "repetitions per demo case")
	if err := flags.Parse(args[1:]); err != nil {
		return nil, err
	}
	if flags.NArg() != 0 {
		return nil, fmt.Errorf("%w: unexpected positional arguments", zk.ErrInput)
	}
	switch args[0] {
	case "setup":
		if *out == "" {
			return nil, fmt.Errorf("%w: -out is required", zk.ErrInput)
		}
		s, err := zk.NewSetup()
		if err != nil {
			return nil, err
		}
		if err := s.Save(*out); err != nil {
			return nil, err
		}
		id, err := zk.SetupID(s.VK)
		return map[string]any{"setup_id": id, "constraints": s.CS.GetNbConstraints()}, err
	case "fixtures":
		if *out == "" {
			return nil, fmt.Errorf("%w: -out is required", zk.ErrInput)
		}
		vk, err := zk.LoadVerifier(*vkPath)
		if err != nil {
			return nil, err
		}
		id, err := zk.SetupID(vk)
		if err != nil {
			return nil, err
		}
		_, fixtures, err := zk.SaveFixtures(*out, id)
		return map[string]any{"fixtures": len(fixtures)}, err
	case "prove":
		if *out == "" {
			return nil, fmt.Errorf("%w: -out is required", zk.ErrInput)
		}
		var cred zk.Credential
		var holder zk.Holder
		var q zk.Request
		if err := zk.ReadJSON(*credPath, &cred); err != nil {
			return nil, err
		}
		if err := zk.ReadJSON(*holderPath, &holder); err != nil {
			return nil, err
		}
		if err := zk.ReadJSON(*requestPath, &q); err != nil {
			return nil, err
		}
		s, err := zk.LoadSetup(*setupDir)
		if err != nil {
			return nil, err
		}
		response, err := s.Prove(cred, holder, q)
		if err != nil {
			return nil, err
		}
		if err := zk.WriteJSON(*out, response); err != nil {
			return nil, err
		}
		return map[string]any{"answer": response.Answer, "response": *out}, nil
	case "verify":
		var response zk.Response
		var q zk.Request
		if err := zk.ReadJSON(*requestPath, &q); err != nil {
			return nil, err
		}
		if err := zk.ReadJSON(*proofPath, &response); err != nil {
			return nil, err
		}
		vk, err := zk.LoadVerifier(*vkPath)
		if err != nil {
			return nil, err
		}
		if err := zk.Verify(vk, q, response); err != nil {
			return nil, err
		}
		return map[string]any{"verified": true, "answer": response.Answer}, nil
	case "demo":
		if *out == "" {
			return nil, fmt.Errorf("%w: -out is required", zk.ErrInput)
		}
		return zk.Demo(*out, *runs)
	default:
		return nil, fmt.Errorf("%w: unknown command", zk.ErrInput)
	}
}

func main() {
	// stdout is machine-readable and never contains witness debug traces.
	logger.Disable()
	value, err := run(os.Args[1:])
	if err != nil {
		code := "execution_error"
		for _, kind := range []error{zk.ErrInput, zk.ErrEvidence, zk.ErrUnsupported, zk.ErrVerification} {
			if errors.Is(err, kind) {
				code = kind.Error()
				break
			}
		}
		// Detailed constraint failures can contain witness values. Do not print
		// arbitrary backend error strings on the CLI's error path.
		_ = json.NewEncoder(os.Stderr).Encode(map[string]string{"error": code})
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		os.Exit(1)
	}
}
