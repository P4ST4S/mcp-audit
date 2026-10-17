package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
	auditverify "github.com/P4ST4S/mcp-audit/internal/audit/verify"
	"github.com/gowebpki/jcs"
)

const verifyUsage = `usage: mcp-audit verify <audit.jsonl|audit.db> [--format auto|jsonl|sqlite] [--key-id ID] [--require-integrity-v2] [--checkpoint FILE] [--json]`

const checkpointUsage = `usage: mcp-audit checkpoint <audit.jsonl|audit.db> --output FILE [--format auto|jsonl|sqlite] [--key-id ID] [--json]`

type verifyOptions struct {
	path       string
	format     auditverify.Format
	keyID      string
	json       bool
	help       bool
	requireV2  bool
	checkpoint string
	output     string
}

func runVerifyCommand(args []string, stdout, stderr io.Writer) int {
	options, err := parseVerifyOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n%s\n", err, verifyUsage)
		return 2
	}
	if options.help {
		fmt.Fprintln(stdout, verifyUsage)
		return 0
	}
	if options.output != "" {
		fmt.Fprintln(stderr, "error: --output is only valid for checkpoint")
		return 2
	}
	secret := os.Getenv("MCP_AUDIT_SIGNING_SECRET")
	if secret == "" {
		secret = os.Getenv("AUDIT_SECRET")
	}
	keys := make(map[string]string)
	if secret != "" {
		keys[options.keyID] = secret
	}
	config := auditverify.Config{
		Format:             options.format,
		Keys:               keys,
		RequireIntegrityV2: options.requireV2,
	}
	if options.checkpoint != "" {
		checkpoint, err := loadCheckpoint(options.checkpoint)
		if err != nil {
			fmt.Fprintf(stderr, "read checkpoint: %v\n", err)
			return 2
		}
		config.Checkpoint = &checkpoint
	}
	result, err := auditverify.VerifyPath(options.path, config)
	if err != nil {
		fmt.Fprintf(stderr, "verification failed: %v\n", err)
		return 2
	}
	if options.json {
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintf(stderr, "write verification result: %v\n", err)
			return 2
		}
	} else {
		fmt.Fprintf(stdout, "verified: %d\ninvalid: %d\nlegacy: %d\nunsigned: %d\n",
			result.Verified, result.Invalid, result.Legacy, result.Unsigned)
	}
	if result.FirstError != "" {
		fmt.Fprintf(stderr, "first error: %s\n", result.FirstError)
	}
	if !result.Clean() {
		return 1
	}
	return 0
}

func parseVerifyOptions(args []string) (verifyOptions, error) {
	options := verifyOptions{format: auditverify.FormatAuto, keyID: integrity.DefaultKeyID}
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--help" || argument == "-h":
			options.help = true
		case argument == "--json":
			options.json = true
		case argument == "--require-integrity-v2":
			options.requireV2 = true
		case argument == "--format" || argument == "--key-id" || argument == "--checkpoint" || argument == "--output":
			if index+1 >= len(args) {
				return verifyOptions{}, fmt.Errorf("%s requires a value", argument)
			}
			index++
			if strings.HasPrefix(args[index], "--") || args[index] == "" {
				return verifyOptions{}, fmt.Errorf("%s requires a value", argument)
			}
			switch argument {
			case "--format":
				options.format = auditverify.Format(args[index])
			case "--key-id":
				options.keyID = args[index]
			case "--checkpoint":
				options.checkpoint = args[index]
			case "--output":
				options.output = args[index]
			}
		case strings.HasPrefix(argument, "--format="):
			options.format = auditverify.Format(strings.TrimPrefix(argument, "--format="))
		case strings.HasPrefix(argument, "--key-id="):
			options.keyID = strings.TrimPrefix(argument, "--key-id=")
		case strings.HasPrefix(argument, "--checkpoint="):
			options.checkpoint = strings.TrimPrefix(argument, "--checkpoint=")
			if options.checkpoint == "" {
				return verifyOptions{}, fmt.Errorf("--checkpoint requires a value")
			}
		case strings.HasPrefix(argument, "--output="):
			options.output = strings.TrimPrefix(argument, "--output=")
			if options.output == "" {
				return verifyOptions{}, fmt.Errorf("--output requires a value")
			}
		case strings.HasPrefix(argument, "-"):
			return verifyOptions{}, fmt.Errorf("unknown option %q", argument)
		default:
			if options.path != "" {
				return verifyOptions{}, fmt.Errorf("expected one audit path, got %q and %q", options.path, argument)
			}
			options.path = argument
		}
	}
	if options.help {
		return options, nil
	}
	if options.path == "" {
		return verifyOptions{}, fmt.Errorf("audit path is required")
	}
	if options.keyID == "" {
		return verifyOptions{}, fmt.Errorf("key ID must not be empty")
	}
	return options, nil
}

func loadCheckpoint(path string) (auditverify.Checkpoint, error) {
	file, err := os.Open(path)
	if err != nil {
		return auditverify.Checkpoint{}, err
	}
	defer file.Close()
	const maxCheckpointBytes = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(file, maxCheckpointBytes+1))
	if err != nil {
		return auditverify.Checkpoint{}, err
	}
	if len(raw) > maxCheckpointBytes {
		return auditverify.Checkpoint{}, fmt.Errorf("checkpoint exceeds 64 KiB")
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return auditverify.Checkpoint{}, fmt.Errorf("invalid checkpoint JSON: %w", err)
	}
	var checkpoint auditverify.Checkpoint
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&checkpoint)
	return checkpoint, err
}

func runCheckpointCommand(args []string, stdout, stderr io.Writer) int {
	options, err := parseVerifyOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n%s\n", err, checkpointUsage)
		return 2
	}
	if options.help {
		fmt.Fprintln(stdout, checkpointUsage)
		return 0
	}
	if options.output == "" || options.checkpoint != "" || options.requireV2 {
		fmt.Fprintf(stderr, "error: checkpoint requires --output and accepts no verification flags\n%s\n", checkpointUsage)
		return 2
	}
	secret := os.Getenv("MCP_AUDIT_SIGNING_SECRET")
	if secret == "" {
		secret = os.Getenv("AUDIT_SECRET")
	}
	checkpoint, err := auditverify.CreateCheckpoint(options.path, auditverify.Config{
		Format: options.format, Keys: map[string]string{options.keyID: secret},
	}, options.keyID)
	if err != nil {
		fmt.Fprintf(stderr, "checkpoint failed: %v\n", err)
		return 2
	}
	raw, err := json.MarshalIndent(checkpoint, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "encode checkpoint: %v\n", err)
		return 2
	}
	file, err := os.OpenFile(options.output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		fmt.Fprintf(stderr, "create checkpoint: %v\n", err)
		return 2
	}
	_, writeErr := file.Write(append(raw, '\n'))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		fmt.Fprintf(stderr, "write checkpoint: %v; close: %v\n", writeErr, closeErr)
		return 2
	}
	if options.json {
		if err := json.NewEncoder(stdout).Encode(checkpoint); err != nil {
			fmt.Fprintf(stderr, "write checkpoint result: %v\n", err)
			return 2
		}
	} else {
		fmt.Fprintf(stdout, "checkpoint: %s\nrecords: %d\n", options.output, checkpoint.Records)
	}
	return 0
}
