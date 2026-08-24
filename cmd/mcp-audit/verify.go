package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/P4ST4S/mcp-audit/internal/audit/integrity"
	auditverify "github.com/P4ST4S/mcp-audit/internal/audit/verify"
)

const verifyUsage = `usage: mcp-audit verify <audit.jsonl|audit.db> [--format auto|jsonl|sqlite] [--key-id ID] [--json]`

type verifyOptions struct {
	path   string
	format auditverify.Format
	keyID  string
	json   bool
	help   bool
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
	secret := os.Getenv("MCP_AUDIT_SIGNING_SECRET")
	if secret == "" {
		secret = os.Getenv("AUDIT_SECRET")
	}
	keys := make(map[string]string)
	if secret != "" {
		keys[options.keyID] = secret
	}
	result, err := auditverify.VerifyPath(options.path, auditverify.Config{
		Format: options.format,
		Keys:   keys,
	})
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
		case argument == "--format" || argument == "--key-id":
			if index+1 >= len(args) {
				return verifyOptions{}, fmt.Errorf("%s requires a value", argument)
			}
			index++
			if argument == "--format" {
				options.format = auditverify.Format(args[index])
			} else {
				options.keyID = args[index]
			}
		case strings.HasPrefix(argument, "--format="):
			options.format = auditverify.Format(strings.TrimPrefix(argument, "--format="))
		case strings.HasPrefix(argument, "--key-id="):
			options.keyID = strings.TrimPrefix(argument, "--key-id=")
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
