// benchmark is the non-interactive control-plane CLI.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/bundle"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/openaivalidator"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
)

const cliVersion = "0.1.0"

var errParametersFileAccess = errors.New("parameters file access")

const (
	exitOK             = 0
	exitValidation     = 2
	exitExecution      = 3
	exitPolicy         = 4
	exitTelemetry      = 5
	exitVerification   = 6
	exitInfrastructure = 7
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, err io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		usage(out)
		return exitOK
	}
	if args[0] == "--version" || args[0] == "version" {
		emit(out, map[string]string{"cliVersion": cliVersion, "apiVersion": api.Version})
		return exitOK
	}
	endpoint := os.Getenv("BENCHMARK_API_URL")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	c := client.New(endpoint)
	ctx := context.Background()
	switch args[0] {
	case "run":
		return runCommands(ctx, c, args[1:], out, err)
	case "schema":
		return schemaCommands(args[1:], out, err)
	case "backend":
		if len(args) > 1 && args[1] == "list" {
			v, e := c.Backends(ctx)
			return result(out, err, v, e)
		}
		return unsupported(out, err, "backend", args[1:])
	case "trajectory":
		return trajectoryCommands(ctx, c, args[1:], out, err)
	case "evidence":
		return evidenceCommands(ctx, c, args[1:], out, err)
	case "result":
		return resultCommands(ctx, c, args[1:], out, err)
	case "harness", "suite":
		return unsupported(out, err, args[0], args[1:])
	default:
		diagnostic(err, "validation", "unknown command")
		usage(err)
		return exitValidation
	}
}
func trajectoryCommands(ctx context.Context, c *client.Client, args []string, out, err io.Writer) int {
	if len(args) == 0 || args[0] == "--help" {
		fmt.Fprintln(out, "benchmark trajectory get|stream|export <run-id>")
		return exitOK
	}
	if len(args) != 2 {
		diagnostic(err, "validation", "trajectory command requires a run id")
		return exitValidation
	}
	switch args[0] {
	case "get":
		v, e := c.Trajectory(ctx, args[1], "", 100)
		return result(out, err, v, e)
	case "stream":
		v, e := c.Events(ctx, args[1])
		if e != nil {
			return result(out, err, nil, e)
		}
		for _, event := range v {
			emit(out, event)
		}
		return exitOK
	case "export":
		v, e := c.ExportTrajectory(ctx, args[1])
		if e != nil {
			return result(out, err, nil, e)
		}
		_, _ = out.Write(v)
		return exitOK
	default:
		diagnostic(err, "validation", "unknown trajectory command")
		return exitValidation
	}
}

func evidenceCommands(ctx context.Context, c *client.Client, args []string, out, err io.Writer) int {
	if len(args) == 0 || args[0] == "--help" {
		fmt.Fprintln(out, "benchmark evidence inspect|verify|export <run-id>; validate --bundle <file> --public-key <file> [--extract <dir>]")
		return exitOK
	}
	if args[0] == "validate" {
		return evidenceValidate(args[1:], out, err)
	}
	if len(args) != 2 {
		diagnostic(err, "validation", "evidence command requires a run id")
		return exitValidation
	}
	switch args[0] {
	case "inspect":
		v, e := c.Evidence(ctx, args[1])
		return result(out, err, v, e)
	case "verify":
		// Report the control plane's recorded verifier outcome, but keep the
		// verification exit code meaningful to non-interactive callers.
		v, e := c.Evidence(ctx, args[1])
		if e != nil {
			return result(out, err, nil, e)
		}
		emit(out, v)
		if v.Verification == nil || !v.Verification.Eligible || v.Verification.Status != "verified" {
			diagnostic(err, "verification", "run is not verified")
			return exitVerification
		}
		return exitOK
	case "export":
		v, e := c.ExportEvidence(ctx, args[1])
		if e != nil {
			return result(out, err, nil, e)
		}
		if _, werr := out.Write(v); werr != nil {
			diagnostic(err, "infrastructure", "write evidence bundle: "+werr.Error())
			return exitInfrastructure
		}
		return exitOK
	default:
		diagnostic(err, "validation", "unknown evidence command")
		return exitValidation
	}
}

func evidenceValidate(args []string, out, err io.Writer) int {
	fs := flag.NewFlagSet("evidence validate", flag.ContinueOnError)
	fs.SetOutput(err)
	bundlePath := fs.String("bundle", "", "evidence bundle file")
	keyPath := fs.String("public-key", "", "raw Ed25519 public key file")
	extract := fs.String("extract", "", "extract bundle files into this empty directory")
	if e := fs.Parse(args); e != nil {
		return exitValidation
	}
	if fs.NArg() != 0 {
		diagnostic(err, "validation", "unexpected argument "+fs.Arg(0))
		return exitValidation
	}
	if *bundlePath == "" || *keyPath == "" {
		diagnostic(err, "validation", "--bundle and --public-key are required")
		return exitValidation
	}
	publicKey, e := os.ReadFile(*keyPath)
	if e != nil {
		diagnostic(err, "infrastructure", "read public key: "+e.Error())
		return exitInfrastructure
	}
	if len(publicKey) != ed25519.PublicKeySize {
		diagnostic(err, "validation", "public key is not a raw Ed25519 key")
		return exitValidation
	}
	raw, e := os.ReadFile(*bundlePath)
	if e != nil {
		diagnostic(err, "infrastructure", "read bundle: "+e.Error())
		return exitInfrastructure
	}
	decoded, e := bundle.Decode(bytes.NewReader(raw))
	if e != nil {
		diagnostic(err, "verification", e.Error())
		return exitVerification
	}
	result, e := bundle.Validate(decoded, ed25519.PublicKey(publicKey))
	if e != nil {
		diagnostic(err, "verification", e.Error())
		return exitVerification
	}
	if *extract != "" {
		if e := bundle.Extract(decoded, *extract, ed25519.PublicKey(publicKey)); e != nil {
			diagnostic(err, "infrastructure", "extract bundle: "+e.Error())
			return exitInfrastructure
		}
	}
	emit(out, result)
	return exitOK
}

func resultCommands(ctx context.Context, c *client.Client, args []string, out, err io.Writer) int {
	if len(args) == 0 || args[0] == "--help" {
		fmt.Fprintln(out, "benchmark result show <run-id>")
		return exitOK
	}
	if len(args) != 2 || args[0] != "show" {
		diagnostic(err, "validation", "result supports show <run-id>")
		return exitValidation
	}
	v, e := c.Evidence(ctx, args[1])
	return result(out, err, v, e)
}
func runCommands(ctx context.Context, c *client.Client, args []string, out, err io.Writer) int {
	if len(args) == 0 || args[0] == "--help" {
		fmt.Fprintln(out, "benchmark run create|start|stop|status|follow|list")
		return 0
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("run create", flag.ContinueOnError)
		fs.SetOutput(err)
		h := fs.String("harness", "", "harness identifier")
		s := fs.String("suite", "", "suite identifier")
		b := fs.String("backend", "", "backend identifier")
		k := fs.String("idempotency-key", "", "retry-safe mutation key")
		parametersFile := fs.String("parameters-file", "", "strict JSON object; use - for stdin")
		verified := fs.Bool("verified", false, "request verified-run admission")
		if e := fs.Parse(args[1:]); e != nil {
			return exitValidation
		}
		if *h == "" || *s == "" || *b == "" {
			diagnostic(err, "validation", "--harness, --suite and --backend are required")
			return exitValidation
		}
		parameters, e := readParametersFile(*parametersFile, os.Stdin)
		if e != nil {
			if errors.Is(e, errParametersFileAccess) {
				diagnostic(err, "infrastructure", "cannot read --parameters-file")
				return exitInfrastructure
			}
			diagnostic(err, "validation", "invalid --parameters-file JSON object")
			return exitValidation
		}
		v, e := c.CreateRun(ctx, client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: *h, Suite: *s, Backend: *b, Parameters: parameters, Verified: *verified}, IdempotencyKey: *k})
		return result(out, err, v, e)
	case "start", "stop":
		if len(args) < 2 {
			diagnostic(err, "validation", "run id is required")
			return exitValidation
		}
		fs := flag.NewFlagSet("run "+args[0], flag.ContinueOnError)
		fs.SetOutput(err)
		k := fs.String("idempotency-key", "", "retry-safe mutation key")
		reason := fs.String("reason", "", "reason")
		if e := fs.Parse(args[2:]); e != nil {
			return exitValidation
		}
		v, e := c.Lifecycle(ctx, args[1], client.LifecycleMutation{Action: args[0], IdempotencyKey: *k, Reason: *reason})
		return result(out, err, v, e)
	case "status":
		if len(args) != 2 {
			diagnostic(err, "validation", "run id is required")
			return exitValidation
		}
		v, e := c.GetRun(ctx, args[1])
		return result(out, err, v, e)
	case "list":
		v, e := c.ListRuns(ctx, "", 100)
		return result(out, err, v, e)
	case "follow":
		if len(args) < 2 {
			diagnostic(err, "validation", "run id is required")
			return exitValidation
		}
		fs := flag.NewFlagSet("run follow", flag.ContinueOnError)
		fs.SetOutput(err)
		fromSeq := fs.Uint64("from-seq", 0, "resume after this event sequence")
		timeout := fs.Duration("timeout", 0, "optional follow timeout, for example 30s")
		if e := fs.Parse(args[2:]); e != nil {
			return exitValidation
		}
		if *timeout < 0 {
			diagnostic(err, "validation", "--timeout cannot be negative")
			return exitValidation
		}
		return followRun(ctx, c, args[1], *fromSeq, *timeout, out, err)
	default:
		diagnostic(err, "validation", "unknown run command")
		return exitValidation
	}
}

func followRun(ctx context.Context, c *client.Client, id string, after uint64, timeout time.Duration, out, diagnostics io.Writer) int {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	poll := func() int {
		log, e := c.Events(ctx, id)
		if e != nil {
			return result(out, diagnostics, nil, e)
		}
		for _, event := range log {
			if event.Seq <= after {
				continue
			}
			if event.Seq != after+1 {
				diagnostic(diagnostics, "telemetry", "trajectory sequence gap while following")
				return exitTelemetry
			}
			emit(out, event)
			after = event.Seq
		}
		return exitOK
	}
	for {
		if code := poll(); code != exitOK {
			return code
		}
		run, e := c.GetRun(ctx, id)
		if e != nil {
			return result(out, diagnostics, nil, e)
		}
		if run.Status == "completed" || run.Status == "failed" || run.Status == "stopped" {
			return poll()
		}
		select {
		case <-ctx.Done():
			diagnostic(diagnostics, "execution", "run follow timed out or was canceled")
			return exitExecution
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// readParametersFile accepts exactly one JSON object and rejects duplicate keys
// at every nesting level. It deliberately returns generic errors so parameter
// contents (which can contain credentials) do not reach diagnostics.
func readParametersFile(path string, stdin io.Reader) (map[string]json.RawMessage, error) {
	if path == "" {
		return nil, nil
	}
	var reader io.Reader = stdin
	var file *os.File
	if path != "-" {
		var err error
		file, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("%w: open", errParametersFileAccess)
		}
		defer file.Close()
		reader = file
	}
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("%w: read", errParametersFileAccess)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := validateJSONObject(decoder); err != nil {
		return nil, err
	}
	if err := requireEOF(decoder); err != nil {
		return nil, err
	}
	var parameters map[string]json.RawMessage
	if err := json.Unmarshal(raw, &parameters); err != nil {
		return nil, err
	}
	return parameters, nil
}

func validateJSONObject(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return errors.New("parameters must be an object")
	}
	return validateObjectBody(decoder)
}
func validateObjectBody(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("invalid object key")
		}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate object key")
		}
		seen[key] = struct{}{}
		if err := validateJSONValue(decoder); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return errors.New("invalid object terminator")
	}
	return nil
}
func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		return validateObjectBody(decoder)
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if end, ok := token.(json.Delim); !ok || end != ']' {
			return errors.New("invalid array terminator")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
func requireEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON")
		}
		return err
	}
	return nil
}
func schemaCommands(args []string, out, err io.Writer) int {
	if len(args) == 0 || args[0] == "--help" {
		fmt.Fprintln(out, "benchmark schema show|validate")
		return 0
	}
	switch args[0] {
	case "show":
		emit(out, map[string]any{"schema": api.OpenAIChatCompletionsSchema, "apiVersion": api.Version})
		return 0
	case "validate":
		fs := flag.NewFlagSet("schema validate", flag.ContinueOnError)
		fs.SetOutput(err)
		kind := fs.String("kind", "", "request, response, chunk, tool, or usage")
		file := fs.String("file", "", "JSON input file; use - for stdin")
		if e := fs.Parse(args[1:]); e != nil {
			return exitValidation
		}
		if *kind == "" || *file == "" {
			diagnostic(err, "validation", "--kind and --file are required")
			return exitValidation
		}
		var r io.Reader = os.Stdin
		if *file != "-" {
			f, e := os.Open(*file)
			if e != nil {
				diagnostic(err, "infrastructure", e.Error())
				return exitInfrastructure
			}
			defer f.Close()
			r = f
		}
		raw, e := io.ReadAll(r)
		if e == nil {
			e = openaivalidator.Validate(*kind, raw)
		}
		if e != nil {
			diagnostic(err, "validation", e.Error())
			return exitValidation
		}
		emit(out, map[string]string{"schema": api.OpenAIChatCompletionsSchema, "kind": *kind, "valid": "true"})
		return 0
	default:
		diagnostic(err, "validation", "unknown schema command")
		return exitValidation
	}
}
func unsupported(out, err io.Writer, group string, args []string) int {
	if len(args) > 0 && args[0] == "--help" {
		fmt.Fprintf(out, "benchmark %s commands are reserved by API v1\n", group)
		return 0
	}
	diagnostic(err, "execution", group+" command is not implemented in Phase 0")
	return exitExecution
}
func result(out, err io.Writer, v any, e error) int {
	if e == nil {
		emit(out, v)
		return 0
	}
	code := "infrastructure"
	var apiErr *client.APIError
	if errors.As(e, &apiErr) && apiErr.Code != "" {
		code = apiErr.Code
	}
	diagnostic(err, code, e.Error())
	switch code {
	case "validation":
		return exitValidation
	case "execution":
		return exitExecution
	case "policy":
		return exitPolicy
	case "telemetry":
		return exitTelemetry
	case "verification":
		return exitVerification
	default:
		return exitInfrastructure
	}
}
func emit(w io.Writer, v any) { _ = json.NewEncoder(w).Encode(v) }
func diagnostic(w io.Writer, code, msg string) {
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "message": msg})
}
func usage(w io.Writer) {
	fmt.Fprintln(w, strings.TrimSpace(`benchmark: agent-native benchmark control plane
Usage: benchmark <family> <command> [flags]
Families: harness, suite, run, trajectory, evidence, result, backend, schema
Run: create, start, stop, status, follow, list
Run create flags: --harness --suite --backend [--parameters-file path|-] [--verified]
Use --version or "schema show" for compatibility discovery.`))
}
