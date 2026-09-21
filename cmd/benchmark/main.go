// benchmark is the non-interactive control-plane CLI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/openaivalidator"
	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
)

const cliVersion = "0.1.0"
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
	case "harness", "suite", "trajectory", "evidence", "result":
		return unsupported(out, err, args[0], args[1:])
	default:
		diagnostic(err, "validation", "unknown command")
		usage(err)
		return exitValidation
	}
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
		if e := fs.Parse(args[1:]); e != nil {
			return exitValidation
		}
		if *h == "" || *s == "" || *b == "" {
			diagnostic(err, "validation", "--harness, --suite and --backend are required")
			return exitValidation
		}
		v, e := c.CreateRun(ctx, client.CreateRunRequest{Spec: client.RunSpec{SchemaVersion: "v1", Harness: *h, Suite: *s, Backend: *b}, IdempotencyKey: *k})
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
		if len(args) != 2 {
			diagnostic(err, "validation", "run id is required")
			return exitValidation
		}
		v, e := c.Events(ctx, args[1])
		if e != nil {
			return result(out, err, nil, e)
		}
		for _, event := range v {
			emit(out, event)
		}
		return 0
	default:
		diagnostic(err, "validation", "unknown run command")
		return exitValidation
	}
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
Use --version or "schema show" for compatibility discovery.`))
}
