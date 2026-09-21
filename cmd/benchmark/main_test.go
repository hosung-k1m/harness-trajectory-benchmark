package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/hosung-k1m/harness-trajectory-benchmark/pkg/client"
)

func TestRunHelpVersionAndSchemaOutput(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"--version"}, {"schema", "show"}} {
		var out, err bytes.Buffer
		if got := run(args, &out, &err); got != exitOK {
			t.Fatalf("%v got %d: %s", args, got, err.String())
		}
		if out.Len() == 0 || err.Len() != 0 {
			t.Fatalf("%v output routing out=%q err=%q", args, out.String(), err.String())
		}
	}
}

func TestResultMapsTypedErrorCodeToStableExitCode(t *testing.T) {
	for code, want := range map[string]int{"validation": exitValidation, "execution": exitExecution, "policy": exitPolicy, "telemetry": exitTelemetry, "verification": exitVerification, "infrastructure": exitInfrastructure} {
		var out, stderr bytes.Buffer
		got := result(&out, &stderr, nil, &client.APIError{StatusCode: 400, Code: code, Message: "no"})
		if got != want {
			t.Fatalf("%s got %d want %d", code, got, want)
		}
		if out.Len() != 0 || !strings.Contains(stderr.String(), `"error":"`+code+`"`) {
			t.Fatalf("bad output for %s", code)
		}
	}
	var out, stderr bytes.Buffer
	if got := result(&out, &stderr, nil, errors.New("offline")); got != exitInfrastructure {
		t.Fatal(got)
	}
}
