// controlplane starts the shared versioned HTTP control-plane API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/appender"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/backend/compat"
	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/controlplane"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "controlplane:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("controlplane", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	listen := flags.String("listen", "127.0.0.1:8080", "HTTP listen address")
	dataDir := flags.String("data-dir", ".benchmark", "directory for durable run data")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if err := validateListenAddress(*listen); err != nil {
		return err
	}
	store, driver, err := newControlPlane(*dataDir)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = driver.Shutdown(cleanupCtx)
		_ = store.Close()
	}()
	server := &http.Server{
		Addr:              *listen,
		Handler:           api.NewHandler(store),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	fmt.Fprintf(diagnostics, "control-plane listening on %s; durable data in %s\n", *listen, *dataDir)
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		if err := driver.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("backend shutdown: %w", err)
		}
		if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		fmt.Fprintln(diagnostics, "control-plane stopped")
		return nil
	}
}

func validateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("control plane has no authentication; listen address must be loopback")
	}
	return nil
}

func newControlPlane(dataDir string) (*api.Store, *controlplane.CompatDriver, error) {
	factory, err := durableEventLogFactory(dataDir)
	if err != nil {
		return nil, nil, err
	}
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, nil, err
	}
	key, err := developmentSigningKey(root)
	if err != nil {
		return nil, nil, err
	}
	backend := compat.New(compat.Config{RootDir: filepath.Join(root, "workloads")})
	driver := controlplane.NewCompatDriver(backend)
	if err := driver.ConfigureManifest(root, key); err != nil {
		return nil, nil, err
	}
	store, err := api.OpenStore(root, factory, driver)
	if err != nil {
		return nil, nil, err
	}
	if err := driver.BindStore(store); err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	if err := driver.ValidatePersistedBundles(); err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return store, driver, nil
}

func durableEventLogFactory(dataDir string) (api.EventLogFactory, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("data directory is required")
	}
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve data directory: %w", err)
	}
	runsRoot := filepath.Join(root, "runs")
	return func(run api.Run) (api.EventLog, error) {
		id, err := sanitizeRunID(run.ID)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(runsRoot, id, "tracked-events.jsonl")
		rel, err := filepath.Rel(runsRoot, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return nil, fmt.Errorf("run ID resolves outside data directory")
		}
		log, err := appender.Open(path)
		if err != nil {
			return nil, err
		}
		return log, nil
	}, nil
}

func sanitizeRunID(id string) (string, error) {
	if id == "" || len(id) > 128 || strings.TrimSpace(id) != id {
		return "", fmt.Errorf("invalid generated run ID %q", id)
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			continue
		}
		return "", fmt.Errorf("invalid generated run ID %q", id)
	}
	return id, nil
}
