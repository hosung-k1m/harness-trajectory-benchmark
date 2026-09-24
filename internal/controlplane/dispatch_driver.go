package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/hosung-k1m/harness-trajectory-benchmark/internal/api"
)

type DispatchDriver struct {
	byBackend map[string]api.RunDriver

	mu   sync.Mutex
	runs map[string]api.RunDriver
}

var _ api.RunDriver = (*DispatchDriver)(nil)

func NewDispatchDriver(drivers map[string]api.RunDriver) *DispatchDriver {
	byBackend := make(map[string]api.RunDriver, len(drivers))
	for name, driver := range drivers {
		if driver == nil {
			continue
		}
		byBackend[name] = driver
	}
	return &DispatchDriver{byBackend: byBackend, runs: make(map[string]api.RunDriver)}
}

func (d *DispatchDriver) Prepare(ctx context.Context, run api.Run) error {
	driver, ok := d.byBackend[run.Spec.Backend]
	if !ok {
		return fmt.Errorf("unknown backend %q", run.Spec.Backend)
	}
	if err := driver.Prepare(ctx, run); err != nil {
		return err
	}
	d.mu.Lock()
	d.runs[run.ID] = driver
	d.mu.Unlock()
	return nil
}

func (d *DispatchDriver) Start(ctx context.Context, runID string) error {
	driver, ok := d.route(runID)
	if !ok {
		return fmt.Errorf("run %q is not prepared", runID)
	}
	return driver.Start(ctx, runID)
}

func (d *DispatchDriver) Stop(ctx context.Context, runID, reason string) error {
	driver, ok := d.route(runID)
	if !ok {
		return fmt.Errorf("run %q is not prepared", runID)
	}
	return driver.Stop(ctx, runID, reason)
}

func (d *DispatchDriver) route(runID string) (api.RunDriver, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	driver, ok := d.runs[runID]
	return driver, ok
}

func (d *DispatchDriver) Abort(ctx context.Context, runID string) error {
	d.mu.Lock()
	driver, ok := d.runs[runID]
	d.mu.Unlock()
	if !ok {
		return nil
	}
	if a, supported := driver.(interface {
		Abort(context.Context, string) error
	}); supported {
		if err := a.Abort(ctx, runID); err != nil {
			return err
		}
	}
	d.mu.Lock()
	delete(d.runs, runID)
	d.mu.Unlock()
	return nil
}

func (d *DispatchDriver) BindStore(store *api.Store) error {
	if store == nil {
		return errors.New("control-plane store is required")
	}
	for _, driver := range d.sorted() {
		b, ok := driver.(interface {
			BindStore(*api.Store) error
		})
		if !ok {
			continue
		}
		if err := b.BindStore(store); err != nil {
			return err
		}
	}
	return nil
}

func (d *DispatchDriver) Shutdown(ctx context.Context) error {
	seen := map[api.RunDriver]bool{}
	var first error
	for _, driver := range d.sorted() {
		if seen[driver] {
			continue
		}
		seen[driver] = true
		s, ok := driver.(interface {
			Shutdown(context.Context) error
		})
		if !ok {
			continue
		}
		if err := s.Shutdown(ctx); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (d *DispatchDriver) Close() error { return d.Shutdown(context.Background()) }

func (d *DispatchDriver) sorted() []api.RunDriver {
	names := make([]string, 0, len(d.byBackend))
	for name := range d.byBackend {
		names = append(names, name)
	}
	sort.Strings(names)
	drivers := make([]api.RunDriver, 0, len(names))
	for _, name := range names {
		drivers = append(drivers, d.byBackend[name])
	}
	return drivers
}
