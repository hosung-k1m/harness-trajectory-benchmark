package bundle

import "testing"

func TestValidBundlePath(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"simple file", "verification.json", false},
		{"nested file", "workload/raw-records.bin", false},
		{"empty", "", true},
		{"leading traversal", "../escape", true},
		{"nested traversal", "workload/../../../etc/passwd", true},
		{"interior traversal", "workload/../secret", true},
		{"absolute", "/etc/passwd", true},
		{"backslash", `workload\raw`, true},
		{"colon", "a:b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validBundlePath(tc.path)
			if tc.wantErr && err == nil {
				t.Fatalf("path %q accepted", tc.path)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("path %q rejected: %v", tc.path, err)
			}
		})
	}
}
