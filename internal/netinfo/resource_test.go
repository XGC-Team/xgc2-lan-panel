package netinfo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCancelledCollectionStartsNoNativeWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CollectContext(ctx, Host{ReadFile: func(string) ([]byte, error) { t.Fatal("cancelled snapshot read OS"); return nil, nil }}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "effect")
	if _, err := RunCommand(ctx, "touch", marker); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled command: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("cancelled command started")
	}
}

func TestNativeOutputAndCommandLifetimeAreBounded(t *testing.T) {
	output, err := RunCommand(context.Background(), "head", "-c", "65537", "/dev/zero")
	if err == nil || len(output) > MaxNativeOutput {
		t.Fatalf("overflow became parser success: %d %v", len(output), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = RunCommand(ctx, "sleep", "2")
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("native query was not joined promptly: %v %v", err, time.Since(start))
	}
}
