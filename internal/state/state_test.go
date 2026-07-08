// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package state

import (
	"testing"

	"github.com/blinklabs-io/cdnsd/internal/config"
)

func TestCloseStopsGCAndClosesDB(t *testing.T) {
	cfg := config.GetConfig()
	oldState := cfg.State
	cfg.State.Directory = t.TempDir()
	t.Cleanup(func() {
		cfg.State = oldState
	})

	s := &State{}
	if err := s.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if s.db == nil {
		t.Fatal("Load() did not open DB")
	}
	if s.gcTimer == nil {
		t.Fatal("Load() did not start GC timer")
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if s.db != nil {
		t.Fatal("Close() did not clear DB handle")
	}
	if s.gcTimer != nil {
		t.Fatal("Close() did not clear GC timer")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
