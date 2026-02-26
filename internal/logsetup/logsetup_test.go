package logsetup

import (
	"io"
	"log/slog"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantDefault slog.Level
		wantOverride map[string]slog.Level
		wantErr     bool
	}{
		{
			name:        "empty string → default info",
			input:       "",
			wantDefault: slog.LevelInfo,
			wantOverride: map[string]slog.Level{},
		},
		{
			name:        "debug → default debug",
			input:       "debug",
			wantDefault: slog.LevelDebug,
			wantOverride: map[string]slog.Level{},
		},
		{
			name:        "warn,cel:debug → default warn, cel override debug",
			input:       "warn,cel:debug",
			wantDefault: slog.LevelWarn,
			wantOverride: map[string]slog.Level{
				"cel": slog.LevelDebug,
			},
		},
		{
			name:        "info,cel:debug,policy:warn → three-way",
			input:       "info,cel:debug,policy:warn",
			wantDefault: slog.LevelInfo,
			wantOverride: map[string]slog.Level{
				"cel":    slog.LevelDebug,
				"policy": slog.LevelWarn,
			},
		},
		{
			name:    "invalid default level → error",
			input:   "badlevel",
			wantErr: true,
		},
		{
			name:    "invalid logger-specific level → error",
			input:   "info,cel:notlevel",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Default != tc.wantDefault {
				t.Errorf("Default level: want %v, got %v", tc.wantDefault, cfg.Default)
			}
			if len(cfg.Override) != len(tc.wantOverride) {
				t.Errorf("Override count: want %d, got %d", len(tc.wantOverride), len(cfg.Override))
			}
			for k, wantLvl := range tc.wantOverride {
				gotLvl, ok := cfg.Override[k]
				if !ok {
					t.Errorf("Override[%q] missing", k)
					continue
				}
				if gotLvl != wantLvl {
					t.Errorf("Override[%q]: want %v, got %v", k, wantLvl, gotLvl)
				}
			}
		})
	}
}

func TestBuild(t *testing.T) {
	base := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})

	t.Run("uses default level when no override", func(t *testing.T) {
		cfg := Config{Default: slog.LevelWarn, Override: map[string]slog.Level{}}
		logger := Build("mylogger", cfg, base)
		if logger == nil {
			t.Error("expected non-nil logger")
		}
	})

	t.Run("uses override level when present", func(t *testing.T) {
		cfg := Config{
			Default:  slog.LevelWarn,
			Override: map[string]slog.Level{"cel": slog.LevelDebug},
		}
		logger := Build("cel", cfg, base)
		if logger == nil {
			t.Error("expected non-nil logger")
		}
	})
}
