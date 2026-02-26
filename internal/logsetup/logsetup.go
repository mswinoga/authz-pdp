package logsetup

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// Config holds the parsed log-level configuration.
type Config struct {
	Default  slog.Level
	Override map[string]slog.Level // logger name → level
}

// Parse parses a flag value like "info,cel:debug,policy:warn".
// The first token without a colon is the default level.
// Subsequent "name:level" tokens override individual named loggers.
// Valid level strings: debug, info, warn, error (case-insensitive).
func Parse(s string) (Config, error) {
	cfg := Config{
		Default:  slog.LevelInfo,
		Override: make(map[string]slog.Level),
	}
	if s == "" {
		return cfg, nil
	}
	for _, token := range strings.Split(s, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		parts := strings.SplitN(token, ":", 2)
		if len(parts) == 1 {
			// default level
			lvl, err := parseLevel(parts[0])
			if err != nil {
				return Config{}, fmt.Errorf("invalid default level %q: %w", parts[0], err)
			}
			cfg.Default = lvl
		} else {
			name, levelStr := parts[0], parts[1]
			lvl, err := parseLevel(levelStr)
			if err != nil {
				return Config{}, fmt.Errorf("invalid level for logger %q: %w", name, err)
			}
			cfg.Override[name] = lvl
		}
	}
	return cfg, nil
}

// Build creates a *slog.Logger for the given name using the base handler.
// The logger applies its own level gate before delegating to base.
// Each logger record includes a "logger" attribute set to name.
func Build(name string, cfg Config, base slog.Handler) *slog.Logger {
	lvl := cfg.Default
	if override, ok := cfg.Override[name]; ok {
		lvl = override
	}
	return slog.New(&levelFilter{level: lvl, inner: base}).With("logger", name)
}

func parseLevel(s string) (slog.Level, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(strings.ToUpper(s))); err != nil {
		return 0, err
	}
	return lvl, nil
}

// levelFilter is a slog.Handler wrapper that gates records by level
// before delegating to the inner handler.
type levelFilter struct {
	level slog.Level
	inner slog.Handler
}

func (f *levelFilter) Enabled(_ context.Context, l slog.Level) bool {
	return l >= f.level
}
func (f *levelFilter) Handle(ctx context.Context, r slog.Record) error {
	return f.inner.Handle(ctx, r)
}
func (f *levelFilter) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &levelFilter{f.level, f.inner.WithAttrs(attrs)}
}
func (f *levelFilter) WithGroup(name string) slog.Handler {
	return &levelFilter{f.level, f.inner.WithGroup(name)}
}
