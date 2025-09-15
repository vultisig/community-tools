package processing

import (
	"strings"
	"sync"
	"time"
)

// Debugger defines the interface for collecting debug events
type Debugger interface {
	Enabled() bool
	Level() DebugLevel
	Emit(level DebugLevel, category, message string, fields map[string]any)
	With(fields map[string]any) Debugger
	Flush() DebugPayload
}

// DebugConfig configures the debug collector behavior
type DebugConfig struct {
	Enabled          bool
	Level            DebugLevel
	Categories       []string
	IncludeSensitive bool
	Capacity         int
}

// Default configuration
var defaultConfig = DebugConfig{
	Enabled:          false,
	Level:            INFO,
	Categories:       []string{},
	IncludeSensitive: false,
	Capacity:         1000,
}

// Package-level debug collector
var (
	debuggerMu sync.RWMutex
	debugger   Debugger = &NoOpCollector{}
)

// SetDebugConfig configures the global debug collector
func SetDebugConfig(config DebugConfig) {
	debuggerMu.Lock()
	defer debuggerMu.Unlock()

	if !config.Enabled {
		debugger = &NoOpCollector{}
		return
	}

	if config.Capacity <= 0 {
		config.Capacity = defaultConfig.Capacity
	}

	debugger = NewActiveCollector(config)
}

// Debug returns the current debug collector
func Debug() Debugger {
	debuggerMu.RLock()
	defer debuggerMu.RUnlock()
	return debugger
}

// ResetDebug resets the debug collector to no-op mode
func ResetDebug() {
	debuggerMu.Lock()
	defer debuggerMu.Unlock()
	debugger = &NoOpCollector{}
}

// NoOpCollector implements Debugger with zero overhead when debugging is disabled
type NoOpCollector struct{}

func (n *NoOpCollector) Enabled() bool                                                          { return false }
func (n *NoOpCollector) Level() DebugLevel                                                      { return ERROR }
func (n *NoOpCollector) Emit(level DebugLevel, category, message string, fields map[string]any) {}
func (n *NoOpCollector) With(fields map[string]any) Debugger                                    { return n }
func (n *NoOpCollector) Flush() DebugPayload {
	return DebugPayload{
		Enabled:    false,
		Level:      ERROR,
		Categories: []string{},
		Dropped:    0,
		Events:     []DebugEvent{},
	}
}

// ActiveCollector implements Debugger with ring buffer and filtering
type ActiveCollector struct {
	config     DebugConfig
	events     []DebugEvent
	capacity   int
	head       int
	size       int
	dropped    int
	mu         sync.RWMutex
	categories map[string]bool
}

// NewActiveCollector creates a new active debug collector
func NewActiveCollector(config DebugConfig) *ActiveCollector {
	categoriesMap := make(map[string]bool)
	for _, cat := range config.Categories {
		categoriesMap[strings.ToUpper(cat)] = true
	}

	return &ActiveCollector{
		config:     config,
		events:     make([]DebugEvent, config.Capacity),
		capacity:   config.Capacity,
		head:       0,
		size:       0,
		dropped:    0,
		categories: categoriesMap,
	}
}

func (a *ActiveCollector) Enabled() bool {
	return a.config.Enabled
}

func (a *ActiveCollector) Level() DebugLevel {
	return a.config.Level
}

// levelPriority returns numeric priority for level filtering
func levelPriority(level DebugLevel) int {
	switch level {
	case ERROR:
		return 0
	case WARN:
		return 1
	case INFO:
		return 2
	case DEBUG:
		return 3
	default:
		return 4
	}
}

func (a *ActiveCollector) Emit(level DebugLevel, category, message string, fields map[string]any) {
	// Fast path: check if we should collect this event
	if !a.shouldCollect(level, category) {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Create event
	event := DebugEvent{
		Timestamp: time.Now().Format("15:04:05.000"),
		Level:     level,
		Category:  strings.ToUpper(category),
		Message:   message,
	}

	// Redact sensitive fields unless explicitly allowed
	if fields != nil {
		event.Fields = a.redactFields(fields)
	}

	// Add to ring buffer
	a.events[a.head] = event
	a.head = (a.head + 1) % a.capacity

	if a.size < a.capacity {
		a.size++
	} else {
		a.dropped++
	}
}

func (a *ActiveCollector) With(fields map[string]any) Debugger {
	return &ContextualCollector{
		parent:  a,
		context: a.redactFields(fields),
	}
}

func (a *ActiveCollector) Flush() DebugPayload {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Copy events from ring buffer in correct order
	events := make([]DebugEvent, 0, a.size)

	if a.size > 0 {
		start := a.head - a.size
		if start < 0 {
			start += a.capacity
		}

		for i := 0; i < a.size; i++ {
			idx := (start + i) % a.capacity
			events = append(events, a.events[idx])
		}
	}

	return DebugPayload{
		Enabled:    a.config.Enabled,
		Level:      a.config.Level,
		Categories: a.config.Categories,
		Dropped:    a.dropped,
		Events:     events,
	}
}

func (a *ActiveCollector) shouldCollect(level DebugLevel, category string) bool {
	// Check level filtering
	if levelPriority(level) > levelPriority(a.config.Level) {
		return false
	}

	// Check category filtering (empty categories means collect all)
	if len(a.categories) > 0 && !a.categories[strings.ToUpper(category)] {
		return false
	}

	return true
}

// Sensitive field names that should be redacted by default
var sensitiveFields = map[string]bool{
	"hexprivkey":         true,
	"hex_priv_key":       true,
	"hexprivkeyecdsa":    true,
	"hexprivkeyeddsa":    true,
	"privatekey":         true,
	"private_key":        true,
	"extendedprivkey":    true,
	"extendedprivatekey": true,
	"chaincode":          true,
	"chain_code":         true,
	"seed":               true,
	"mnemonic":           true,
	"password":           true,
	"wifprivatekey":      true,
	"wif_private_key":    true,
}

func (a *ActiveCollector) redactFields(fields map[string]any) map[string]any {
	if a.config.IncludeSensitive {
		return fields
	}

	result := make(map[string]any)
	for key, value := range fields {
		lowerKey := strings.ToLower(key)
		if sensitiveFields[lowerKey] {
			result[key] = "[REDACTED]"
		} else {
			result[key] = value
		}
	}
	return result
}

// ContextualCollector wraps another collector with additional context fields
type ContextualCollector struct {
	parent  Debugger
	context map[string]any
}

func (c *ContextualCollector) Enabled() bool {
	return c.parent.Enabled()
}

func (c *ContextualCollector) Level() DebugLevel {
	return c.parent.Level()
}

func (c *ContextualCollector) Emit(level DebugLevel, category, message string, fields map[string]any) {
	// Merge context fields with provided fields
	mergedFields := make(map[string]any)

	// Add context fields first
	for k, v := range c.context {
		mergedFields[k] = v
	}

	// Add provided fields (they override context)
	for k, v := range fields {
		mergedFields[k] = v
	}

	c.parent.Emit(level, category, message, mergedFields)
}

func (c *ContextualCollector) With(fields map[string]any) Debugger {
	// Merge with existing context
	mergedContext := make(map[string]any)
	for k, v := range c.context {
		mergedContext[k] = v
	}
	for k, v := range fields {
		mergedContext[k] = v
	}

	return &ContextualCollector{
		parent:  c.parent,
		context: mergedContext,
	}
}

func (c *ContextualCollector) Flush() DebugPayload {
	return c.parent.Flush()
}
