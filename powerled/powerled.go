// Package powerled controls the system power LED via sysfs to provide
// visual feedback when the FIDO token is waiting for user presence.
package powerled

import (
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

const ledPath = "/sys/class/leds/tpacpi::power"

// Blinker toggles the power LED on and off to signal that user interaction
// is needed (e.g. fingerprint touch).
type Blinker struct {
	mu       sync.Mutex
	active   bool
	stopCh   chan struct{}
	doneCh   chan struct{}
	origTrig string
	maxBri   string
}

// New returns a Blinker. It does not touch the LED until Start is called.
func New() *Blinker {
	return &Blinker{}
}

// Start begins blinking the power LED at the given interval. If the LED
// cannot be accessed, blinking is silently skipped. Calling Start while
// already blinking is a no-op.
func (b *Blinker) Start(interval time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.active {
		return
	}

	// Save original state so we can restore it on Stop.
	origTrig, err := readFile(ledPath + "/trigger")
	if err != nil {
		log.Printf("powerled: cannot read trigger, skipping blink: %s", err)
		return
	}
	maxBri, err := readFile(ledPath + "/max_brightness")
	if err != nil {
		log.Printf("powerled: cannot read max_brightness, skipping blink: %s", err)
		return
	}

	b.origTrig = parseActiveTrigger(origTrig)
	b.maxBri = maxBri
	b.active = true
	b.stopCh = make(chan struct{})
	b.doneCh = make(chan struct{})

	// Switch to "none" trigger so we can control brightness directly.
	writeFile(ledPath+"/trigger", "none")

	go func() {
		defer close(b.doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		on := false
		for {
			select {
			case <-ticker.C:
				if on {
					writeFile(ledPath+"/brightness", "0")
				} else {
					writeFile(ledPath+"/brightness", b.maxBri)
				}
				on = !on
			case <-b.stopCh:
				return
			}
		}
	}()
}

// Stop ends the blinking and restores the LED to its on state.
// Safe to call even if Start was never called or failed.
func (b *Blinker) Stop() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.active {
		return
	}

	close(b.stopCh)
	<-b.doneCh
	b.active = false

	// Ensure the LED is solid-on before restoring the original trigger.
	// The blink goroutine may have left it in the off phase.
	writeFile(ledPath+"/brightness", b.maxBri)
	writeFile(ledPath+"/trigger", b.origTrig)
}

// parseActiveTrigger extracts the currently active trigger from the sysfs
// trigger file, which lists all options with the active one in brackets.
func parseActiveTrigger(s string) string {
	start := strings.Index(s, "[")
	end := strings.Index(s, "]")
	if start >= 0 && end > start {
		return s[start+1 : end]
	}
	return strings.TrimSpace(s)
}

func readFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func writeFile(path, value string) {
	if err := os.WriteFile(path, []byte(value), 0644); err != nil {
		log.Printf("powerled: write %s: %s", path, err)
	}
}
