// Package notify sends desktop notifications via libnotify (notify-send).
//
// Notifications carry the context the user needs to recognise what they are
// about to approve: which RPID, which authenticator instance, and a short
// correlation id derived from the request. The id matches what
// ssh-agent-mux prints for the corresponding sign request, letting the user
// confirm the linux-id prompt belongs to the SSH session they expect.
//
// Each Send returns a Handle whose Close method dismisses the notification
// via the org.freedesktop.Notifications D-Bus interface. Notifications are
// fired with `--urgency=critical --expire-time=0` so they persist until the
// caller closes them, ensuring the user has time to read the context before
// approving on the fingerprint reader or pinentry.
//
// All sends are best-effort: missing notify-send, no D-Bus session, or any
// other failure is logged once and ignored. A sign must never fail because
// the desktop is unreachable.
package notify

import (
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
)

var (
	once    sync.Once
	binPath string
)

func locate() string {
	once.Do(func() {
		if p, err := exec.LookPath("notify-send"); err == nil {
			binPath = p
		}
	})
	return binPath
}

// Handle identifies a notification that has been sent and can be closed.
// A nil *Handle is a valid no-op (returned when notify-send is unavailable
// or the notification could not be fired).
type Handle struct {
	id uint32
}

// Send fires a persistent notification and returns a handle to close it
// when the operation completes. Returns nil on failure (best-effort).
func Send(title, body string) *Handle {
	bin := locate()
	if bin == "" {
		return nil
	}
	cmd := exec.Command(bin,
		"--app-name=linux-id",
		"--category=device",
		"--urgency=critical",
		"--expire-time=0",
		"--print-id",
		title, body,
	)
	out, err := cmd.Output()
	if err != nil {
		log.Printf("notify: %s", err)
		return nil
	}
	id64, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
	if err != nil {
		log.Printf("notify: parse id %q: %s", out, err)
		return nil
	}
	return &Handle{id: uint32(id64)}
}

// Close dismisses the notification. Safe on nil. Idempotent in practice
// because a stale id is silently ignored by the notification daemon.
func (h *Handle) Close() {
	if h == nil || h.id == 0 {
		return
	}
	conn, err := dbus.SessionBus()
	if err != nil {
		return
	}
	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	_ = obj.Call("org.freedesktop.Notifications.CloseNotification", 0, h.id).Err
}
