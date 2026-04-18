// Package notify sends desktop notifications via libnotify (notify-send).
//
// Notifications carry the context the user needs to recognise what they are
// about to approve: which RPID, which authenticator instance, and a short
// correlation id derived from the request. The id matches what
// ssh-agent-mux prints for the corresponding sign request, letting the user
// confirm the linux-id prompt belongs to the SSH session they expect.
//
// All sends are best-effort: missing notify-send, no D-Bus session, or any
// other failure is logged at debug level and ignored. A sign must never fail
// because the desktop is unreachable.
package notify

import (
	"log"
	"os/exec"
	"sync"
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

// Send fires a notification asynchronously. Returns immediately; never blocks
// the caller on D-Bus or pinentry.
func Send(title, body string) {
	bin := locate()
	if bin == "" {
		return
	}
	go func() {
		cmd := exec.Command(bin,
			"--app-name=linux-id",
			"--category=device",
			"--urgency=normal",
			"--expire-time=15000",
			title, body,
		)
		if err := cmd.Run(); err != nil {
			log.Printf("notify: %s", err)
		}
	}()
}
