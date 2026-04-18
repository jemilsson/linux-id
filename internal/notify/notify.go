// Package notify sends and updates desktop notifications via the
// org.freedesktop.Notifications D-Bus interface.
//
// Notifications carry the context the user needs to recognise what they are
// about to approve: which RPID, which authenticator instance, and a short
// correlation id derived from the request. The id matches what
// ssh-agent-mux prints for the corresponding sign request, letting the user
// confirm the linux-id prompt belongs to the SSH session they expect.
//
// Each Send returns a Handle whose Update replaces the notification body
// in-place (using the replaces_id parameter on Notify) and whose Close
// dismisses it. Notifications are sent with critical urgency and an
// infinite expire timeout so they persist until linux-id closes them.
//
// All operations are best-effort. A missing session bus or any failure is
// logged once and ignored. A sign must never fail because the desktop is
// unreachable.
package notify

import (
	"log"

	"github.com/godbus/dbus/v5"
)

const (
	dest      = "org.freedesktop.Notifications"
	objectPth = "/org/freedesktop/Notifications"
	notifyM   = "org.freedesktop.Notifications.Notify"
	closeM    = "org.freedesktop.Notifications.CloseNotification"
	appName   = "linux-id"
)

// Handle identifies a live notification.
type Handle struct {
	id    uint32
	title string
}

// Send fires a persistent notification and returns a handle for later
// Update / Close calls. Returns nil on failure (best-effort).
func Send(title, body string) *Handle {
	id, ok := notify(0, title, body)
	if !ok {
		return nil
	}
	return &Handle{id: id, title: title}
}

// Update replaces the notification's body in place. Title is preserved.
// Safe on nil receiver.
func (h *Handle) Update(body string) {
	if h == nil || h.id == 0 {
		return
	}
	if newID, ok := notify(h.id, h.title, body); ok {
		h.id = newID
	}
}

// UpdateTitle replaces both title and body. Safe on nil.
func (h *Handle) UpdateTitle(title, body string) {
	if h == nil || h.id == 0 {
		return
	}
	if newID, ok := notify(h.id, title, body); ok {
		h.id = newID
		h.title = title
	}
}

// Close dismisses the notification. Safe on nil.
func (h *Handle) Close() {
	if h == nil || h.id == 0 {
		return
	}
	conn, err := dbus.SessionBus()
	if err != nil {
		return
	}
	_ = conn.Object(dest, dbus.ObjectPath(objectPth)).
		Call(closeM, 0, h.id).Err
}

// notify is the underlying Notify call. Pass replacesID=0 for a fresh
// notification, or an existing id to update in place.
func notify(replacesID uint32, title, body string) (uint32, bool) {
	conn, err := dbus.SessionBus()
	if err != nil {
		log.Printf("notify: session bus: %s", err)
		return 0, false
	}
	hints := map[string]dbus.Variant{
		"urgency":  dbus.MakeVariant(byte(2)), // critical
		"category": dbus.MakeVariant("device"),
	}
	var id uint32
	err = conn.Object(dest, dbus.ObjectPath(objectPth)).
		Call(notifyM, 0,
			appName,    // app_name
			replacesID, // replaces_id
			"",         // app_icon
			title,      // summary
			body,       // body
			[]string{}, // actions
			hints,
			int32(0), // expire_timeout: 0 = never
		).Store(&id)
	if err != nil {
		log.Printf("notify: %s", err)
		return 0, false
	}
	return id, true
}
