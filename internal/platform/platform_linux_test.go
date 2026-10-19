package platform

import (
	"strings"
	"testing"
)

// An AppImage mounts to a fresh tmpfs every run, so `setcap` on the extracted binary cannot
// stick. The tray hint must therefore send an AppImage launch to the dashboard + `run` rather
// than suggest setcap, while a normally installed binary should still be told to setcap it.
func TestRelaunchTrayHintByExecutableKind(t *testing.T) {
	t.Run("appimage", func(t *testing.T) {
		t.Setenv("APPIMAGE", "/home/j1/net-merge-x86_64.AppImage")
		err := RelaunchTray(nil, false)
		if err == nil {
			t.Fatal("RelaunchTray should report the missing CAP_NET_ADMIN")
		}
		msg := err.Error()
		if strings.Contains(msg, "setcap") {
			t.Errorf("AppImage hint must not suggest setcap on a transient mount:\n%s", msg)
		}
		if !strings.Contains(msg, "dashboard") || !strings.Contains(msg, "run") {
			t.Errorf("AppImage hint should point at the dashboard and a separate `run`:\n%s", msg)
		}
	})

	t.Run("plain binary", func(t *testing.T) {
		t.Setenv("APPIMAGE", "") // not launched from inside an AppImage
		err := RelaunchTray(nil, false)
		if err == nil {
			t.Fatal("RelaunchTray should report the missing CAP_NET_ADMIN")
		}
		if msg := err.Error(); !strings.Contains(msg, "setcap") {
			t.Errorf("a normally installed binary should still be told to setcap it:\n%s", msg)
		}
	})
}
