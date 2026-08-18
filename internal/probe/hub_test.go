package probe

import "testing"

func TestHubViewerCount(t *testing.T) {
	h := NewHub()
	if h.Viewing() {
		t.Fatal("empty hub is not viewing")
	}
	id1, _, n := h.Subscribe()
	if n != 1 || !h.Viewing() {
		t.Fatalf("one viewer: n=%d viewing=%v", n, h.Viewing())
	}
	id2, _, n := h.Subscribe()
	if n != 2 {
		t.Fatalf("two viewers: %d", n)
	}
	if h.Unsubscribe(id1) != 1 {
		t.Fatal("after one leave")
	}
	if h.Unsubscribe(id2) != 0 || h.Viewing() {
		t.Fatal("last leave must clear viewing")
	}
}

func TestHubPublishLatestWins(t *testing.T) {
	h := NewHub()
	_, ch, _ := h.Subscribe()
	h.Publish([]byte("a"))
	h.Publish([]byte("b"))
	got := string(<-ch)
	if got != "a" && got != "b" {
		t.Fatalf("got %q", got)
	}
}
