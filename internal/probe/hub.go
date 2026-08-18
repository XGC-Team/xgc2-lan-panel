package probe

import (
	"sync"
)

// Hub is viewer presence plus a fan-out of robot snapshots.
// A browser tab that is actually looking at the page holds one subscription.
type Hub struct {
	mu      sync.Mutex
	next    int
	subs    map[int]chan []byte
	viewers int
}

func NewHub() *Hub {
	return &Hub{subs: map[int]chan []byte{}}
}

func (h *Hub) Subscribe() (id int, updates <-chan []byte, viewers int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.next++
	id = h.next
	ch := make(chan []byte, 1)
	h.subs[id] = ch
	h.viewers++
	return id, ch, h.viewers
}

func (h *Hub) Unsubscribe(id int) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.subs[id]
	if !ok {
		return h.viewers
	}
	delete(h.subs, id)
	close(ch)
	if h.viewers > 0 {
		h.viewers--
	}
	return h.viewers
}

func (h *Hub) Viewers() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.viewers
}

func (h *Hub) Viewing() bool {
	return h.Viewers() > 0
}

func (h *Hub) Publish(payload []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, ch := range h.subs {
		select {
		case ch <- payload:
		default:
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- payload:
			default:
				_ = id
			}
		}
	}
}
