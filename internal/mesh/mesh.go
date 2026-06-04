package mesh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/secretbox"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

const (
	// defaultTTL bounds how many hops a shared result propagates across the mesh.
	defaultTTL = 3
	// seenTTL is how long a message ID is remembered for de-duplication.
	seenTTL = 5 * time.Minute
)

// NodeInfo describes a peer in the mesh.
type NodeInfo struct {
	ID        string    `json:"id"`
	Addr      string    `json:"addr"`
	LastSeen  time.Time `json:"last_seen"`
	ScanCount int       `json:"scan_count"`
}

// ScanShare is a scan result broadcast to peers.
type ScanShare struct {
	NodeID  string                 `json:"node_id"`
	Results []types.EnrichedResult `json:"results"`
}

// Mesh implements a UDP gossip mesh for coordinating distributed Corvus nodes.
// Messages are authenticated-encrypted with a shared cluster key (NaCl
// secretbox); shared scan results are forwarded multi-hop with de-duplication.
type Mesh struct {
	nodeID   string
	bindAddr string
	port     int
	log      *slog.Logger

	encrypted bool
	key       [32]byte

	mu    sync.RWMutex
	peers map[string]*NodeInfo

	seenMu sync.Mutex
	seen   map[string]time.Time

	conn     *net.UDPConn
	incoming chan ScanShare
	cancel   context.CancelFunc
}

// New creates a new Mesh node. If key is non-empty, all traffic is encrypted and
// authenticated with a key derived from it; peers must share the same key.
func New(nodeID, bindAddr string, port int, key string, log *slog.Logger) *Mesh {
	m := &Mesh{
		nodeID:   nodeID,
		bindAddr: bindAddr,
		port:     port,
		log:      log,
		peers:    make(map[string]*NodeInfo),
		seen:     make(map[string]time.Time),
		incoming: make(chan ScanShare, 64),
	}
	if key != "" {
		m.key = sha256.Sum256([]byte(key))
		m.encrypted = true
	}
	return m
}

// Encrypted reports whether mesh traffic is encrypted.
func (m *Mesh) Encrypted() bool { return m.encrypted }

// Start binds the UDP socket and begins listening for gossip messages.
func (m *Mesh) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", m.bindAddr, m.port))
	if err != nil {
		return fmt.Errorf("resolving mesh addr: %w", err)
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("binding mesh socket: %w", err)
	}
	m.conn = conn

	ctx, m.cancel = context.WithCancel(ctx)

	if m.encrypted {
		m.log.Info("mesh node started", "id", m.nodeID, "addr", addr, "encryption", "on")
	} else {
		m.log.Warn("mesh node started WITHOUT encryption — set CORVUS_MESH_KEY to secure gossip", "id", m.nodeID, "addr", addr)
	}

	go m.readLoop(ctx)
	go m.heartbeatLoop(ctx)
	return nil
}

// Join sends a hello message to a known peer to join the mesh.
func (m *Mesh) Join(peerAddr string) error {
	msg := gossipMsg{Type: "hello", NodeID: m.nodeID, Addr: fmt.Sprintf("%s:%d", m.bindAddr, m.port)}
	return m.sendTo(peerAddr, msg)
}

// Broadcast shares scan results with all known peers (origin of a multi-hop gossip).
func (m *Mesh) Broadcast(results []types.EnrichedResult) {
	share := ScanShare{NodeID: m.nodeID, Results: results}
	msg := gossipMsg{
		Type:    "share",
		NodeID:  m.nodeID,
		ID:      randID(),
		TTL:     defaultTTL,
		Payload: mustMarshal(share),
	}
	// Remember our own message so it isn't re-delivered if it loops back.
	m.markSeen(msg.ID)
	m.forward(msg, "")
}

// Nodes returns a snapshot of all known peers.
func (m *Mesh) Nodes() []NodeInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	nodes := make([]NodeInfo, 0, len(m.peers))
	for _, p := range m.peers {
		nodes = append(nodes, *p)
	}
	return nodes
}

// Incoming returns the channel of scan shares received from peers.
func (m *Mesh) Incoming() <-chan ScanShare {
	return m.incoming
}

// Stop cancels the loops and closes the socket (no busy-spin on shutdown).
func (m *Mesh) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
	if m.conn != nil {
		_ = m.conn.SetReadDeadline(time.Now()) // unblock a pending ReadFromUDP
		_ = m.conn.Close()
	}
}

// ── internal ─────────────────────────────────────────────────────────────────

type gossipMsg struct {
	Type    string          `json:"type"`
	NodeID  string          `json:"node_id"`
	Addr    string          `json:"addr,omitempty"`
	ID      string          `json:"id,omitempty"`  // unique per shared message (for dedup)
	TTL     int             `json:"ttl,omitempty"` // remaining hops
	Payload json.RawMessage `json:"payload,omitempty"`
}

func (m *Mesh) readLoop(ctx context.Context) {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = m.conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remoteAddr, err := m.conn.ReadFromUDP(buf)
		if err != nil {
			// On shutdown the socket is closed and reads error instantly — exit
			// promptly instead of spinning.
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}

		plain, ok := m.open(buf[:n])
		if !ok {
			// Undecryptable / forged / corrupt packet — drop silently.
			continue
		}

		var msg gossipMsg
		if err := json.Unmarshal(plain, &msg); err != nil {
			continue
		}
		m.handleMsg(msg, remoteAddr.String())
	}
}

func (m *Mesh) handleMsg(msg gossipMsg, from string) {
	if msg.NodeID == m.nodeID {
		return // ignore our own traffic (loops)
	}

	// Track / refresh the peer. The UDP source address is authoritative (the
	// packet is authenticated, so it can't be spoofed by a third party).
	m.mu.Lock()
	if _, exists := m.peers[msg.NodeID]; !exists {
		m.log.Info("new mesh peer", "id", msg.NodeID, "addr", from)
	}
	m.peers[msg.NodeID] = &NodeInfo{ID: msg.NodeID, Addr: from, LastSeen: time.Now()}
	m.mu.Unlock()

	switch msg.Type {
	case "hello":
		reply := gossipMsg{Type: "hello", NodeID: m.nodeID, Addr: fmt.Sprintf("%s:%d", m.bindAddr, m.port)}
		_ = m.sendTo(from, reply)

	case "heartbeat":
		// Liveness already refreshed above.

	case "share":
		if msg.ID != "" && m.markSeen(msg.ID) {
			return // already processed this message — stop the loop
		}
		var share ScanShare
		if err := json.Unmarshal(msg.Payload, &share); err == nil && share.NodeID != m.nodeID {
			select {
			case m.incoming <- share:
			default: // backpressure: drop rather than block the read loop
			}
		}
		// Multi-hop: forward to other peers, decrementing TTL, skipping the sender.
		if msg.TTL > 0 {
			fwd := msg
			fwd.TTL = msg.TTL - 1
			m.forward(fwd, from)
		}
	}
}

// forward sends a message to all known peers except exceptAddr.
func (m *Mesh) forward(msg gossipMsg, exceptAddr string) {
	m.mu.RLock()
	peers := make([]string, 0, len(m.peers))
	for _, p := range m.peers {
		if p.Addr != exceptAddr {
			peers = append(peers, p.Addr)
		}
	}
	m.mu.RUnlock()

	for _, addr := range peers {
		if err := m.sendTo(addr, msg); err != nil {
			m.log.Debug("forward failed", "peer", addr, "err", err)
		}
	}
}

// markSeen records a message ID and returns true if it was already seen.
func (m *Mesh) markSeen(id string) bool {
	m.seenMu.Lock()
	defer m.seenMu.Unlock()
	if _, ok := m.seen[id]; ok {
		return true
	}
	m.seen[id] = time.Now()
	return false
}

func (m *Mesh) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msg := gossipMsg{Type: "heartbeat", NodeID: m.nodeID}
			m.mu.RLock()
			for _, peer := range m.peers {
				_ = m.sendTo(peer.Addr, msg)
			}
			m.mu.RUnlock()

			// Evict peers not seen in 2 minutes.
			m.mu.Lock()
			for id, peer := range m.peers {
				if time.Since(peer.LastSeen) > 2*time.Minute {
					m.log.Info("evicting stale mesh peer", "id", id)
					delete(m.peers, id)
				}
			}
			m.mu.Unlock()

			// Expire old de-dup entries so the set doesn't grow unbounded.
			m.seenMu.Lock()
			for id, ts := range m.seen {
				if time.Since(ts) > seenTTL {
					delete(m.seen, id)
				}
			}
			m.seenMu.Unlock()
		}
	}
}

func (m *Mesh) sendTo(addr string, msg gossipMsg) error {
	if m.conn == nil {
		return fmt.Errorf("mesh not started")
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	_, err = m.conn.WriteToUDP(m.seal(data), udpAddr)
	return err
}

// ── crypto ───────────────────────────────────────────────────────────────────

// seal authenticates+encrypts a payload as nonce||box. Passthrough when no key.
func (m *Mesh) seal(plain []byte) []byte {
	if !m.encrypted {
		return plain
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return plain // extremely unlikely; fail open rather than drop traffic
	}
	return secretbox.Seal(nonce[:], plain, &nonce, &m.key)
}

// open verifies+decrypts a nonce||box payload. Passthrough when no key.
func (m *Mesh) open(box []byte) ([]byte, bool) {
	if !m.encrypted {
		return box, true
	}
	if len(box) < 24 {
		return nil, false
	}
	var nonce [24]byte
	copy(nonce[:], box[:24])
	return secretbox.Open(nil, box[24:], &nonce, &m.key)
}

func randID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func mustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
