package mesh

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/ObeeJ/corvus-serverside/internal/types"
)

func TestMesh_AuthAndEncryption(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// 1. Setup Mesh Node A and B with correct shared key
	sharedKey := "super-secret-cluster-key"
	nodeA := New("nodeA", "127.0.0.1", 10001, sharedKey, logger)
	nodeB := New("nodeB", "127.0.0.1", 10002, sharedKey, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := nodeA.Start(ctx); err != nil {
		t.Fatalf("failed to start A: %v", err)
	}
	defer nodeA.Stop()

	if err := nodeB.Start(ctx); err != nil {
		t.Fatalf("failed to start B: %v", err)
	}
	defer nodeB.Stop()

	// Connect A and B
	if err := nodeA.Join("127.0.0.1:10002"); err != nil {
		t.Fatalf("failed to join: %v", err)
	}

	// Wait for peer registration
	time.Sleep(150 * time.Millisecond)

	nodesA := nodeA.Nodes()
	nodesB := nodeB.Nodes()

	if len(nodesA) != 1 || nodesA[0].ID != "nodeB" {
		t.Errorf("A should have registered nodeB, got nodes: %+v", nodesA)
	}
	if len(nodesB) != 1 || nodesB[0].ID != "nodeA" {
		t.Errorf("B should have registered nodeA, got nodes: %+v", nodesB)
	}

	// 2. Setup Mesh Node C with a WRONG key
	nodeC := New("nodeC", "127.0.0.1", 10003, "wrong-key", logger)
	if err := nodeC.Start(ctx); err != nil {
		t.Fatalf("failed to start C: %v", err)
	}
	defer nodeC.Stop()

	// Try to make C join A
	if err := nodeC.Join("127.0.0.1:10001"); err != nil {
		t.Fatalf("C failed to join A: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	// A's peers list should STILL be only B, it should reject C
	nodesAAfter := nodeA.Nodes()
	if len(nodesAAfter) != 1 || nodesAAfter[0].ID != "nodeB" {
		t.Errorf("A should have only nodeB as peer, got: %+v", nodesAAfter)
	}

	// C's peers list should be empty (since A rejected C's join)
	nodesC := nodeC.Nodes()
	if len(nodesC) != 0 {
		t.Errorf("C should not have registered any peers, got: %+v", nodesC)
	}
}

func TestMesh_MultiHopAndDeduplication(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	sharedKey := "gossip-mesh-key"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup nodes A, B, C
	nodeA := New("nodeA", "127.0.0.1", 10011, sharedKey, logger)
	nodeB := New("nodeB", "127.0.0.1", 10012, sharedKey, logger)
	nodeC := New("nodeC", "127.0.0.1", 10013, sharedKey, logger)

	if err := nodeA.Start(ctx); err != nil {
		t.Fatalf("start A: %v", err)
	}
	defer nodeA.Stop()

	if err := nodeB.Start(ctx); err != nil {
		t.Fatalf("start B: %v", err)
	}
	defer nodeB.Stop()

	if err := nodeC.Start(ctx); err != nil {
		t.Fatalf("start C: %v", err)
	}
	defer nodeC.Stop()

	// A connects to B, B connects to C (Line topology: A <-> B <-> C)
	if err := nodeA.Join("127.0.0.1:10012"); err != nil {
		t.Fatalf("A join B: %v", err)
	}
	if err := nodeC.Join("127.0.0.1:10012"); err != nil {
		t.Fatalf("C join B: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	// Verify A has B, C has B, B has both A and C
	if len(nodeA.Nodes()) != 1 {
		t.Errorf("A should have 1 peer (B), got: %d", len(nodeA.Nodes()))
	}
	if len(nodeC.Nodes()) != 1 {
		t.Errorf("C should have 1 peer (B), got: %d", len(nodeC.Nodes()))
	}
	if len(nodeB.Nodes()) != 2 {
		t.Errorf("B should have 2 peers (A and C), got: %d", len(nodeB.Nodes()))
	}

	// Broadcast from A
	testResults := []types.EnrichedResult{
		{
			ScanResult: types.ScanResult{
				Port:       80,
				Protocol:   "tcp",
				ResponseMs: 12,
			},
		},
	}
	nodeA.Broadcast(testResults)

	// C should receive this broadcast forwarded by B!
	select {
	case share := <-nodeC.Incoming():
		if share.NodeID != "nodeA" {
			t.Errorf("expected share from nodeA, got: %s", share.NodeID)
		}
		if len(share.Results) != 1 || share.Results[0].Port != 80 {
			t.Errorf("invalid share payload results: %+v", share.Results)
		}
	case <-time.After(800 * time.Millisecond):
		t.Fatal("timed out waiting for multi-hop share on nodeC")
	}

	// Deduplication: broadcast again, make sure it is received
	nodeA.Broadcast(testResults)
	select {
	case share := <-nodeC.Incoming():
		if share.NodeID != "nodeA" {
			t.Errorf("expected second share from nodeA, got: %s", share.NodeID)
		}
	case <-time.After(800 * time.Millisecond):
		t.Fatal("timed out waiting for second scan share")
	}
}
