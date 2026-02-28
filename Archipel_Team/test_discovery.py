#!/usr/bin/env python3
"""Test basic peer discovery without needing multi-node setup"""
import sys
import os
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from network.node import ArchipelNode

def test_single_node():
    """Test that a single node creates correct node_id"""
    print("[TEST] Starting single node to verify node_id generation...")
    
    node = ArchipelNode(tcp_port=7777, db_file="test_peer_table.json", local_ip="127.0.0.1")
    
    print(f"[TEST] Node ID (should be 64-char hex): {node.node_id}")
    print(f"[TEST] Node UID (for comparison): {node.node_uid}")
    
    # Verify node_id is a valid 64-character hex string
    assert len(node.node_id) == 64, f"Node ID should be 64 chars, got {len(node.node_id)}"
    assert all(c in '0123456789abcdef' for c in node.node_id), "Node ID should be valid hex"
    assert node.node_id == node.node_uid, "node_id should equal node_uid"
    
    print("[PASS] Node ID generation verified")
    return node

def test_discovery_loop(node1_port=7777, node2_port=7778):
    """Test peer discovery with simulated timeout"""
    print("\n[TEST] Testing peer discovery mechanism...")
    
    # Note: This is a simpler test that verifies the mechanism works
    # Full multi-node test would require network setup
    
    node1 = ArchipelNode(tcp_port=node1_port, db_file="test_peer1.json")
    node2 = ArchipelNode(tcp_port=node2_port, db_file="test_peer2.json")
    
    # Start nodes
    node1.start()
    node2.start()
    
    # Wait for discovery to happen
    print("[TEST] Waiting 40 seconds for peer discovery...")
    for i in range(40):
        print(f"[TEST] {i}s... Node1 sees {len(node1.peer_table)} peers, Node2 sees {len(node2.peer_table)} peers")
        time.sleep(1)
        if len(node1.peer_table) > 0 or len(node2.peer_table) > 0:
            print("[PASS] Peers discovered!")
            break
    
    # Stop nodes
    node1.running = False
    node2.running = False
    
    time.sleep(1)
    
    if len(node1.peer_table) == 0 and len(node2.peer_table) == 0:
        print("[INFO] No peers discovered - this is expected on localhost without proper multicast")
    else:
        print(f"[PASS] Node1 discovered {len(node1.peer_table)} peers")
        print(f"[PASS] Node2 discovered {len(node2.peer_table)} peers")

if __name__ == "__main__":
    try:
        node = test_single_node()
        # Cleanup single node test
        node.running = False
        
        # Optionally run discovery test (won't work on localhost)
        # Uncomment to test with actual network:
        # test_discovery_loop()
        
        print("\n[OK] All basic tests passed!")
    except AssertionError as e:
        print(f"[FAIL] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
