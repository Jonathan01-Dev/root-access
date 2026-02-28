import threading
import time
import sys
import struct

# ensure package path
sys.path.insert(0, r"c:\Users\LBS PC\Desktop\access_update2\root-access\Archipel_Team\src")
from network.node import ArchipelNode, TCP_PORT as DEFAULT_PORT


def run_node(port, node_id, peer_info=None, recv_messages=None):
    # override global TCP_PORT for new instances
    import network.node as nm
    nm.TCP_PORT = port
    node = ArchipelNode(node_id)
    # optionally set peers
    if peer_info:
        node.peer_table = peer_info
    threading.Thread(target=node._tcp_server, daemon=True).start()
    threading.Thread(target=node._udp_announcer, daemon=True).start()
    threading.Thread(target=node._udp_listener, daemon=True).start()
    threading.Thread(target=node._garbage_collector, daemon=True).start()

    # attach receive hook if provided
    if recv_messages is not None:
        def hook(sock, addr):
            data = sock.recv(4096)
            if data and data.startswith(b"ARCH") and data[4] == 0x03:
                payload = data[struct.calcsize(nm.PACKET_FORMAT):-32]
                # try decrypt with each peer_id we know
                for pid in node.peer_table.keys():
                    try:
                        txt = node.decrypt_from_peer(pid, payload).decode(errors='ignore')
                        recv_messages.append((node_id, pid, txt))
                        print(f"{node_id} got from {pid}", txt)
                        break
                    except Exception:
                        continue
            sock.close()
        node._handle_client = hook
    return node


def main():
    # create three nodes on 7000,7001,7002
    recv = []
    n1 = run_node(7000, "N1", peer_info={"N2": {"ip":"127.0.0.1","tcp_port":7001,"last_seen":time.time(),"pubkey":""}}, recv_messages=recv)
    n2 = run_node(7001, "N2", peer_info={"N1": {"ip":"127.0.0.1","tcp_port":7000,"last_seen":time.time(),"pubkey":""},
                                            "N3": {"ip":"127.0.0.1","tcp_port":7002,"last_seen":time.time(),"pubkey":""}}, recv_messages=recv)
    n3 = run_node(7002, "N3", peer_info={"N2": {"ip":"127.0.0.1","tcp_port":7001,"last_seen":time.time(),"pubkey":""}}, recv_messages=recv)
    # wait for nodes to startup
    time.sleep(1)
    # update peer pubkeys now that nodes exist
    n1.peer_table["N2"]["pubkey"] = n2.verify_key.encode().hex()
    n2.peer_table["N1"]["pubkey"] = n1.verify_key.encode().hex()
    n2.peer_table["N3"]["pubkey"] = n3.verify_key.encode().hex()
    n3.peer_table["N2"]["pubkey"] = n2.verify_key.encode().hex()

    # send messages
    n1.send_message("N2", "hello from N1 to N2")
    n2.send_message("N3", "hi from N2 to N3")
    n3.send_message("N2", "back from N3 to N2")

    time.sleep(1)
    print("received list:", recv)

if __name__ == "__main__":
    main()
