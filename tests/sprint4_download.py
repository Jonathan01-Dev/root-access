import threading
import time
import sys
import os
import json
import struct
import tempfile

# ensure package path
sys.path.insert(0, r"c:\Users\LBS PC\Desktop\access_update2\root-access\Archipel_Team\src")
from network.node import ArchipelNode, TCP_PORT as DEFAULT_PORT
import transfer.manifest as mf


def run_node(port, node_id, peer_info=None, use_udp=False):
    import network.node as nm
    nm.TCP_PORT = port
    node = ArchipelNode(node_id)
    if peer_info:
        node.peer_table = peer_info
    threading.Thread(target=node._tcp_server, daemon=True).start()
    if use_udp:
        threading.Thread(target=node._udp_announcer, daemon=True).start()
        threading.Thread(target=node._udp_listener, daemon=True).start()
    # skip garbage_collector for test to avoid table mutations
    # threading.Thread(target=node._garbage_collector, daemon=True).start()
    return node


def main():
    # create a small temp file to share
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.write(b"hello sprint4" * 1000)
    tmp.flush()
    tmp.close()

    # create two nodes N1 and N2
    n1 = run_node(7100, "N1", use_udp=False)
    n2 = run_node(7101, "N2", use_udp=False)
    # allow servers to start
    time.sleep(0.1)
    # populate peer tables manually so they can talk without UDP discovery
    n1.peer_table = {"N2": {"ip":"127.0.0.1","tcp_port":7101,"last_seen":time.time(),"pubkey":""}}
    n2.peer_table = {"N1": {"ip":"127.0.0.1","tcp_port":7100,"last_seen":time.time(),"pubkey":""}}
    # exchange pubkeys
    n1.peer_table["N2"]["pubkey"] = n2.verify_key.encode().hex()
    n2.peer_table["N1"]["pubkey"] = n1.verify_key.encode().hex()

    # N1 creates manifest and registers filepath
    manifest = mf.create_manifest(tmp.name)
    manifest['filepath'] = tmp.name
    # N1 must register its own manifest before others can request chunks
    n1.manifests[manifest['file_id']] = manifest
    # send manifest to N2
    for pid, info in n1.peer_table.items():
        n1.send_manifest(info['ip'], info['tcp_port'], manifest)

    # allow some time for N2 to process
    time.sleep(0.5)

    # wait until the manifest is known by the download manager
    deadline2 = time.time() + 5
    while time.time() < deadline2:
        if manifest['file_id'] in n2.dl_manager.sessions:
            break
        time.sleep(0.1)
    n2.dl_manager.start_download(manifest['file_id'])

    # wait until file synched or timeout
    deadline = time.time() + 15
    while time.time() < deadline:
        progress = n2.dl_manager.progress(manifest['file_id'])
        print(f"Progress: {progress}")
        if progress and progress[0] == progress[1]:
            break
        time.sleep(1)

    out_path = manifest.get('filename')
    print("Download finished, checking content:", out_path, os.path.exists(out_path))
    assert os.path.exists(out_path)
    assert open(out_path,'rb').read() == open(tmp.name,'rb').read()
    print("Test sprint4 download: OK")

    # cleanup
    os.unlink(tmp.name)
    if os.path.exists(out_path):
        os.unlink(out_path)

if __name__ == "__main__":
    main()
