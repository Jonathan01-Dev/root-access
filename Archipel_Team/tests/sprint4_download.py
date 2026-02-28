#!/usr/bin/env python3
"""Integration test simulating two nodes exchanging a small file."""
import threading, time, os, sys

root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(root, 'src'))

from network.node import ArchipelNode


def run_node(port, dbfile, local_ip="127.0.0.1"):
    node = ArchipelNode(tcp_port=port, db_file=dbfile, local_ip=local_ip)
    node.start()
    return node


def main():
    # cleanup old peer files
    for f in ['peer1.json','peer2.json']:
        try: os.remove(f)
        except: pass

    node1 = run_node(7777, 'peer1.json')
    node2 = run_node(7778, 'peer2.json')

    # wait for discovery
    print('waiting for discovery...')
    time.sleep(35)
    print('peer tables:')
    print('node1 peers', node1.peer_table.keys())
    print('node2 peers', node2.peer_table.keys())

    # send a message from node1 to node2 if known
    for pid in node1.peer_table:
        print('sending test msg to', pid)
        node1.send_message(pid, 'bonjour de node1')
        break

    # create a small file
    fname = 'test.bin'
    with open(fname,'wb') as f: f.write(os.urandom(1024*128))
    # send file manifest from node1 to node2
    for pid,info in node1.peer_table.items():
        if pid in node2.peer_table:
            fid = node1.send_file(pid, fname)
            print('manifest id', fid)
            break

    # start download on node2 once manifest known
    time.sleep(5)
    if node2.peer_table:
        for fid in node2.available_files():
            print('node2 starting download of',fid)
            node2.dl_manager.start_download(fid)
    # wait for progress
    for i in range(60):
        for fid in node2.dl_manager.sessions:
            done,total=node2.dl_manager.progress(fid)
            print('node2 download',fid,done,'/',total)
        time.sleep(1)

    # cleanup
    node1.running=False
    node2.running=False

if __name__=='__main__':
    main()
