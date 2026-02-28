import os
import threading
import time
import hashlib
from collections import defaultdict


class DownloadSession:
    def __init__(self, manifest, save_path):
        self.manifest = manifest
        self.file_id = manifest['file_id']
        self.save_path = save_path
        self.chunk_size = manifest['chunk_size']
        self.nb_chunks = manifest['nb_chunks']
        # state arrays
        # 0 = not requested, 1 = requested/in-flight, 2 = received
        self.states = [0] * self.nb_chunks
        # mapping idx -> hash
        self.hashes = [c['hash'] for c in manifest['chunks']]
        # temporary file
        self.temp_path = save_path + ".part"
        # lock for thread-safety
        self.lock = threading.Lock()
        # peers that have the manifest (peer_id -> count)
        self.peers = set()
        # frequency cache for chunks
        self.chunk_frequency = None

        # ensure temp file exists and has correct size
        total_size = manifest['size']
        with open(self.temp_path, 'wb') as f:
            f.truncate(total_size)

    def mark_peer(self, peer_id):
        self.peers.add(peer_id)
        # invalidate frequency cache
        self.chunk_frequency = None

    def _compute_chunk_frequency(self):
        # build frequency of how many peers have each chunk
        # in simple implementation every peer is assumed to have all chunks
        # since manifest describes entire file; if peers can advertise partial
        # availability later this should be refined
        if self.chunk_frequency is None:
            freq = [len(self.peers)] * self.nb_chunks
            self.chunk_frequency = freq
        return self.chunk_frequency

    def next_chunk(self):
        """Choose the next chunk to request using rarest-first strategy."""
        with self.lock:
            freq = self._compute_chunk_frequency()
            best_idx = None
            best_freq = None
            for idx, state in enumerate(self.states):
                if state == 0:  # not yet requested
                    f = freq[idx]
                    if best_freq is None or f < best_freq:
                        best_freq = f
                        best_idx = idx
            if best_idx is not None:
                self.states[best_idx] = 1  # mark in-flight
            return best_idx

    def save_chunk(self, idx, data_hex):
        """Store a received chunk (hex string) verifying its hash."""
        with self.lock:
            if self.states[idx] == 2:
                return False
            data = bytes.fromhex(data_hex)
            # verify hash
            h = hashlib.sha256(data).hexdigest()
            if h != self.hashes[idx]:
                raise ValueError(f"Hash mismatch for chunk {idx}")
            # write at offset
            with open(self.temp_path, 'r+b') as f:
                f.seek(idx * self.chunk_size)
                f.write(data)
            self.states[idx] = 2
            # if all received, finalize
            if all(s == 2 for s in self.states):
                os.replace(self.temp_path, self.save_path)
                return True
            return False

    def progress(self):
        done = sum(1 for s in self.states if s == 2)
        return done, self.nb_chunks


class DownloadManager:
    def __init__(self, node):
        self.node = node
        self.sessions = {}  # file_id -> DownloadSession
        self.lock = threading.Lock()
        # limit of simultaneous requests per peer
        self.max_inflight_per_peer = 4
        # track in-flight per peer
        self.peer_inflight = defaultdict(int)

    def register_manifest(self, manifest, peer_id):
        """Record a manifest announced by a peer, ready for download."""
        fid = manifest['file_id']
        with self.lock:
            sess = self.sessions.get(fid)
            if not sess:
                # default save path is filename in cwd
                save_path = manifest.get('filename', fid)
                sess = DownloadSession(manifest, save_path)
                self.sessions[fid] = sess
            sess.mark_peer(peer_id)

    def start_download(self, file_id, save_path=None):
        """Begin downloading a file previously registered by manifest."""
        sess = self.sessions.get(file_id)
        if not sess:
            raise KeyError("Manifest unknown")
        if save_path:
            sess.save_path = save_path
        threading.Thread(target=self._download_loop, args=(sess,), daemon=True).start()

    def _download_loop(self, sess: DownloadSession):
        """Main scheduling loop for a session."""
        while True:
            # choose a chunk to request
            idx = sess.next_chunk()
            if idx is None:
                # Tous les chunks ont été demandés
                # Attendre la réception de tous les chunks
                max_wait = 300  # 5 minutes max
                start = time.time()
                while time.time() - start < max_wait:
                    done, total = sess.progress()
                    if done == total:
                        print(f"[DL] All chunks received for {sess.file_id}")
                        return
                    time.sleep(0.5)
                print(f"[DL] Timeout waiting for chunks in {sess.file_id}")
                return
            # select a peer that is not saturated
            with self.lock:
                candidate = None
                for pid in sess.peers:
                    if self.peer_inflight[pid] < self.max_inflight_per_peer:
                        candidate = pid
                        break
                if candidate:
                    self.peer_inflight[candidate] += 1
            if not candidate:
                # wait a bit until inflight slots free
                time.sleep(0.1)
                continue
            # ask node to send request
            info = self.node.peer_table.get(candidate)
            if info:
                self.node.request_chunk(info['ip'], info['tcp_port'], sess.file_id, idx)
            else:
                print(f"[!] peer {candidate} not in peer_table")
            # little delay to avoid busy loop
            time.sleep(0.01)

    def handle_chunk_data(self, resp, peer_id):
        """Called when a CHUNK_DATA packet is received."""
        fid = resp['file_id']
        idx = resp['chunk_idx']
        print(f"[DL.handle] got chunk {idx} for {fid} from {peer_id}")
        sess = self.sessions.get(fid)
        if not sess:
            print(f"[DL.handle] no session for {fid}")
            return
        try:
            finished = sess.save_chunk(idx, resp['data'])
            print(f"[DL.handle] saved chunk {idx}, finished={finished}")
        except Exception as e:
            print(f"[!] erreur enregistre chunk: {e}")
        # decrement inflight count
        with self.lock:
            if peer_id in self.peer_inflight and self.peer_inflight[peer_id] > 0:
                self.peer_inflight[peer_id] -= 1
        if finished:
            print(f"[DL] fichier {fid} téléchargé -> {sess.save_path}")

    def progress(self, file_id):
        sess = self.sessions.get(file_id)
        if not sess:
            return None
        return sess.progress()
