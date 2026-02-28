import time

from flask import Flask, jsonify, render_template_string, request


PAGE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Archipel Control</title>
  <style>
    :root {
      --bg: #f4f6f8;
      --fg: #122027;
      --muted: #4f6470;
      --card: #ffffff;
      --line: #d7e0e5;
      --accent: #006e6d;
      --accent2: #c94f2d;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", sans-serif;
      color: var(--fg);
      background:
        radial-gradient(1200px 600px at 90% -20%, #b8d6d2 0%, transparent 60%),
        radial-gradient(900px 400px at -10% 10%, #f3ccb7 0%, transparent 50%),
        var(--bg);
    }
    .wrap { max-width: 1180px; margin: 24px auto; padding: 0 16px 60px; }
    .hero {
      background: linear-gradient(115deg, #0f5560, #1e8a7a);
      color: #fff;
      border-radius: 16px;
      padding: 18px 20px;
      margin-bottom: 16px;
      box-shadow: 0 12px 28px rgba(0,0,0,.15);
    }
    .hero h1 { margin: 0 0 6px; font-size: 28px; letter-spacing: .3px; }
    .hero p { margin: 0; opacity: .95; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 12px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 12px;
      box-shadow: 0 6px 18px rgba(0,0,0,.06);
    }
    h3 { margin: 0 0 10px; font-size: 17px; color: #163741; }
    label { display: block; margin: 6px 0 4px; color: var(--muted); font-size: 13px; }
    input, textarea {
      width: 100%;
      padding: 8px 10px;
      border: 1px solid #c7d2d9;
      border-radius: 8px;
      font-size: 14px;
      background: #fff;
    }
    textarea { min-height: 64px; resize: vertical; }
    button {
      margin-top: 8px;
      border: 0;
      background: var(--accent);
      color: #fff;
      padding: 8px 12px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
    }
    button.alt { background: var(--accent2); }
    .mono { font-family: Consolas, "Courier New", monospace; font-size: 12px; }
    .small { color: var(--muted); font-size: 12px; }
    .list { max-height: 250px; overflow: auto; border-top: 1px solid #e2e8ec; margin-top: 8px; padding-top: 8px; }
    .item { padding: 5px 0; border-bottom: 1px dashed #edf2f4; }
    .badge { display: inline-block; padding: 2px 6px; border-radius: 999px; font-size: 11px; background: #e4f2f1; color: #084a49; }
    .ok { color: #0c7a2f; font-weight: 600; }
    .err { color: #a6332a; font-weight: 600; }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>Archipel Control Panel</h1>
      <p>Node <span id="node" class="mono"></span> | TCP <span id="port" class="mono"></span> | Peers <span id="peerCount"></span></p>
    </div>

    <div class="grid">
      <div class="card">
        <h3>Status</h3>
        <div id="statusBox" class="small">Loading...</div>
      </div>

      <div class="card">
        <h3>Send Encrypted Message</h3>
        <label>Peer ID</label>
        <input id="msgPeer" placeholder="peer id">
        <label>Message</label>
        <textarea id="msgText" placeholder="hello"></textarea>
        <button onclick="sendMsg()">Send</button>
        <div id="msgResult" class="small"></div>
      </div>

      <div class="card">
        <h3>Trust Peer</h3>
        <label>Peer ID</label>
        <input id="trustPeer" placeholder="peer id">
        <button class="alt" onclick="trustPeer()">Trust</button>
        <div id="trustResult" class="small"></div>
      </div>

      <div class="card">
        <h3>File Transfer</h3>
        <label>Target Peer ID</label>
        <input id="sendPeer" placeholder="peer id">
        <label>Local File Path</label>
        <input id="sendPath" placeholder="C:\\path\\file.bin">
        <button onclick="sendFile()">Send Manifest</button>
        <hr>
        <label>File ID</label>
        <input id="dlFileId" placeholder="sha256 file id">
        <label>Output Path (optional)</label>
        <input id="dlPath" placeholder="downloaded.bin">
        <button onclick="downloadFile()">Download</button>
        <div id="fileResult" class="small"></div>
      </div>

      <div class="card">
        <h3>Ask AI (optional)</h3>
        <label>Question</label>
        <textarea id="askText" placeholder="/ask ..."></textarea>
        <button onclick="askAi()">Ask</button>
        <div id="askResult" class="small"></div>
      </div>

      <div class="card">
        <h3>Peers</h3>
        <div id="peers" class="list mono"></div>
      </div>

      <div class="card">
        <h3>Files/Downloads</h3>
        <div id="downloads" class="list mono"></div>
      </div>

      <div class="card">
        <h3>Messages</h3>
        <div id="messages" class="list mono"></div>
      </div>

      <div class="card">
        <h3>Events</h3>
        <div id="events" class="list mono"></div>
      </div>
    </div>
  </div>

  <script>
    async function post(url, body) {
      const r = await fetch(url, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(body)
      });
      return r.json();
    }

    function showResult(id, payload) {
      const e = document.getElementById(id);
      if (payload.ok) e.innerHTML = '<span class="ok">OK</span> ' + (payload.message || "");
      else e.innerHTML = '<span class="err">ERR</span> ' + (payload.error || "unknown");
    }

    async function sendMsg() {
      const payload = await post("/api/msg", {
        peer_id: document.getElementById("msgPeer").value,
        text: document.getElementById("msgText").value
      });
      showResult("msgResult", payload);
    }

    async function trustPeer() {
      const payload = await post("/api/trust", { peer_id: document.getElementById("trustPeer").value });
      showResult("trustResult", payload);
    }

    async function sendFile() {
      const payload = await post("/api/send", {
        peer_id: document.getElementById("sendPeer").value,
        filepath: document.getElementById("sendPath").value
      });
      showResult("fileResult", payload);
    }

    async function downloadFile() {
      const payload = await post("/api/download", {
        file_id: document.getElementById("dlFileId").value,
        output_path: document.getElementById("dlPath").value
      });
      showResult("fileResult", payload);
    }

    async function askAi() {
      const payload = await post("/api/ask", { query: document.getElementById("askText").value });
      if (payload.ok) {
        document.getElementById("askResult").innerHTML = '<span class="ok">OK</span> ' + payload.answer;
      } else {
        showResult("askResult", payload);
      }
    }

    function esc(text) {
      return String(text ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
    }

    async function refreshState() {
      const r = await fetch("/api/state");
      const st = await r.json();
      document.getElementById("node").textContent = st.node_id;
      document.getElementById("port").textContent = st.tcp_port;
      document.getElementById("peerCount").textContent = st.peers;
      document.getElementById("statusBox").innerHTML =
        "Known manifests: <b>" + st.known_manifests + "</b><br>" +
        "AI ready: <b>" + (st.ai_ready ? "yes" : "no") + "</b>";

      document.getElementById("peers").innerHTML = Object.entries(st.peer_table || {}).map(([pid, info]) =>
        `<div class="item"><span class="badge">${info.trusted ? "trusted" : "untrusted"}</span> ${esc(pid)} @ ${esc(info.ip)}:${esc(info.tcp_port)}</div>`
      ).join("") || "<div class='small'>No peers yet.</div>";

      document.getElementById("downloads").innerHTML = Object.entries(st.downloads || {}).map(([fid, d]) =>
        `<div class="item">${esc(fid)}<br>${esc(d.file)}<br>${d.done}/${d.total}</div>`
      ).join("") || "<div class='small'>No transfers yet.</div>";

      const msgs = st.messages || [];
      document.getElementById("messages").innerHTML = msgs.slice(-30).map(m =>
        `<div class="item">[${m.direction}] ${esc(m.peer)}: ${esc(m.text)}</div>`
      ).join("") || "<div class='small'>No messages yet.</div>";

      const ev = st.events || [];
      document.getElementById("events").innerHTML = ev.slice(-40).map(e =>
        `<div class="item">[${esc(e.level)}] ${esc(e.text)}</div>`
      ).join("") || "<div class='small'>No events yet.</div>";
    }

    refreshState();
    setInterval(refreshState, 2000);
  </script>
</body>
</html>
"""


def create_app(node, gemini_client):
    app = Flask(__name__)
    ask_context = []

    @app.get("/")
    def index():
        return render_template_string(PAGE)

    @app.get("/api/state")
    def state():
        st = node.node_status()
        st["peer_table"] = node.peer_table
        st["ai_ready"] = gemini_client.is_ready()
        return jsonify(st)

    @app.post("/api/msg")
    def send_msg():
        body = request.get_json(force=True, silent=True) or {}
        peer_id = (body.get("peer_id") or "").strip()
        text = (body.get("text") or "").strip()
        if not peer_id or not text:
            return jsonify({"ok": False, "error": "peer_id and text are required"})
        try:
            node.send_message(peer_id, text)
            return jsonify({"ok": True, "message": "Message sent"})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)})

    @app.post("/api/trust")
    def trust():
        body = request.get_json(force=True, silent=True) or {}
        peer_id = (body.get("peer_id") or "").strip()
        if not peer_id:
            return jsonify({"ok": False, "error": "peer_id is required"})
        try:
            node.trust_peer(peer_id)
            return jsonify({"ok": True, "message": f"{peer_id} trusted"})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)})

    @app.post("/api/send")
    def send():
        body = request.get_json(force=True, silent=True) or {}
        peer_id = (body.get("peer_id") or "").strip()
        filepath = (body.get("filepath") or "").strip()
        if not peer_id or not filepath:
            return jsonify({"ok": False, "error": "peer_id and filepath are required"})
        try:
            file_id = node.send_file(peer_id, filepath)
            return jsonify({"ok": True, "message": f"Manifest sent ({file_id})", "file_id": file_id})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)})

    @app.post("/api/download")
    def download():
        body = request.get_json(force=True, silent=True) or {}
        file_id = (body.get("file_id") or "").strip()
        output_path = (body.get("output_path") or "").strip() or None
        if not file_id:
            return jsonify({"ok": False, "error": "file_id is required"})
        try:
            node.dl_manager.start_download(file_id, output_path)
            return jsonify({"ok": True, "message": f"Download started for {file_id}"})
        except Exception as exc:
            return jsonify({"ok": False, "error": str(exc)})

    @app.post("/api/ask")
    def ask():
        body = request.get_json(force=True, silent=True) or {}
        query = (body.get("query") or "").strip()
        if not query:
            return jsonify({"ok": False, "error": "query is required"})
        result = gemini_client.ask(ask_context, query)
        if not result.get("ok"):
            return jsonify(result)
        answer = result["text"]
        ask_context.append(f"user: {query}")
        ask_context.append(f"assistant: {answer}")
        ask_context[:] = ask_context[-16:]
        node._log_event("ai", "AI query processed")
        return jsonify({"ok": True, "answer": answer})

    return app


def run_ui(node, gemini_client, host, port):
    app = create_app(node, gemini_client)
    node._log_event("info", f"UI started on http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)

