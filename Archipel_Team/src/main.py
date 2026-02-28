import argparse
import os
import shlex
import sys
import threading
import time

from messaging.gemini import GeminiClient
from network.node import ArchipelNode


def init_node(args):
    os.environ["TCP_PORT"] = str(args.port)
    os.environ["IDENTITY_FILE"] = args.identity_file
    if args.local_ip:
        os.environ["ARCHIPEL_LOCAL_IP"] = args.local_ip
    if args.clear_peer_db and os.path.exists(args.peer_db):
        os.remove(args.peer_db)

    node = ArchipelNode(
        args.node_id or f"NODE_{int(time.time())}",
        tcp_port=args.port,
        db_file=args.peer_db,
        local_ip=args.local_ip,
    )
    if args.node_id is None:
        node.node_id = node.verify_key.encode().hex()[:32]
    node.start()
    return node


def print_help():
    print("Commands:")
    print("  peers")
    print("  msg <node_id> <text>")
    print("  msg @archipel-ai <question>")
    print("  /ask <question>")
    print("  send <node_id> <filepath>")
    print("  receive")
    print("  download <file_id> [output_path]")
    print("  status")
    print("  trust <node_id>")
    print("  quit")


def run_cli(node, gemini):
    context = []
    print_help()

    while True:
        try:
            raw = input("archipel> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not raw:
            continue
        if raw in ("help", "?"):
            print_help()
            continue
        if raw in ("quit", "exit"):
            break

        parts = shlex.split(raw)
        cmd = parts[0]
        try:
            if cmd == "peers":
                if not node.peer_table:
                    print("No peers discovered yet.")
                for pid, info in node.peer_table.items():
                    trust = "trusted" if info.get("trusted") else "untrusted"
                    print(f"{pid} -> {info.get('ip')}:{info.get('tcp_port')} ({trust})")
            elif cmd == "msg" and len(parts) >= 3:
                target = parts[1]
                text = " ".join(parts[2:])
                if target == "@archipel-ai":
                    result = gemini.ask(context, text)
                    if result["ok"]:
                        reply = result["text"]
                        context.append(f"user: {text}")
                        context.append(f"assistant: {reply}")
                        print(f"[AI] {reply}")
                    else:
                        print(f"[AI] {result['error']}")
                else:
                    node.send_message(target, text)
                    context.append(f"to:{target} {text}")
                    print("Message sent.")
            elif cmd == "/ask" and len(parts) >= 2:
                query = " ".join(parts[1:])
                result = gemini.ask(context, query)
                if result["ok"]:
                    reply = result["text"]
                    context.append(f"user: {query}")
                    context.append(f"assistant: {reply}")
                    print(f"[AI] {reply}")
                else:
                    print(f"[AI] {result['error']}")
            elif cmd == "send" and len(parts) == 3:
                file_id = node.send_file(parts[1], parts[2])
                print(f"Manifest sent. file_id={file_id}")
            elif cmd == "receive":
                if not node.dl_manager.sessions:
                    print("No announced files yet.")
                for fid, sess in node.dl_manager.sessions.items():
                    done, total = sess.progress()
                    print(f"{fid} | file={sess.save_path} | progress={done}/{total}")
            elif cmd == "download" and len(parts) >= 2:
                fid = parts[1]
                out = parts[2] if len(parts) >= 3 else None
                node.dl_manager.start_download(fid, out)
                print(f"Download started for {fid}")
            elif cmd == "status":
                st = node.node_status()
                print(f"node_id={st['node_id']}")
                print(f"tcp_port={st['tcp_port']}")
                print(f"peers={st['peers']}")
                print(f"known_manifests={st['known_manifests']}")
                for fid, info in st["downloads"].items():
                    print(f"{fid}: {info['done']}/{info['total']} -> {info['file']}")
            elif cmd == "trust" and len(parts) == 2:
                node.trust_peer(parts[1])
                print(f"{parts[1]} marked trusted.")
            else:
                print("Unknown command. Type 'help'.")
        except Exception as exc:
            print(f"Command failed: {exc}")


def _start(args):
    node = init_node(args)
    gemini = GeminiClient(enabled=not args.no_ai, api_key=args.ai_api_key)

    print(f"Archipel node started: {node.node_id}")
    if args.no_ai:
        print("AI mode: disabled (--no-ai)")
    else:
        print("AI mode: enabled if GEMINI_API_KEY is configured")

    if args.ui:
        try:
            from ui.web import run_ui
        except ModuleNotFoundError:
            print("UI unavailable: install dependencies with `pip install -r ../requirements.txt`")
            node.running = False
            return
        if args.cli:
            ui_thread = threading.Thread(
                target=run_ui,
                args=(node, gemini, args.ui_host, args.ui_port),
                daemon=True,
            )
            ui_thread.start()
            print(f"UI available at http://{args.ui_host}:{args.ui_port}")
            run_cli(node, gemini)
        else:
            print(f"UI available at http://{args.ui_host}:{args.ui_port}")
            run_ui(node, gemini, args.ui_host, args.ui_port)
    else:
        run_cli(node, gemini)

    print("Stopping node...")
    node.running = False


def build_parser():
    parser = argparse.ArgumentParser(description="Archipel CLI/UI")
    sub = parser.add_subparsers(dest="subcmd")

    start = sub.add_parser("start", help="Start a local Archipel node")
    start.add_argument("--port", type=int, default=7777)
    start.add_argument("--node-id", default=None)
    start.add_argument("--identity-file", default="identity.key")
    start.add_argument("--peer-db", default="peer_table.json")
    start.add_argument("--clear-peer-db", action="store_true")
    start.add_argument("--local-ip", default=None, help="Bind/select this LAN IPv4 for multicast")
    start.add_argument("--no-ai", action="store_true")
    start.add_argument("--ai-api-key", default=None)
    start.add_argument("--ui", action="store_true", help="Start web UI")
    start.add_argument("--ui-host", default="127.0.0.1")
    start.add_argument("--ui-port", type=int, default=8080)
    start.add_argument("--cli", action="store_true", help="Keep interactive CLI when UI is enabled")

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subcmd == "start":
        _start(args)
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
