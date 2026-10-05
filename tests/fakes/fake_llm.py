"""Fake LLM servers emulating llama.cpp, Ollama and mlx-lm HTTP APIs.

Usage: python fake_llm.py <kind> <port> <mode> <state_file>
mode: ok | badjson | fail_unload | fail_reset
The state file records request bodies' keys (never content) for assertions.
"""
from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

kind, port, mode, state_file = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
state = {"requests": [], "loaded": [], "erased": 0, "starts": 0}
try:  # persist across restarts (mlx reset restarts the server)
    with open(state_file) as _f:
        state.update(json.load(_f))
except (FileNotFoundError, json.JSONDecodeError):
    pass
state["starts"] += 1
state["loaded"] = []


def save():
    with open(state_file, "w") as f:
        json.dump(state, f)


FINDING = {"findings": [{"start": 0, "end": 4, "text": "Acme", "category": "CLIENT_RELATIONSHIP",
                         "rationale_code": "CONTRACT_COUNTERPARTY"}]}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path in ("/health", "/v1/models", "/api/version"):
            return self._json(200, {"status": "ok", "version": "fake"})
        if self.path == "/api/ps":
            return self._json(200, {"models": [{"name": m} for m in state["loaded"]]})
        if self.path == "/api/tags":
            return self._json(200, {"models": [{"name": "fake:70b", "digest": "abc123"}]})
        self._json(404, {})

    def do_POST(self):
        body = self._body()
        state["requests"].append({"path": self.path.split("?")[0], "keys": sorted(body.keys()),
                                  "cache_prompt": body.get("cache_prompt"),
                                  "keep_alive": body.get("keep_alive"),
                                  "think": body.get("think"),
                                  "template_kwargs": body.get("chat_template_kwargs"),
                                  "has_schema": bool(body.get("response_format") or body.get("format"))})
        save()
        content = "{not json" if mode == "badjson" else json.dumps(FINDING)
        if kind == "mlx" and mode == "ok":
            # Thinking model output: braces inside the reasoning must not confuse parsing.
            content = "<think>maybe {start: 0} or {other}</think>\n" + content
        if self.path == "/v1/chat/completions":
            return self._json(200, {"choices": [{"message": {"content": content}}]})
        if self.path.startswith("/slots/0"):
            if mode == "fail_reset":
                return self._json(501, {})
            state["erased"] += 1
            save()
            return self._json(200, {"id_slot": 0})
        if self.path == "/api/chat":
            if body.get("model") not in state["loaded"]:
                state["loaded"].append(body.get("model"))
            save()
            return self._json(200, {"message": {"content": content}})
        if self.path == "/api/generate":
            if body.get("keep_alive") == 0 and mode != "fail_unload":
                state["loaded"] = [m for m in state["loaded"] if m != body.get("model")]
            save()
            return self._json(200, {"done": True})
        self._json(404, {})


save()
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
