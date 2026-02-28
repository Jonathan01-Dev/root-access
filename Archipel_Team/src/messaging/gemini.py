import json
import os
import urllib.error
import urllib.request


class GeminiClient:
    """Isolated Gemini integration, optional and disable-able for offline mode."""

    def __init__(self, enabled=True, api_key=None, model="gemini-1.5-pro"):
        self.enabled = enabled
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = model

    def is_ready(self):
        return self.enabled and bool(self.api_key)

    def ask(self, conversation_context, user_query):
        if not self.enabled:
            return {"ok": False, "error": "AI disabled (--no-ai)."}
        if not self.api_key:
            return {"ok": False, "error": "GEMINI_API_KEY missing."}

        prompt = self._build_prompt(conversation_context, user_query)
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            text = self._extract_text(data)
            if not text:
                return {"ok": False, "error": "Empty AI response."}
            return {"ok": True, "text": text}
        except urllib.error.HTTPError as exc:
            return {"ok": False, "error": f"HTTP {exc.code}: Gemini unavailable."}
        except Exception:
            return {"ok": False, "error": "Gemini request failed (offline or timeout)."}

    @staticmethod
    def _build_prompt(context, query):
        ctx = "\n".join(context[-8:]) if context else "(no context)"
        return (
            "You are Archipel assistant in a local secure P2P demo.\n"
            f"Conversation context:\n{ctx}\n\n"
            f"User query:\n{query}\n"
        )

    @staticmethod
    def _extract_text(data):
        try:
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception:
            return None

