
"""web.py — خادم Flask البسيط لإبقاء Render سعيدًا"""
import os
from flask import Flask

from core.storage import storage

app = Flask(__name__)


@app.route("/")
def index():
    stats = storage.stats()
    return {
        "status": "online",
        "service": "The Hunter",
        "stats": stats,
    }


@app.route("/health")
def health():
    return {"ok": True}


def run_web():
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
