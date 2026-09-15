"""web.py — خادم Flask البسيط لإبقاء Render سعيدًا"""
import os
from flask import Flask

from core.storage import storage

app = Flask(__name__)


@app.route("/")
def index():
    # إرجاع نص قصير جداً لتجنب خطأ Output Too Large في cron-job
    return "OK", 200


@app.route("/health")
def health():
    return {"ok": True}


@app.route("/stats")
def stats():
    # نقل الإحصائيات لمسار منفصل لطلبها عند الحاجة فقط
    return {
        "status": "online",
        "service": "The Hunter",
        "stats": storage.stats(),
    }


def run_web():
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
    
