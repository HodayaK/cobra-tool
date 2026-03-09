#!/usr/bin/env python3
"""
Vulnerable web app for COBRA scenario 8: accepts 'cmd' query parameter
and runs it as a shell command without sanitization (command injection).
Returns command stdout/stderr in the HTTP response.
"""
import os
import subprocess
from flask import Flask, request

app = Flask(__name__)
PORT = 8000


@app.route("/")
def index():
    cmd = request.args.get("cmd", "")
    if not cmd:
        return "Usage: ?cmd=<command>\n", 200
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        out = (result.stdout or "") + (result.stderr or "")
        return out or "(no output)\n", 200
    except Exception as e:
        return str(e) + "\n", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=False)
