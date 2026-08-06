#!/usr/bin/env python3
import json
import os
import subprocess

from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>🐉 GOODS-DRAGON - Web UI</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #0d1117; color: #c9d1d9; }
        .container { max-width: 900px; margin-top: 30px; }
        .card { background: #161b22; border: 1px solid #30363d; }
        .card-header { background: #21262d; color: #f0f6fc; }
        .btn-primary { background: #238636; border: none; }
        .btn-primary:hover { background: #2ea043; }
        .btn-danger { background: #da3633; border: none; }
        .btn-danger:hover { background: #f85149; }
        .output-box { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 15px; max-height: 400px; overflow-y: auto; font-family: monospace; white-space: pre-wrap; }
        .form-control { background: #0d1117; color: #c9d1d9; border: 1px solid #30363d; }
        .form-control:focus { background: #0d1117; color: #c9d1d9; border-color: #58a6ff; box-shadow: none; }
    </style>
</head>
<body>
<div class="container">
    <div class="text-center mb-4">
        <h1 class="display-4">🐉 GOODS-DRAGON</h1>
        <p class="lead">Advanced Pentesting & Bug Bounty Tool</p>
        <p><small>Author: zeus (z4) | Telegram: @iM_z4</small></p>
    </div>

    <div class="card">
        <div class="card-header">⚙️ Command Runner</div>
        <div class="card-body">
            <form id="runForm">
                <div class="mb-3">
                    <label for="target" class="form-label">Target (domain/IP/Phone)</label>
                    <input type="text" class="form-control" id="target" placeholder="e.g. example.com" value="szmarket.ru">
                </div>
                <div class="mb-3">
                    <label for="module" class="form-label">Select Module</label>
                    <select class="form-select" id="module">
                        <option value="recon">Reconnaissance (Subdomain, Wayback, Active, Takeover, Cloud)</option>
                        <option value="web" selected>Web Vulnerabilities (Full scan)</option>
                        <option value="scan">Network Scan (Port, SSL, S3, Brute)</option>
                        <option value="smart">Smart Scan (Rate limit detection)</option>
                        <option value="report">Generate HackerOne Report</option>
                    </select>
                </div>
                <div class="mb-3">
                    <label for="threads" class="form-label">Threads (default 30)</label>
                    <input type="number" class="form-control" id="threads" value="30">
                </div>
                <div class="form-check mb-3">
                    <input class="form-check-input" type="checkbox" id="verbose" checked>
                    <label class="form-check-label" for="verbose">Verbose mode</label>
                </div>
                <div class="form-check mb-3">
                    <input class="form-check-input" type="checkbox" id="report" checked>
                    <label class="form-check-label" for="report">Generate HTML report</label>
                </div>
                <button type="submit" class="btn btn-primary w-100" id="runBtn">🚀 Run Scan</button>
            </form>
        </div>
    </div>

    <div class="card mt-4">
        <div class="card-header">📤 Output</div>
        <div class="card-body">
            <div id="output" class="output-box">Ready to run...</div>
        </div>
    </div>
</div>

<script>
document.getElementById('runForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const target = document.getElementById('target').value.trim();
    if (!target) { alert('Please enter a target.'); return; }
    const module = document.getElementById('module').value;
    const threads = document.getElementById('threads').value || 30;
    const verbose = document.getElementById('verbose').checked;
    const report = document.getElementById('report').checked;

    const outputDiv = document.getElementById('output');
    outputDiv.textContent = 'Running scan... Please wait.';
    document.getElementById('runBtn').disabled = true;

    fetch('/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, module, threads, verbose, report })
    })
    .then(response => response.json())
    .then(data => {
        outputDiv.textContent = data.output || 'Done.';
        document.getElementById('runBtn').disabled = false;
    })
    .catch(err => {
        outputDiv.textContent = 'Error: ' + err;
        document.getElementById('runBtn').disabled = false;
    });
});
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/run", methods=["POST"])
def run():
    data = request.json
    target = data.get("target")
    module = data.get("module")
    threads = data.get("threads", 30)
    verbose = data.get("verbose", True)
    report = data.get("report", True)

    cmd = f"python main.py {module} -t {target} -th {threads}"
    if verbose:
        cmd += " -v"
    if report:
        cmd += " --report"

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=300
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Scan timed out after 300 seconds."
    except Exception as e:
        output = f"Error: {str(e)}"

    return jsonify({"output": output})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
