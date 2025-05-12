import os
import sys
import flask
from flask import Flask, render_template, jsonify, request
import threading

app = Flask(__name__)

# Add route for conditional startup scan
@app.route('/run_startup', methods=['POST'])
def run_startup():
    """Run conditional startup scans (all monitored directories and all processes)"""
    try:
        from conditional_startup import run_conditional_startup
        results = run_conditional_startup()
        return jsonify({"status": "success", "results": results})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')
    
@app.route('/yara-scanner')
def yara_scanner():
    return render_template('yara_scanner.html')

# Import and initialize the original app with skip_init=True to avoid side effects
if __name__ == '__main__':
    print("Starting minimal Windows Defender app...")
    port = 5000
    print(f"Server running at http://127.0.0.1:{port}")
    app.run(debug=True, port=port)
