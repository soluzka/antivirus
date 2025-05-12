import os
import sys
import threading
import logging
from flask import Flask, jsonify, render_template

# Create a clean app without indentation issues
app = Flask(__name__, 
            template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'),
            static_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static'))

# -- Import other necessary modules --
from conditional_startup import run_conditional_startup

# -- Add support for the Run Conditional Startup button --
@app.route('/run_startup', methods=['POST'])
def run_startup():
    """Run conditional startup scans (all monitored directories and all processes)"""
    try:
        results = run_conditional_startup()
        return jsonify({"status": "success", "results": results})
    except Exception as e:
        logging.error(f"Error running conditional startup: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# -- Main index page --
@app.route('/')
def index():
    return render_template('index.html')

# -- YARA scanner page --
@app.route('/yara-scanner')
def yara_scanner():
    return render_template('yara_scanner.html')

# -- Start the server --
if __name__ == '__main__':
    print("Starting clean Windows Defender app instance...")
    print("Server running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
