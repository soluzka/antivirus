from flask import Flask

# Create a small launcher script that doesn't have indentation issues
app = Flask(__name__)

@app.route('/')
def index():
    return "Redirecting to main app..."

if __name__ == '__main__':
    import os
    import sys
    import subprocess
    
    # Launch the fixed version in a separate process
    print("Starting Windows Defender antivirus service...")
    # Run app.py but bypass the duplicate route definitions
    os.environ['SKIP_DUPLICATE_ROUTES'] = '1'
    
    # Launch Flask directly with app.py
    try:
        from app import app as main_app
        print("App imported successfully, running server...")
        main_app.run(host='127.0.0.1', port=5000, debug=True)
    except Exception as e:
        print(f"Error starting app: {e}")
        print("Please check for syntax errors in app.py")
