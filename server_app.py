from flask import Flask, jsonify
import psutil
import socket

# Create a Flask web application
app = Flask(__name__)

# --- Main endpoint ---
# Returns the hostname of the server to show which one we've hit.
@app.route('/')
def index():
    return f"<h1>Hello from Server: {socket.gethostname()}</h1>"

# --- Metrics endpoint ---
# Returns the server's current CPU usage as a JSON object.
# This is the API our controller will call.
@app.route('/metrics')
def metrics():
    cpu_usage = psutil.cpu_percent(interval=0.1)
    return jsonify({'cpu_percent': cpu_usage})

# --- Load endpoint ---
# An endpoint to simulate high CPU load for our demo.
# Running this will make the CPU spike.
@app.route('/load')
def load():
    # A simple, silly loop to waste CPU cycles
    for i in range(10**7):
        _ = i * i
    return "Load simulation complete."

if __name__ == '__main__':
    # Run the app on all available network interfaces on port 5000
    app.run(host='0.0.0.0', port=5000)