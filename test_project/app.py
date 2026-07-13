from flask import Flask, request, render_template_string
import sqlite3
import subprocess

app = Flask(__name__)

AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection via string formatting
    cursor.execute("SELECT * FROM users WHERE username = '%s'" % username)
    return str(cursor.fetchone())

@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # Reflected XSS - unescaped template rendering
    return render_template_string("<h1>Hello " + name + "</h1>")

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd")
    # Dangerous eval usage
    result = eval(cmd)
    return str(result)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Shell injection via subprocess with shell=True
    output = subprocess.check_output("ping -c 1 " + host, shell=True)
    return output
