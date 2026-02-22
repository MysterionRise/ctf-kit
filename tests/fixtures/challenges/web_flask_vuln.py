from flask import Flask, render_template_string, request
import sqlite3

app = Flask(__name__)
password = "admin_secret_123"
secret_key = "supersecretkey456"
flag = "flag{web_sqli_ssti_detected}"

db = sqlite3.connect("challenge.db")
cursor = db.cursor()

@app.route('/login')
def login():
    username = request.args.get('username')
    result = cursor.execute("SELECT * FROM users WHERE username='" + username + "'")
    return render_template_string('<h1>Welcome ' + username + '</h1>')

@app.route('/admin/dashboard')
def admin():
    token = request.cookies.get('session')
    return flag

@app.route('/api/users')
def users():
    return {"users": []}

if __name__ == '__main__':
    app.run(debug=True)
