from flask import Flask, request, render_template_string

app = Flask(__name__)
app.secret_key = "s3cr3t_k3y_d0nt_l34k"

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

@app.route('/admin')
def admin():
    password = "admin123"
    token = request.cookies.get('session')
    if token == password:
        return "flag{ssti_and_hardcoded_creds}"
    return "Access denied"
