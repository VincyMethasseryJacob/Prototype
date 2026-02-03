from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask import Flask, request, render_template, make_response, abort
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(16)
csrf = CSRFProtect(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

@app.route('/login', methods=['GET', 'POST'])
def do_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if check_credentials(username, password):
            session_id = secrets.token_hex(32)
            resp = make_response("Logged in successfully!")
            resp.set_cookie(
                'session_id',
                session_id,
                httponly=True,
                secure=True,
                samesite='Lax'
            )
            return resp
        else:
            return render_template('login.html', error="Invalid credentials", csrf_token=csrf.generate_csrf()), 401
    return render_template('login.html', csrf_token=csrf.generate_csrf())