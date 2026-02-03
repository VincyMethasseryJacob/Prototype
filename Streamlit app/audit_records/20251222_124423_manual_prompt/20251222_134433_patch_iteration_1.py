from flask import Flask, request, redirect, url_for, session, abort, make_response
import os
import secrets
from urllib.parse import html_escape

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = secrets.token_hex(16)

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe()
    return session['csrf_token']

def is_authenticated():
    return session.get('user_authenticated', False)

@app.after_request
def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, secure=True, httponly=False, samesite='Lax')
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Example user check
        if username == 'admin' and password == 'password123':
            session['user_authenticated'] = True
            return redirect(url_for('upload_file'))
        else:
            return 'Invalid credentials', 401
    html = '''
    <!doctype html>
    <title>Login</title>
    <h1>Login</h1>
    <form method=post>
      Username: <input type=text name=username><br>
      Password: <input type=password name=password><br>
      <input type=submit value=Login>
    </form>
    '''
    return html

@app.route('/logout')
def logout():
    session.pop('user_authenticated', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if not is_authenticated():
        return redirect(url_for('login'))
    if request.method == 'POST':
        token = request.form.get('csrf_token', None)
        cookie_token = request.cookies.get('csrf_token', None)
        if not token or not cookie_token or token != cookie_token or token != session.get('csrf_token'):
            abort(400, description="Invalid CSRF token")
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
        safe_filename = html_escape(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        file.save(filepath)
        return 'File uploaded successfully'
    csrf_token = generate_csrf_token()
    html = f'''
    <!doctype html>
    <title>Upload File</title>
    <h1>Upload new File</h1>
    <form method=post enctype=multipart/form-data>
      <input type=file name=file>
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <input type=submit value=Upload>
    </form>
    <br>
    <a href="{url_for('logout')}">Logout</a>
    '''
    response = make_response(html)
    response.set_cookie('csrf_token', csrf_token, secure=True, httponly=False, samesite='Lax')
    return response

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 'yes']
    app.run(debug=debug_mode)