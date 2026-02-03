from flask import Flask, request, redirect, url_for, session, abort, render_template, make_response
import os
import secrets

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

def require_authentication():
    if not is_authenticated():
        abort(403)

@app.after_request
def set_csrf_cookie(response):
    csrf_token = generate_csrf_token()
    response.set_cookie('csrf_token', csrf_token, secure=True, httponly=True, samesite='Lax')
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'password123':
            session['user_authenticated'] = True
            return redirect(url_for('upload_file'))
        else:
            return 'Invalid credentials', 401
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    require_authentication()
    token = request.form.get('csrf_token', None)
    cookie_token = request.cookies.get('csrf_token', None)
    if not token or not cookie_token or token != cookie_token or token != session.get('csrf_token'):
        abort(400, description="Invalid CSRF token")
    session.pop('user_authenticated', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    require_authentication()
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
        safe_filename = file.filename  # Let Werkzeug handle filename sanitization if necessary
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        file.save(filepath)
        return 'File uploaded successfully'
    csrf_token = generate_csrf_token()
    logout_csrf_token = csrf_token
    response = make_response(render_template('upload.html', csrf_token=csrf_token, logout_csrf_token=logout_csrf_token))
    response.set_cookie('csrf_token', csrf_token, secure=True, httponly=True, samesite='Lax')
    return response

@app.before_request
def csrf_protect():
    if request.method == "POST":
        if request.endpoint in ('logout', 'upload_file'):
            token = request.form.get('csrf_token', None)
            cookie_token = request.cookies.get('csrf_token', None)
            if not token or not cookie_token or token != cookie_token or token != session.get('csrf_token'):
                abort(400, description="Invalid CSRF token")
            if not is_authenticated():
                abort(403)

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ['true', '1', 'yes']
    app.run(debug=debug_mode)
```

**Create a `templates/login.html`:**
```html
<!doctype html>
<title>Login</title>
<h1>Login</h1>
<form method="post">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
```

**Create a `templates/upload.html`:**
```html
<!doctype html>
<title>Upload File</title>
<h1>Upload new File</h1>
<form method="post" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  <input type="submit" value="Upload">
</form>
<br>
<form method="post" action="{{ url_for('logout') }}">
  <input type="hidden" name="csrf_token" value="{{ logout_csrf_token }}">
  <input type="submit" value="Logout">
</form>