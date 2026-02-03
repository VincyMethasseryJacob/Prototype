import os
from flask_wtf.csrf import CSRFProtect
from flask import Flask, request

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
csrf = CSRFProtect(app)

@app.post("/upload")
@csrf.exempt  # Remove this line if present in your routes, do not use csrf_exempt for state-changing routes
def upload():
    file = request.files.get('file')
    if file is None:
        return {"error": "No file"}, 400
    try:
        xml_bytes = file.read()
        tree = lxml.etree.fromstring(xml_bytes)
        userid = tree.findtext('userid')
        password = tree.findtext('password')
        if not userid or not password:
            return {"error": "Missing userid or password"}, 400
        if checkPassword(userid, password):
            return {"status": "ok"}, 200
        else:
            return {"status": "invalid credentials"}, 401
    except Exception:
        return {"error": "Failed to parse XML"}, 400