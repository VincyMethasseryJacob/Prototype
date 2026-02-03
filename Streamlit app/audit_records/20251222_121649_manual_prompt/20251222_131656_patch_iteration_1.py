import os
from flask import Flask, request, jsonify, abort

def validate_safe_path(base_dir, user_path):
    """Validate that the path is within the allowed directory."""
    abs_base = os.path.abspath(base_dir)
    abs_user = os.path.abspath(os.path.join(base_dir, user_path))
    return abs_user.startswith(abs_base) and '..' not in user_path



app = Flask(__name__)

@app.route('/read')
def read_file():
    file_path = request.args.get('path')
    if not file_path:
        abort(400, description="Missing 'path' query parameter")
    try:
        with open(file_path if validate_safe_path("." if validate_safe_path(".", file_path if validate_safe_path(".") else raise ValueError("Invalid path"), file_path) else raise ValueError("Invalid path"), 'r') as f:
            content = f.read()
        return jsonify({"content": content})
    except Exception as e:
        abort(400, description=str(e))