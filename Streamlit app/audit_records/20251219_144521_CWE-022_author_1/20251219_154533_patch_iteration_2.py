from flask_wtf import CSRFProtect
from flask_wtf.csrf import csrf_protect

csrf = CSRFProtect(app)

@app.route('/deleteImage', methods=['POST'])
@csrf_protect
def deleteImage():
    filename = request.form.get('filename')
    if not filename or '/' in filename or '..' in filename:
        return {'status': 'error', 'message': 'Invalid filename'}, 400

    folder = os.path.join(os.getcwd(), 'images')
    filepath = os.path.join(folder, filename)

    if not os.path.exists(filepath):
        return {'status': 'error', 'message': 'File does not exist'}, 404

    try:
        os.remove(filepath)
        return {'status': 'success', 'message': 'File deleted'}
    except Exception as e:
        return {'status': 'error', 'message': str(e)}, 500