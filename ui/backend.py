import os
import time
import uuid
from zipfile import ZipFile

import flask
from flask import request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

from wrapper import ItyFuzzOnchain, ItyFuzzOffChin
import multiprocessing
from flask_cors import CORS, cross_origin

app = flask.Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

online_ityfuzz = []

MAX_ONLINE = 2000

results = {}


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(app.static_folder + '/' + path):
        print("serving", path)
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


def sync_results():
    while True:
        to_remove = []
        for i in online_ityfuzz:
            if not i.is_running():
                to_remove.append(i)

            out, status = i.get_output()
            extra = i.get_extra()
            idx = i.get_idx()

            if idx in results and status == "Cancelled":
                del results[idx]
                continue


            results[idx] = {
                "out": out if status != "Cancelled" else "",
                "status": status,
                "extra": extra if status != "Cancelled" else "",
                "name": i.name if status != "Cancelled" else "",
                "ty": i.ty if status != "Cancelled" else "",
            }

        for i in to_remove:
            online_ityfuzz.remove(i)
        break

        time.sleep(5)


UPLOAD_FOLDER = './uploads/'
ALLOWED_EXTENSIONS = {'zip'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    if not allowed_file(file.filename):
        return jsonify({"error": "Invalid file type"}), 400
    uuid_str = str(uuid.uuid4())
    upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], uuid_str)
    os.makedirs(upload_folder)
    filename = secure_filename(file.filename)
    file_path = os.path.join(upload_folder, filename)
    file.save(file_path)
    with ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(upload_folder)
    os.remove(file_path)
    return jsonify({"message": "File uploaded and extracted successfully", "uuid": uuid_str}), 200


@app.route('/submit_onchain', methods=['POST'])
@cross_origin()
def submit_onchain():
    if len(online_ityfuzz) >= MAX_ONLINE:
        return jsonify({'status': 'failed', 'error': 'too many online ityfuzz'}), 400

    data = flask.request.get_json()
    print(data)
    ityfuzz = ItyFuzzOnchain(data)
    online_ityfuzz.append(ityfuzz)
    print(" ".join(ityfuzz.to_command()))
    ityfuzz.run()
    return jsonify({"status": "ok"})


@app.route('/submit_offchain', methods=['POST'])
@cross_origin()
def submit_offchain():
    if len(online_ityfuzz) >= MAX_ONLINE:
        return jsonify({'status': 'failed', 'error': 'too many online ityfuzz'}), 400

    data = flask.request.get_json()
    ityfuzz = ItyFuzzOffChin(data)
    online_ityfuzz.append(ityfuzz)
    print(" ".join(ityfuzz.to_command()))
    ityfuzz.run()
    return jsonify({"status": "ok"})


@app.route('/results')
@cross_origin()
def results_func():
    sync_results()
    return jsonify({k:v for (k, v) in results.items() if k is not None})


@app.route('/results/<idx>')
@cross_origin()
def result(idx):
    return jsonify(results[idx] if idx in results else {})


@app.route('/terminate/<idx>')
@cross_origin()
def terminate(idx):
    for i in online_ityfuzz:
        if i.get_idx() == idx:
            i.cancelit()
            del results[idx]
            return jsonify({"status": "ok"})
    return jsonify({"status": "failed"})


if __name__ == '__main__':
    app.run(debug=True, port=8000, host="0.0.0.0")