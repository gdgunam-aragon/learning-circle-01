import json

from flask import Flask

app = Flask(__name__)


@app.route('/hola-mundo')
def hola_mundo():
    return 'Hola mundo'


@app.route('/hola-json')
def hola_json():
    response = {
        'message': 'Hola mundo'
    }
    return json.dumps(response)
