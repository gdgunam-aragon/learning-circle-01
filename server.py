import json

from flask import Flask

app = Flask(__name__)


@app.route('/hola-mundo')
def hola():
    return 'Hola mundo'

# :3
