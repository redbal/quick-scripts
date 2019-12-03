import os
from flask import Flask
app = Flask(__name__)

DPORT = os.environ.get('DPORT')

@app.route('/')
def hello():
    return "Hello from lp!"

if __name__ == '__main__':
    app.run(host = '0.0.0.0',port=DPORT)
