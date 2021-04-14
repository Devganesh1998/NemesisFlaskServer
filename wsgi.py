from app import create_app
from flask_cors import CORS

config_name = 'produciton'
app = create_app(config_name)
CORS(app, supports_credentials=True, expose_headers="Set-Cookie", allow_headers=['X-Requested-With', 'X-HTTP-Method-Override', 'Content-Type', 'Accept'])

@app.route('/')
def home():
    return 'Home'


if __name__ == 'main':
    app.run()
