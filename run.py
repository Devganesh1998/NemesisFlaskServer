from app import create_app
from flask_cors import CORS

config_name = 'development'
app = create_app(config_name)
CORS(app, supports_credentials=True)

@app.route('/')
def home():
    return 'Home'


if __name__ == 'main':
    app.run()
