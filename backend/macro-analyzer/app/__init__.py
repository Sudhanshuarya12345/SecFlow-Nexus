from flask import Flask
from flask_cors import CORS


def create_app() -> Flask:
    app = Flask(__name__)
    CORS(app)

    from app.routes import bp
    app.register_blueprint(bp, url_prefix="/api/macro-analyzer")

    return app
