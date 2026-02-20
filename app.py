import os
import logging

from flask import Flask

from src.hybrid_waf.routes.dashboard import dashboard_bp
from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

app = Flask(__name__)
app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)
app.register_blueprint(dashboard_bp)


@app.errorhandler(404)
def not_found(e):
    return {'error': 'Not found'}, 404

@app.errorhandler(405)
def method_not_allowed(e):
    return {'error': 'Method not allowed'}, 405

@app.errorhandler(500)
def server_error(e):
    return {'error': 'Internal server error'}, 500


if __name__ == '__main__':
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    port = int(os.getenv('PORT', 5000))
    app.run(debug=debug_mode, port=port)