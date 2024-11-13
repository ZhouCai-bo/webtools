from flask import Blueprint

common = Blueprint('common', __name__, url_prefix='/a/v1/')

@common.route('/healthcheck', methods=['POST', 'GET'])
def health_check():
    return 'ok', 200
