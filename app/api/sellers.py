from flask import jsonify, request, g
from .. import db
from ..models import User, Permission
from . import api
from .errors import forbidden, validation_error, bad_request
from .decorators import permission_required
from ..email import send_email


@api.route('/sellers/add-opportunity', methods=['POST'])
@permission_required(Permission.ADD_OPORTUNITY)
def add_opportunity():
    user_email = request.json.get('email')
    user = User.query.filter_by(email=user_email).first()
    if user is None:
        raise validation_error(400)
    opportunities = request.json.get('opportunities')
    if user.opportunity is None:
        user.opportunity = 0
    user.opportunity = user.opportunity + int(opportunities)
    db.session.add(user)
    db.session.commit()
    return jsonify(201)


@api.route('/sellers/create-seller', methods=['POST'])
@permission_required(Permission.ADMIN)
def create_seller():
    username = request.json.get('username')
    email = request.json.get('email')
    if User.query.filter_by(username=username).first() is not None:
        raise validation_error(400)
    if User.query.filter_by(email=email).first() is not None:
        raise validation_error(400)
    user = User.from_json(request.json)
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_json(), 201)


@api.route('/sellers/user-to-seller', methods=['POST'])
@permission_required(Permission.ADMIN)
def user_to_seller():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if user is None:
        raise validation_error(400)
    user.role_id = 2
    token = user.generation_confirmed_token()  # CREATING THE TOKEN
    send_email(user.email, 'Confirm Your Account', 'api/email/confirm', user=user, token=token)
    return jsonify(user.to_json(), 201)

