from flask import jsonify, request, g
from .. import db
from ..models import User
from . import api
from .errors import validation_error, bad_request
from ..email import send_email


@api.route('/users/<int:id>')
def get_user(id):
    user = User.query.get_or_404(id)
    return jsonify(user.to_json())


# @api.route('/users/<int:id>', methods=['PUT'])
# def update_username(id):
#     new_username = request.json.get('new-username')
#     if User.query.filter_by(username=new_username).first() is not None:
#         raise validation_error(400)
#     user = User.query.get_or_404(id)
#     print(user)
#     user.username = new_username.lower()
#     db.session.add(user)
#     db.session.commit()
#     return jsonify(user.to_json())


# @api.route('users/change-email', methods=['GET', 'POST'])
# def change_email_request():
#     password = request.json.get('password')
#     if g.current_user.verify_password(password):
#         new_email = request.json.get('new-email')
#         token = g.current_user.generate_email_change_token(new_email)
#         send_email(new_email, 'Confirm your email address', 'auth/email/change_email', user=g.current_user, token=token)
#         return jsonify({'token': token})
#     return bad_request('Wrong password')


# @api.route('users/change-email/<token>')
# def change_email(token):
#     if g.current_user.change_email(token):
#         db.session.commit()
#         return jsonify(201)
#     return bad_request('Wrong password')


# @api.route('users/change-password', methods=['GET', 'POST'])
# def change_password():
#     old_password = request.json.get('old-password')
#     if g.current_user.verify_password(old_password):
#         new_password = request.json.get('new-password')
#         g.current_user.password = new_password
#         db.session.add(g.current_user)
#         db.session.commit()
#         return jsonify(201)
#     return bad_request('Wrong password')