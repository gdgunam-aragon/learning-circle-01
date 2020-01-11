from flask import jsonify, request
from .. import db
from ..models import User
from ..email import send_email
from .errors import validation_error, bad_request
from . import api_ops


@api_ops.route('/register', methods=['POST'])
def register():  # THIS METHOD IS GOING TO REGISTER THE NEW USERS
    username = request.json.get('username')
    email = request.json.get('email')
    if User.query.filter_by(username=username).first() is not None:
        raise validation_error(400)
    if User.query.filter_by(email=email).first() is not None:
        raise validation_error(400)
    user = User.from_json(request.json)
    db.session.add(user)
    db.session.commit()  # HERE WE GONNA TO MAKE A COMMIT ON THE DB BECAUSE IF IT WAITS AFTER THE REQUEST IT WILL
    # BE TO LATE TO PASS THE ID OF THE NEW USER AN SEND IT TO HIM IN A EMAIL.
    token = user.generation_confirmed_token()  # CREATING THE TOKEN
    send_email(user.email, 'Confirm Your Account', 'api/email/confirm', user=user, token=token)  # SENDING A EMAIL
    # WITH THE TOKEN
    return jsonify(user.to_json(), 201)


# @api_ops.route('/reset', methods=['GET', 'POST'])
# def password_reset_request():
#     email = request.json.get('email')
#     user = User.query.filter_by(email=email).first()
#     if user:
#         token = user.generate_reset_token()
#         send_email(user.email, 'Reset your password', 'auth/email/reset_password', user=user, token=token)
#         return jsonify({'token': token})
#     return bad_request('Wrong email')


# @api_ops.route('/reset/<token>', methods=['GET', 'POST'])
# def password_reset(token):
#     new_password = request.json.get('new-password')
#     if User.reset_password(token, new_password):
#         db.session.commit()
#         return jsonify(201)
#     return bad_request('Something went wrong')