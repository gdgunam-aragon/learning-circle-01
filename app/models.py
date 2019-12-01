from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature
from flask import current_app, request, url_for

from . import db

class Permission:
   EDIT_ACCOUNT = 2
   ADMIN = 4


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    @staticmethod
    def insert_roles():
        roles = {
            'User': Permission.EDIT_ACCOUNT,
            'Administrator': [Permission.ADMIN, Permission.EDIT_ACCOUNT]
        }

        default_role = 'User'

        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = (role.name == default_role)
            db.session.add(role)
        db.session.commit()

        def add_permission(self, perm):
            if not self.has_permissions(perm):
                self.permissions += perm
        
        def remove_permission(self, perm):
            if self.has_permissions(perm):
                self.permissions -= perm
        
        def reset_permissions(self):
            self.permissions = 0

        def has_permissions(self, perm):
            return self.permissions & perm == perm
        
        def __repr__(self):
            return '<Role %r>' % self.name



class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key = True)
    email =  db.Column(db.String(64), unique = True, index = True)
    username =  db.Column(db.String(64), unique = True, index = True)
    role_id = db.Column(db.Interger, db.ForeignKey("role.id"))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default = False)
    name = db.Column(db.String(64))
    member_since = db.Column(db.DateTime(), default = datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default = datetime.utcnow)
    
       def __init__(self, **kwargs):  # ROLE ASSIGNMENT USING THE CURRENT_APP USER EMAIL
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['APP_ADMIN']:
                self.role = Role.query.filter_by(name='Administrator').first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    @property
    def password(self):  # THIS METHOD ASSERT THAT THE PASSWORD IS READABLE
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):  # THIS METHOD IS USING TO GENERATE THE HASH OF THE PASSWORD
        self.password_hash = generate_password_hash(password)

    def ping(self):  # THIS IS USED IN ORDER TO UPDATE THE LAST SINCE PROPERTY EACH TIME USER COMES. THIS METHOD IS
        # USED FOR 'BEFORE_APP_REQUEST' TO WORK
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def verify_password(self, password):  # THIS METHOD IS TO VALIDATE THAT THE PASSWORD HASH
        # IS A REFERENCE OF THE PASSWORD
        return check_password_hash(self.password_hash, password)

    def generation_confirmed_token(self, expiration=3600):  # THIS FUNCTION GENERATES A TOKEN
        # THE EXPIRATION ARGUMENT CAN BE SET
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id}).decode('utf-8')

    def confirm(self, token):  # THIS FUNCTION ASSERT THAT IN FACT THE TOKEN WILL BE RECIP DOESN'T BE EXPIRATED AND ALSO
        # THAT WAS THE SAME WE SENT IN THE MAIL
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))  # HERE WE ASSERT IT DOESN'T EXPIRED
        except:  # ANY KIND OF EXCEPTION WILL BE RETURN FALSE
            return False
        if data.get('confirm') != self.id:  # HERE WE ASSERT IT IS THE SAME TOKEN
            return False
        self.confirmed = True
        db.session.add(self)  # IF ALL IS OK WE ADD THE SESSION TO THE DB
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id}).decode('utf-8')

    @staticmethod
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        user = User.query.get(data.get('reset'))
        if user is None:
            return False
        user.password = new_password
        db.session.add(user)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email}).decode('utf-8')

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf-8'))
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        db.session.add(self)
        return True

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    def to_json(self):
        json_user = {
            'url': url_for('api.get_user', id=self.id),
            'name': self.name,
            'email': self.email,
            'username': self.username
        }
        return json_user

    def from_json(json_user):
        credentials = []

        username = json_user.get('username'),
        name = json_user.get('name'),
        email = json_user.get('email'),
        password = json_user.get('password')

        credentials.append(username)
        credentials.append(name)
        credentials.append(email)
        credentials.append(password)

        for value in credentials:
            if value is None or value == '':
                raise ValidationError('One or more values were wrong')

        return User(username=username, name=name, email=email, password=password)

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id}).decode('utf-8')

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        return User.query.get(data['id'])

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    def __repr__(self):
        return '<User %r>' % self.username
