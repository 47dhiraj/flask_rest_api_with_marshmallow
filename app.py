from enum import unique
from flask import Flask, json, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash , check_password_hash
from flask_migrate import Migrate
from marshmallow import Schema, fields, validate, validates, validates_schema, ValidationError, post_dump
from flask_marshmallow import Marshmallow
from marshmallow import Schema, fields
from flask_jwt_extended import JWTManager
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from flask_jwt_extended import set_access_cookies               
from flask_jwt_extended import set_refresh_cookies              
from flask_jwt_extended import unset_jwt_cookies
from flask_jwt_extended import unset_access_cookies
from flask_jwt_extended import unset_refresh_cookies            

from flask_swagger_ui import get_swaggerui_blueprint
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from flask_cors import CORS



app = Flask(__name__)                                              

# To Allow, Cors Origin Resource Sharing
# cors = CORS(app, resources={r"/*": {"origins": "http://127.0.0.1:3000"}})
CORS(app)                                                       


app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/cuisine_db'            
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False                                  
app.config['PROPAGATE_EXCEPTIONS'] = True                                               
app.secret_key = 'dc2f94e89666fc38b523ffe87dd199143da9da4c358efaeb1bd20b720a14a7b2'     



# Configuration for Flask JWT Extended

app.config['JWT_SECRET_KEY'] = 'dc2f94e89666fc38b523ffe87dd199143da9da4c358efaeb1bd20b720a14a7b2'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=5)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_COOKIE_CSRF_PROTECT'] = False                                

# Configration for Implicit setting cookies from backend
app.config["JWT_COOKIE_SECURE"] = False                                       
# app.config["JWT_TOKEN_LOCATION"] = ["cookies"]                              

# app.config['JWT_BLACKLIST_ENABLED'] = True                              
# app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']

jwt = JWTManager(app)        


SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Cuisine Rest API"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)


db = SQLAlchemy(app)

ma = Marshmallow(app)

migrate = Migrate(app, db)


class Cuisine(db.Model):
    __tablename__ = 'cuisines'

    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text(), nullable=False)
    complete = db.Column(db.Boolean, nullable=False, default = False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user_id = db.Column(db.Integer(), db.ForeignKey('users.id'))
    user = db.relationship('User', back_populates = 'cuisines')

    def __repr__(self):
        return f"<Cuisine {self.name}>"

    @classmethod
    def get_all(cls):
        return cls.query.all()
    
    @classmethod
    def get_by_id(cls,id):
        return cls.query.get_or_404(id)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True, nullable=False)
    email = db.Column(db.String(120), index=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    cuisines = db.relationship('Cuisine', back_populates='user', cascade='all, delete')

    def __repr__(self):
        return f"<User {self.username}>"
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    
    @classmethod
    def get_all_users(cls):
        return cls.query.all()
    
    @classmethod
    def get_by_id(cls, id):
        return cls.query.get_or_404(id)
    
    @classmethod
    def get_by_username(cls, username):
        return cls.query.filter_by(username = username).first()
    
    @classmethod
    def get_by_email(cls, email):
        return cls.query.filter_by(email = email).first()

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()
    

class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        model = User
        ordered = True
    
    id = ma.auto_field(dump_only=True)
    username = ma.auto_field(required=True, validate=validate.Length(min=3, max=64))
    email = ma.auto_field(required=True, validate=[validate.Length(max=120), validate.Email()])
    password = ma.String(required=True, load_only=True, validate=validate.Length(min=3))
    cuisines = ma.auto_field(dump_only=True)
    
    
    @validates('username')
    def validate_username(self, value):
        if not value.isalpha():
            raise ValidationError('Username should not contain special characters')



class CuisineSchema(ma.SQLAlchemySchema):
    class Meta:
        model = Cuisine
        include_fk = True
        ordered = True
        # fields = ('id', 'name', 'description', 'complete', 'date_created', 'user')

    id = ma.auto_field(dump_only=True)
    name = ma.auto_field(required = True, validate = validate.Length(min=3, max=80))
    description = ma.auto_field(required=True, validate=validate.Length(min=1, max=280))
    complete = ma.auto_field()
    date_created = ma.auto_field(dump_only=True)
    user = ma.Nested(UserSchema(only=("id", "username", "email",)))



@app.errorhandler(400)
def handle_400_error(_error):
    """Return a http 400 error to client"""
    return make_response(jsonify({'error': 'Bad Request'}), 400)

@app.errorhandler(401)
def handle_401_error(_error):
    """ Return a http 401 error to client """
    return make_response(jsonify({'error': 'Unauthorized'}), 401)

@app.errorhandler(403)
def handle_403_error(_error):
    """ Return a http 403 error to client """
    return make_response(jsonify({'error': 'Forbidden'}), 403)

@app.errorhandler(404)
def handle_404_error(_error):
    """ Return a http 404 error to client """
    return make_response(jsonify({'error': 'Not Found'}), 404)

@app.errorhandler(429)
def handle_429_error(_error):
    """ Return a http 429 error to client """
    return make_response(jsonify({'error': 'Too Many Requests'}), 429)

@app.errorhandler(500)
def handle_500_error(_error):
    """ Return a http 500 error to client """
    return make_response(jsonify({'error': 'Internal Server Error'}), 500)

@app.errorhandler(502)
def handle_502_error(_error):
    """ Return a http 502 error to client """
    return make_response(jsonify({'error': 'Bad Gateway'}), 502)

@app.errorhandler(503)
def handle_503_error(_error):
    """ Return a http 503 error to client """
    return make_response(jsonify({'error': 'Service Unavailable'}), 503)




# Get All Cuisines
@app.route("/cuisines", methods = ["GET"])
@jwt_required()
def get_all_cusines():
    user_id = get_jwt_identity()
    current_user = User.get_by_id(user_id)

    # cuisines = Cuisine.query.all()
    # cuisines = Cuisine.get_all()
    cuisines = Cuisine.query.filter_by(user = current_user)

    serializer = CuisineSchema(many=True)

    data = serializer.dump(cuisines)

    return jsonify(data), 200              



# Get single Cuisine
@app.route('/cuisines/<int:id>', methods = ['GET'])
@jwt_required()
def get_recipe(id):
    user_id = get_jwt_identity()
    current_user = User.get_by_id(user_id)

    # cuisine = Cuisine.query.get_or_404(int(id))
    cuisine = Cuisine.get_by_id(id)

    if cuisine:
        if cuisine.user == current_user:
            serializer = CuisineSchema(many = False)

            data = serializer.dump(cuisine)

            return data, 200                               
            # return jsonify(data), 200                   
        
        return jsonify({"detail": "Unauthroized"}), 403

    return jsonify({"detail": "Cuisine does not exist"}), 400




# Add Cuisine
@app.route('/cuisines',methods=['POST'])
@jwt_required()
def create_a_cuisine():
    try:
        user_id = get_jwt_identity()
        current_user = User.get_by_id(user_id)

        data = request.get_json()

        new_cuisine = Cuisine(
            name = data.get('name'),
            description = data.get('description'),
            complete = data.get('complete'),
            user=current_user
        )

        # db.session.add(new_cuisine)
        # db.session.commit()

        new_cuisine.save()                        

        serializer = CuisineSchema(many = False)  

        data = serializer.dump(new_cuisine)

        return data, 201
        # return jsonify(data), 201

    except Exception as e:
        return jsonify({"detail": "Something went wrong. Cuisine can not be created."})



# Update Cuisine
@app.route('/cuisines/<int:id>', methods = ['PUT'])
@jwt_required()
def update_a_cuisine(id):
    user_id = get_jwt_identity()
    current_user = User.get_by_id(user_id)

    # cuisine = Cuisine.query.get_or_404(id)
    cuisine = Cuisine.get_by_id(id)

    if cuisine:
        if cuisine.user == current_user:
            request_data = request.get_json()

            cuisine.name = request_data.get('name')
            cuisine.description = request_data.get('description')
            cuisine.complete = request_data.get('complete')
            cuisine.user = current_user
            
            db.session.commit()                           

            serializer = CuisineSchema(many = False)

            data = serializer.dump(cuisine)

            return data, 200
            # return jsonify(data), 200
            
        return jsonify({"detail": "Unauthroized"}), 403
    
    return jsonify({"detail": "Cuisine does not exist"}), 400




# Delete Cuisine
@app.route('/cuisines/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_a_cuisine(id):
    user_id = get_jwt_identity()
    current_user = User.get_by_id(user_id)

    # cuisine = Cuisine.query.get_or_404(id)
    cuisine = Cuisine.get_by_id(id)

    if cuisine:
        if cuisine.user == current_user:
            # db.session.delete(cuisine)
            # db.session.commit()

            cuisine.delete()
            return jsonify(), 204
        
        return jsonify({"detail": "Unauthroized"}), 403
    
    return jsonify({"detail": "Cuisine does not exist"}), 400



# Register new user
@app.route('/register', methods=['POST'])
def create_a_user():
    data = request.get_json()

    if User.get_by_username(data.get('username')):    
        return {"detail": "User with that username already exists"}, 400
    
    if User.get_by_email(data.get('email')):    
        return {"detail": "User with that email already exists"}, 400

    schema = UserSchema(many = False)

    try:
        schema.load(data)                             

        # creating new user object or instance
        new_user = User(**data)

        new_user.save()                      

        data = schema.dump(new_user)

        return data, 201
        # return jsonify(data), 201

    except ValidationError as err:
        return err.messages





# login user
@app.route('/login', methods=['POST'])
def signin_a_user():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    # user = User.query.filter_by(username = username).first()
    user = User.get_by_email(data.get('email'))

    if (user is not None and password is not None) and user.verify_password(password):
        data = {}

        access_token = create_access_token(identity = user.id, fresh=True)
        refresh_token = create_refresh_token(identity = user.id)

        tokens = {
            'acccess_token':access_token
        }
        data['tokens'] = tokens

        schema = UserSchema(many = False)
        serializer  = schema.dump(user)

        for k, v in serializer.items():
            data[k] = v
        
        response = jsonify(data)
        set_refresh_cookies(response, refresh_token)

        return response, 200

    return {"detail": "Invalid Credentials"}, 401



# Refresh Token
@app.route('/token/refresh', methods=['POST'])
@jwt_required(locations=["cookies"], refresh=True)             
def token_refresh():
    try:
        data = {}

        user_id = get_jwt_identity()

        if user_id:
            user = User.get_by_id(user_id)

            access_token = create_access_token(identity = user_id, fresh = False)              
            # create_access_token(identity = user_id, fresh=datetime.timedelta(minutes=5))         

            refresh_token = create_refresh_token(identity = user_id)

            tokens = {
                'acccess_token':access_token            
            }

            data['tokens'] = tokens

            schema = UserSchema(many = False)
            serializer  = schema.dump(user)

            for k, v in serializer.items():
                data[k] = v
            
            response = jsonify(data)

            # Expiring and unsetting old refresh token
            response.set_cookie('refresh_token_cookie', '', expires=0)
            unset_refresh_cookies(response)

            # setting new refresh token
            set_refresh_cookies(response, refresh_token)

            return response, 200
        
        else:
            return {"detail": "Token expired or Unauthorized"}, 401

    except ValidationError as err:
        return {"detail": "Token expired or Unauthorized"}, 401



# Logout Feature
@app.route('/logout', methods=['POST'])
@jwt_required(locations=["cookies"], refresh=True)
def logout():
    jti = get_jwt()["jti"]
    user_identity = get_jwt_identity()

    if jti and user_identity:
        response = jsonify({"detail": "logout successful"})               
        unset_refresh_cookies(response)                    
        
        return response, 200
    
    else:
        return {"detail": "Token expired or Unauthorized"}, 401






if __name__ == '__main__':
    app.run(port=5000, debug = True)                               





