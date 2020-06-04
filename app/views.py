from flask import render_template, flash, url_for, session, redirect, request, make_response, jsonify
from app import app, db
from .models import User, Event
from .forms import RegistrationForm, LoginForm
from werkzeug.security import generate_password_hash, check_password_hash
import jwt, datetime
from functools import wraps


@app.route ('/', methods=['GET'])
def  index():
    return render_template('index.html', title="Lanai's Main Page")


@app.route('/register', methods=['POST', 'GET'])
def register():

    form = RegistrationForm()

    if form.validate_on_submit():
        firstname =  form.firstname.data
        lastname =  form.lastname.data
        lastname =  form.lastname.data
        email =  form.email.data
        password =  form.password.data

        user = User(firstname = firstname, lastname =  lastname, email=email, password=generate_password_hash(password, method='sha256'))

        db.session.add(user)
        db.session.commit()

        flash('Successfully Registered', category='success')
        return redirect(url_for('index'))

    return render_template('register.html', title = "Register", form = form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Credentials incorrect', category='danger')
            return redirect (url_for('login'))

        if check_password_hash(user.password, password):
            session['user'] = user.firstname
            flash('Successfully Logged in', category='success')
            return redirect(url_for('events'))

    return render_template('login.html', title = 'Login', form = form)


@app.route('/events', methods=['GET'])
def events():
    events = Event.query.all()
    return render_template('events.html', title="Events", user=session['user'], events=events)


@app.route('/logout', methods=['GET'])
def logout():
    if user in session:
        session.pop('user', None)
    flash("You have logged out successfully", category='success')
    return (url_for('login'))


# =====================================     REST API     ========================================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'Message' : 'Missing Token'}), 401    
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(email = data['email']).first()
        except Exception as e:
            print(e)
            return jsonify({'Message': 'Invalid Token'}), 401
        return f(current_user, *args, **kwargs)
    return decorated



@app.route('/user', methods=['POST'])
def create_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')

    user = User(firstname = data['firstname'], lastname =  data['lastname'], email=data['email'], password=hashed_password, admin=False)

    db.session.add(user)
    db.session.commit()

    return jsonify({'Message' : 'The user was created.'})


@app.route('/user', methods=['GET'])
@token_required
def get_users(current_user):

    if not current_user.admin:
        return jsonify({'Message': 'Function Not Permitted'})
        
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data["id"] = user.id 
        user_data["firstname"] = user.firstname 
        user_data["lastname"] = user.lastname 
        user_data["email"] = user.email
        user_data["admin"] = user.admin
        output.append(user_data)
    return jsonify({'users':output})


@app.route('/user/<user_id>', methods=['GET'])
def get_one_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({'message': 'User does not exist.'})

    user_data = {}
    user_data["id"] = user.id 
    user_data["firstname"] = user.firstname 
    user_data["lastname"] = user.lastname 
    user_data["email"] = user.email
    user_data["admin"] = user.admin

    return jsonify({'user' : user_data})


@app.route('/user/<user_id>', methods=['PUT'])
def promote_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({'message': 'User does not exist.'})

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user with email %s is now admin.' %  user.email})

@app.route('/user/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    user = User.query.filter_by(id=user_id).first()
    if not user:
        return jsonify({'message': 'User does not exist.'})

    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'The user with email %s is now deleted.' %  user.email})


@app.route('/authlogin')
def authlogin():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('User verification failed', 401, {'WWW-Authenticate' : 'Basic realm = "Login Required"'})

    user = User.query.filter_by(email=auth.username).first()
    if not user:
        return make_response('User verification failed', 401, {'WWW-Authenticate' : 'Basic realm = "Login Required"'})
    
    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'email':user.email, 'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})
    return make_response('User verification failed', 401, {'WWW-Authenticate' : 'Basic realm = "Login Required"'})
