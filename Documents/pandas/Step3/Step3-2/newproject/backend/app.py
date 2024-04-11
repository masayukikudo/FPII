from flask import Flask, render_template, request, redirect,jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate
#from flask_wtf.csrf import CSRFProtect
#from flask_wtf.csrf import generate_csrf
from datetime import datetime
import os
import pytz
import openai

class Base(DeclarativeBase):
  pass
db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "secret_key"
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db)
#csrf = CSRFProtect(app)

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emotion = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(50), nullable=False)
    body = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.timezone('Asia/Tokyo')))
    manager_comment = db.Column(db.String(300), nullable=True)
    likes = db.Column(db.Integer, default=0)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True)
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'GET':
        posts = Post.query.all()
        return render_template('index.html', posts=posts)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User(username=username, password=password)

        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    else:
        return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        manager_redirect = 'manager_redirect' in request.form

        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            if manager_redirect:
                return redirect('/manager')
            else:
                return redirect('/')
    else:
        return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        emotion = request.form.get('emotion')
        title = request.form.get('title')
        body = request.form.get('body')

        post = Post(emotion=emotion,title=title, body=body)

        db.session.add(post)
        db.session.commit()
        return redirect('/')
    else:
        return render_template('create.html')

@app.route('/check', methods=['GET'])
@login_required
def check():
    posts = Post.query.all()
    return render_template('check.html', posts=posts)

@app.route('/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update(id):
    post = Post.query.get(id)
    if request.method == 'GET':
        return render_template('update.html', post=post)
    else:
        post.title = request.form.get('title')
        post.body = request.form.get('body')

        db.session.commit()
        return redirect('/')

@app.route('/<int:id>/delete', methods=['GET'])
@login_required
def delete(id):
    post = Post.query.get(id)

    db.session.delete(post)
    db.session.commit()
    return redirect('/')

@app.route('/manager')
@login_required
def manager():
    posts = Post.query.all()
    return render_template('manager.html', posts=posts)

@app.route('/manager/comment/<int:id>', methods=['POST'])
@login_required
def manager_comment(id):
    post = Post.query.get_or_404(id)
    post.manager_comment = request.form['manager_comment']
    db.session.commit()
    return redirect('/manager')

@app.route('/manager/update/<int:id>', methods=['GET','POST'])
@login_required
def manager_update(id):
    post = Post.query.get_or_404(id)
    post.manager_comment = request.form['manager_comment']
    db.session.commit()
    return redirect('/manager')

@app.route('/manager/comment/update/<int:post_id>', methods=['POST'])
@login_required
def update_manager_comment(post_id):
    post = Post.query.get_or_404(post_id)
    if 'manager_comment' in request.form:
        post.manager_comment = request.form['manager_comment']
        db.session.commit()
        return jsonify({'message': 'コメントが更新されました', 'status': 'success'})
    return jsonify({'message': '更新に失敗しました', 'status': 'error'})

@app.route('/manager/like/<int:id>', methods=['POST'])
@login_required
def manager_like(id):
    post = Post.query.get_or_404(id)
    if post.likes is None:
        post.likes = 0
    post.likes += 1
    db.session.commit()
    return redirect('/manager')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)