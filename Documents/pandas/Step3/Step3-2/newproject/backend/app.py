from flask import Flask, render_template, request, redirect,jsonify, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate
from flask_cors import CORS
#from flask_wtf.csrf import CSRFProtect
#from flask_wtf.csrf import generate_csrf
from datetime import datetime
import os
import pytz
import openai
import logging
from wordcloud import WordCloud, STOPWORDS
import matplotlib.pyplot as plt
import re

class Base(DeclarativeBase):
  pass
db = SQLAlchemy(model_class=Base)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "secret_key"
app.config['IMAGE_FOLDER'] = r'C:\Users\masay\Documents\pandas\Step3\Step3-2\newproject\backend\static\images'
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
migrate = Migrate(app, db)
CORS(app)
#csrf = CSRFProtect(app)

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

# APIキーを直接指定
api_key = "YOUR_API_KEY"

# APIキーを直接使用してクライアントを初期化
client = openai.OpenAI(api_key=api_key)

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

@app.route('/')
def index():
    # ユーザーがログインしていれば、投稿一覧ページを表示
    if current_user.is_authenticated:
        posts = Post.query.all()
        return render_template('index.html', posts=posts)
    # ユーザーがログインしていなければ、ログインページにリダイレクト
    else:
        return redirect(url_for('login'))

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

@app.route('/login', methods=['GET','POST'])
def login():
    data = request.get_json()  # JSONデータの取得
    username = data['username']
    password = data['password']
    manager_redirect = data.get('manager_redirect', False)  # デフォルト値をFalseに設定

    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        login_user(user)
        if manager_redirect:
            return jsonify({'redirectURL': '/manager'}), 200
        else:
            return jsonify({'redirectURL': '/'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/mypage')
@login_required
def mypage():
    return render_template('mypage.html')

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

@app.route('/api/posts', methods=['GET'])
def get_posts():
    posts = Post.query.all()
    post_data = [{
        'id': post.id,
        'title': post.title,
        'body': post.body,
        'manager_comment': post.manager_comment,  # 経営層のコメントも含める
        'likes': post.likes,
        'created_at': post.created_at
    } for post in posts]
    return jsonify(post_data)

@app.route('/api/posts/<int:post_id>/delete', methods=['DELETE'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return jsonify({'message': 'Post deleted successfully'})

@app.route('/api/posts/<int:post_id>/update', methods=['POST'])
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    data = request.get_json()
    post.title = data.get('title', post.title)
    post.body = data.get('body', post.body)
    db.session.commit()
    return jsonify({'message': 'Post updated successfully', 'post': {'title': post.title, 'body': post.body}})

@app.route('/api/posts/create', methods=['POST'])
def create_post():
    data = request.get_json()
    app.logger.info(f"Received data: {data}")
    logging.info(f'Received headers: {request.headers}')
    logging.info(f'Received body: {request.get_json()}')
    new_post = Post(
        title=data['title'],
        body=data['body'],
        emotion=data['emotion'],
        created_at=datetime.now(),
        likes=0  # 初期いいね数は0
    )
    db.session.add(new_post)
    db.session.commit()
    return jsonify({'message': 'Post created successfully'}), 201

@app.route('/api/posts/<int:post_id>/like', methods=['POST'])
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.likes += 1  # シンプルにいいね数を増やす
    db.session.commit()
    return jsonify({'message': 'Like added successfully', 'likes': post.likes})

@app.route('/api/manager/comment/update/<int:post_id>', methods=['POST'])
def update_manager_comment_specific(post_id):
    post = Post.query.get_or_404(post_id)
    data = request.get_json()
    if 'manager_comment' in data:
        post.manager_comment = data['manager_comment']
        db.session.commit()
        return jsonify({'message': 'コメントが更新されました'}), 200
    return jsonify({'error': '更新に失敗しました'}), 400

#上手くいかなかったため、"https://textmining.userlocal.jp/results/wordcloud/a309a58d-10cf-47a6-8f4a-aaae7d6e40c3"の生成結果を格納
@app.route('/api/static/images/<filename>', endpoint='get_image_static')
def get_image_static(filename):
    posts = Post.query.all()
    text = " ".join(post.title + " " + post.body for post in posts)
    text = re.sub(r'[^\w\s]', '', text)  # 単語とスペース以外を除去
    custom_stopwords = set(STOPWORDS).union({'から', 'こと', 'ため', 'それ', 'これ', 'たち', 'たくさん', '自分', 'ので'})

    # ワードクラウドの生成
    wc = WordCloud(
        background_color="white", 
        width=800, 
        height=400,
        stopwords=custom_stopwords,
        collocations=False
    ).generate(text)

    # ファイル名の生成と画像の保存
    filename = f"wordcloud_{datetime.now().strftime('%Y%m%d%H%M%S')}.png"
    path = os.path.join(app.config['IMAGE_FOLDER'], filename)
    wc.to_file(path)

    return jsonify({"url": url_for('get_image', filename=filename, _external=True)})

#上手くいかなかったため、"https://textmining.userlocal.jp/results/wordcloud/a309a58d-10cf-47a6-8f4a-aaae7d6e40c3"の生成結果を格納
@app.route('/api/static/images/<filename>')
def get_image(filename):
    return send_from_directory(app.config['IMAGE_FOLDER'], filename)

@app.route('/api/chat', methods=['POST'])
def chat_with_gpt():
    user_input = request.json.get('message')  # ユーザーからの入力を取得

    # コンテキストを短縮して明確にする
    context = """
    従業員の指導とフィードバックに関するアドバイスを提供します。
    ネガティブな意見には寄り添う姿勢を見せながらも、ポジティブな気持ちになるように表現を調整します。
    回答は、概要を先に示し、その後具体的なアドバイスを伝えるようにしてください。
    回答は、出来るだけ短く、端的な表現を心がけてください。アドバイスも1、2点に留めてください。
    """

    try:
        response = client.chat.completions.create(
            messages=[
                {"role": "system", "content": context},
                {"role": "user", "content": user_input},
                {"role": "assistant", "content": "カウンセラーとしてどのように応対するか"}
            ],
            model="gpt-3.5-turbo",
            temperature=0.3,  # 温度パラメータを低く設定
            top_p=0.5,  # 生成の確定性を高める
        )
        full_response = response.choices[0].message.content.strip()

        # レスポンスが不完全な場合にピリオドで終了させる
        if not full_response.endswith('.'):
            full_response += '.'

        return jsonify({'response': full_response})
    except Exception as e:
        app.logger.error(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
