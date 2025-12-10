from flask import Flask, render_template, redirect, url_for, request, session, flash, jsonify, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import pytz
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_secreta_segura_escolar'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///redsocial.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mp3', 'wav', 'ogg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)

# MODELOS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)
    badges = db.relationship('Badge', backref='user', lazy=True)
    reactions = db.relationship('Reaction', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    media_url = db.Column(db.String(255))
    media_type = db.Column(db.String(20))
    reactions = db.relationship('Reaction', backref='post', lazy=True)
    comments = db.relationship('Comment', backref='post', lazy=True)

class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    emoji = db.Column(db.String(10), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# MODELOS AMIGOS, SOLICITUDES Y MENSAJES

class FriendRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    from_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, declined

    from_user = db.relationship('User', foreign_keys=[from_user_id])
    to_user = db.relationship('User', foreign_keys=[to_user_id])

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)
    file_path = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

# RUTAS

@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        posts = Post.query.order_by(Post.timestamp.desc()).all()
        return render_template('index.html', user=user, posts=posts)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        password2 = request.form['password2']
        if not username or not email or not password or not password2:
            flash('Por favor completa todos los campos', 'warning')
            return redirect(url_for('register'))
        if password != password2:
            flash('Las contraseñas no coinciden', 'danger')
            return redirect(url_for('register'))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Usuario o email ya registrado', 'danger')
            return redirect(url_for('register'))
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registro exitoso. Por favor inicia sesión.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            flash(f'Bienvenido, {user.username}!', 'success')
            return redirect(url_for('index'))
        flash('Credenciales inválidas', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

@app.route('/post/new', methods=['GET', 'POST'])
def new_post():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para publicar', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        file = request.files.get('media')
        media_url = None
        media_type = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            media_url = f'/static/uploads/{filename}'
            ext = filename.rsplit('.', 1)[1].lower()
            if ext in ['png', 'jpg', 'jpeg', 'gif']:
                media_type = 'image'
            elif ext == 'mp4':
                media_type = 'video'
            elif ext in ['mp3', 'wav', 'ogg']:
                media_type = 'audio'
        if not content and not media_url:
            flash('Debes ingresar texto o subir un archivo válido', 'warning')
            return redirect(url_for('new_post'))

        tz = pytz.timezone('America/Mexico_City')
        fecha_hora_toluca = datetime.now(tz)

        post = Post(content=content if content else '', user_id=session['user_id'],
                    media_url=media_url, media_type=media_type,
                    timestamp=fecha_hora_toluca)
        db.session.add(post)
        db.session.commit()

        user = User.query.get(session['user_id'])
        count_posts = len(user.posts)

        if count_posts == 3:
            badge = Badge(name='Iniciador Escolar', user_id=user.id)
            db.session.add(badge)
            db.session.commit()
            flash('¡Has ganado la insignia "Iniciador Escolar"! Sigue participando.', 'info')
        elif count_posts == 5:
            badge = Badge(name='Publicador Activo', user_id=user.id)
            db.session.add(badge)
            db.session.commit()
            flash('¡Felicidades! Has ganado la insignia "Publicador Activo".', 'info')
        elif count_posts == 10:
            badge = Badge(name='Líder Escolar', user_id=user.id)
            db.session.add(badge)
            db.session.commit()
            flash('¡Eres un Líder Escolar! Has ganado una insignia especial.', 'info')

        flash('Publicación creada con éxito', 'success')
        return redirect(url_for('index'))
    return render_template('new_post.html')

@app.route('/reaction', methods=['POST'])
def reaction():
    if 'user_id' not in session:
        return jsonify({'error': 'No autenticado'}), 401
    data = request.json
    post_id = data.get('post_id')
    emoji = data.get('emoji')
    if not post_id or not emoji:
        return jsonify({'error': 'Datos incompletos'}), 400
    existing = Reaction.query.filter_by(user_id=session['user_id'], post_id=post_id, emoji=emoji).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        action = 'removed'
    else:
        new_reaction = Reaction(user_id=session['user_id'], post_id=post_id, emoji=emoji)
        db.session.add(new_reaction)
        db.session.commit()
        action = 'added'
    counts = db.session.query(Reaction.emoji, db.func.count(Reaction.id)).filter(Reaction.post_id == post_id).group_by(Reaction.emoji).all()
    counts_dict = {e:c for e,c in counts}
    return jsonify({'action': action, 'counts': counts_dict})

@app.route('/comment/new', methods=['POST'])
def new_comment():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    post_id = request.form.get('post_id')
    content = request.form.get('content', '').strip()
    if not content or not post_id:
        flash('Comentario vacío o publicación no válida', 'warning')
        return redirect(url_for('index'))
    comment = Comment(content=content, user_id=session['user_id'], post_id=post_id)
    db.session.add(comment)
    db.session.commit()
    flash('Comentario agregado', 'success')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para ver tu perfil', 'warning')
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    badges = Badge.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', user=user, badges=badges)

@app.route('/games')
def games():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a los juegos', 'warning')
        return redirect(url_for('login'))
    return render_template('games.html')

@app.route('/games/tic_tac_toe')
def tic_tac_toe():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para jugar', 'warning')
        return redirect(url_for('login'))
    return render_template('tic_tac_toe.html')

@app.route('/games/rock_paper_scissors')
def rock_paper_scissors():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para jugar', 'warning')
        return redirect(url_for('login'))
    return render_template('rock_paper_scissors.html')

@app.route('/games/memory')
def memory():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a los juegos', 'warning')
        return redirect(url_for('login'))
    return render_template('memory.html')

@app.route('/games/guess_number')
def guess_number():
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder a los juegos', 'warning')
        return redirect(url_for('login'))
    return render_template('guess_number.html')

@app.route('/post/edit/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para editar publicaciones', 'warning')
        return redirect(url_for('login'))
    post = Post.query.get_or_404(post_id)
    if post.user_id != session['user_id']:
        flash('No tienes permiso para editar esta publicación', 'danger')
        return redirect(url_for('index'))
    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        file = request.files.get('media')
        media_url = post.media_url
        media_type = post.media_type

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            media_url = f'/static/uploads/{filename}'
            ext = filename.rsplit('.', 1)[1].lower()
            if ext in ['png', 'jpg', 'jpeg', 'gif']:
                media_type = 'image'
            elif ext == 'mp4':
                media_type = 'video'
            elif ext in ['mp3', 'wav', 'ogg']:
                media_type = 'audio'

        if not content and not media_url:
            flash('Debes ingresar texto o subir un archivo válido', 'warning')
            return redirect(url_for('edit_post', post_id=post.id))

        post.content = content if content else ''
        post.media_url = media_url
        post.media_type = media_type
        db.session.commit()
        flash('Publicación actualizada con éxito', 'success')
        return redirect(url_for('index'))

    return render_template('edit_post.html', post=post)

@app.route('/post/delete/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' not in session:
        flash('Debes iniciar sesión para eliminar publicaciones', 'warning')
        return redirect(url_for('login'))
    post = Post.query.get_or_404(post_id)
    if post.user_id != session['user_id']:
        flash('No tienes permiso para eliminar esta publicación', 'danger')
        return redirect(url_for('index'))

    Comment.query.filter_by(post_id=post.id).delete()
    Reaction.query.filter_by(post_id=post.id).delete()
    db.session.delete(post)
    db.session.commit()

    flash('Publicación y todo su contenido relacionado eliminados', 'success')
    return redirect(url_for('index'))

# RUTAS AMIGOS Y MENSAJES

@app.route('/friends')
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    current_user = User.query.get(session['user_id'])
    users = User.query.filter(User.id != current_user.id).all()
    friend_requests = FriendRequest.query.filter_by(to_user_id=current_user.id, status='pending').all()
    friendships = Friendship.query.filter(
        (Friendship.user1_id == current_user.id) | (Friendship.user2_id == current_user.id)
    ).all()
    friends = []
    for f in friendships:
        friend_id = f.user2_id if f.user1_id == current_user.id else f.user1_id
        friend_user = User.query.get(friend_id)
        if friend_user:
            friends.append(friend_user)
    return render_template('friends.html', users=users, friend_requests=friend_requests, friends=friends)

@app.route('/friend-request/send', methods=['POST'])
def send_friend_request():
    if 'user_id' not in session:
        return jsonify(success=False, error="No autenticado"), 401
    data = request.get_json()
    to_user_id = data.get('to_user_id')
    if not to_user_id or to_user_id == session['user_id']:
        return jsonify(success=False, error="Solicitud inválida")
    existing = FriendRequest.query.filter_by(
        from_user_id=session['user_id'], to_user_id=to_user_id, status='pending').first()
    if existing:
        return jsonify(success=False, error="Solicitud ya enviada")
    fr = FriendRequest(from_user_id=session['user_id'], to_user_id=to_user_id)
    db.session.add(fr)
    db.session.commit()
    return jsonify(success=True)

@app.route('/friend-request/accept', methods=['POST'])
def accept_friend_request():
    if 'user_id' not in session:
        return jsonify(success=False, error="No autenticado"), 401
    data = request.get_json()
    request_id = data.get('request_id')
    fr = FriendRequest.query.filter_by(id=request_id, to_user_id=session['user_id'], status='pending').first()
    if not fr:
        return jsonify(success=False, error="Solicitud no encontrada")
    fr.status = 'accepted'
    friendship = Friendship(user1_id=fr.from_user_id, user2_id=fr.to_user_id)
    db.session.add(friendship)
    db.session.commit()
    return jsonify(success=True)

@app.route('/friend-request/decline', methods=['POST'])
def decline_friend_request():
    if 'user_id' not in session:
        return jsonify(success=False, error="No autenticado"), 401
    data = request.get_json()
    request_id = data.get('request_id')
    fr = FriendRequest.query.filter_by(id=request_id, to_user_id=session['user_id'], status='pending').first()
    if not fr:
        return jsonify(success=False, error="Solicitud no encontrada")
    fr.status = 'declined'
    db.session.commit()
    return jsonify(success=True)

@app.route('/friend/remove', methods=['POST'])
def remove_friend():
    if 'user_id' not in session:
        return jsonify(success=False, error="No autenticado"), 401
    data = request.get_json()
    friend_id = data.get('friend_id')
    current_user_id = session['user_id']
    if not friend_id:
        return jsonify(success=False, error="ID de amigo no proporcionado"), 400

    friendship = Friendship.query.filter(
        ((Friendship.user1_id == current_user_id) & (Friendship.user2_id == friend_id)) |
        ((Friendship.user1_id == friend_id) & (Friendship.user2_id == current_user_id))
    ).first()

    if not friendship:
        return jsonify(success=False, error="Amistad no encontrada"), 404

    db.session.delete(friendship)
    db.session.commit()
    return jsonify(success=True)

@app.route('/messages/<int:friend_id>', methods=['GET', 'POST'])
def messages(friend_id):
    if 'user_id' not in session:
        return jsonify(success=False, error="No autenticado"), 401
    current_user_id = session['user_id']
    friend = User.query.get(friend_id)
    if not friend:
        abort(404)
    friendship = Friendship.query.filter(
        ((Friendship.user1_id == current_user_id) & (Friendship.user2_id == friend_id)) |
        ((Friendship.user1_id == friend_id) & (Friendship.user2_id == current_user_id))
    ).first()
    if not friendship:
        return jsonify(success=False, error="No son amigos"), 403

    if request.method == 'GET':
        msgs = Message.query.filter(
            ((Message.sender_id == current_user_id) & (Message.receiver_id == friend_id)) |
            ((Message.sender_id == friend_id) & (Message.receiver_id == current_user_id))
        ).order_by(Message.timestamp.asc()).all()
        messages_list = []
        for m in msgs:
            messages_list.append({
                'sender': 'me' if m.sender_id == current_user_id else 'friend',
                'content': m.content,
                'file_url': url_for('uploaded_file', filename=m.file_path) if m.file_path else None,
                'timestamp': m.timestamp.isoformat()
            })
        return jsonify(messages=messages_list)

    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        file = request.files.get('file')
        filename = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        msg = Message(sender_id=current_user_id, receiver_id=friend_id,
                      content=content if content else None, file_path=filename)
        db.session.add(msg)
        db.session.commit()
        return jsonify(success=True)
    
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


    

if __name__ == '__main__':
    if not os.path.exists('redsocial.db'):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
