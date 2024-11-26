from flask import Flask, render_template, request, jsonify, flash, redirect, url_for
import facebook as fb
import requests
from flask import Flask, render_template, request, jsonify
import facebook as fb
import requests
from datetime import timedelta, timezone
from flask import abort
import os
from werkzeug.security import generate_password_hash, check_password_hash
# Banco de dados (no arquivo principal)
from datetime import datetime
import uuid
from datetime import date, timedelta
from flask_mail import Message
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_login import login_required, current_user, UserMixin, login_user
import pytz
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from sqlalchemy.sql.functions import current_user
# Página Inicialj
import requests
from flask_login import current_user
from apscheduler.schedulers.background import BackgroundScheduler

# Configuração do scheduler
scheduler = BackgroundScheduler()
scheduler.start()

from datetime import datetime
from functools import wraps



app = Flask(__name__)

from flask_login import LoginManager

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Define a rota de login


# Configuração do carregamento do usuário
@login_manager.user_loader
def load_user(id):
    return db.session.get(User, int(id))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario_id' not in session:
            flash('Por favor, faça login para continuar.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function

# Configurações
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# Configurações do Flask e SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///facebook_posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['MAIL_SERVER']= 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'storeexecutivo@gmail.com'
app.config['MAIL_PASSWORD'] = 'sokqmiqjebfqeogh'

# Verifique se a pasta de upload existe, se não, crie
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
mail = Mail(app)

app.secret_key = '701517828f08f86f2fcba2e79ed9583f'

# Token de Acesso da API do Facebook
AD_ACCOUNT_ID = 'act_1772358199633718'
INSTAGRAM_ACCOUNT_ID = '17841465681073010'
#PAGE_ID = '101777818499902'
PAGE_ID = '111771022018850'
ACCESS_TOKEN = "EAA6jGHZB8lvkBOZC4XhpotHzfuuWT9OJ4gka0C3Fi5n925ORE32VLZAyCNMP5ifymwy0LzQQZBc6cNyYRbaJdvNTi2TZAgHSn6zw43ecAAYQlzlmmhtvKAGbUvAjK7KspwNnSrbzqSR0FAPTQTtI0myl0SCE4TF7W854lCgWYtqnZBc4ZANC5rvikPz4KHFsgkZD"
#ACCESS_TOKEN = "EAA6jGHZB8lvkBO884CZCJgKehFbpVL6x0SbHgBrUZBGzoLZBkZA2Jc11I3VZBknyZBFMkPExvD4YToJnDZBOl6VKqTYNzEYvr8gnZCK98c3GZCtELK1R2zOeVJz6TdNqb7dYUDwMZCRwctsxgbd0RvmrMuSgXkG1s47EqrWkRjZAHIMWwIL5yghd9WuL4QiKnobwG0BqhJcZD"
graph = fb.GraphAPI(ACCESS_TOKEN)


# Modelo de Dados
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    likes = db.Column(db.Integer, default=0)  # Adicione este campo
    comments = db.Column(db.Integer, default=0)  # Adicione este campo
    shares = db.Column(db.Integer, default=0)  # Adicione este campo

    def __repr__(self):
        return f'<Post {self.name}>'

class ScheduledPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.String(100), unique=True, nullable=True)
    name = db.Column(db.String(150), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    scheduled_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default="PENDING")  # Status: PENDING, POSTED, FAILED

    def __repr__(self):
        return f'<ScheduledPost {self.name}>'

# Modelo para usuários
class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    ativo = db.Column(db.Boolean, default=True, nullable=False)
    role = db.Column(db.String(50), default='Admin', nullable=False)  # Exemplos: 'admin', 'usuario', 'moderador'
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expira_em = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f'<User {self.nome} ({self.email})>'

    def set_password(self, senha):
        """Hash da senha."""
        self.senha = generate_password_hash(senha)

    def check_password(self, senha):
        """Verifica se a senha corresponde ao hash armazenado."""
        return check_password_hash(self.senha, senha)

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('logs', lazy=True))
    action = db.Column(db.String(150), nullable=False)  # Ex: 'login', 'logout', 'failed_login'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    details = db.Column(db.Text, nullable=True)  # Informações adicionais, se necessário

    def __repr__(self):
        return f'<UserLog {self.action} by {self.user.nome} at {self.timestamp}>'


def registrar_log(user_id, action, details=None):
    """Registra uma ação de um usuário no banco de dados."""
    with app.app_context():
        log = UserLog(user_id=user_id, action=action, details=details)
        db.session.add(log)
        db.session.commit()

# Criar a base de dados
with app.app_context():
    db.create_all()

# Criação do primeiro usuário (Jenny)
def criar_usuario_inicial():
    with app.app_context():
        if User.query.filter_by(nome="Jenny").first() is None:
            novo_usuario = User(nome="Jenny")
            novo_usuario.set_password("2345")
            db.session.add(novo_usuario)
            db.session.commit()
            print("Usuário inicial Jenny criado com sucesso.")

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Admin':
            # Retorna erro 403 (Acesso Proibido) se o usuário não for admin
            abort(403)
        return f(*args, **kwargs)
    return decorated_function
# Rota para página não encontrada (404)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('Erros/404.html'), 404

# Rota para requisição inválida (400)
@app.errorhandler(400)
def bad_request(e):
    return render_template('Erros/400.html'), 400

# Rota para acesso proibido (403)
@app.errorhandler(403)
def forbidden(e):
    return render_template('Erros/403.html'), 403

# Rota para método não permitido (405)
@app.errorhandler(405)
def method_not_allowed(e):
    return render_template('Erros/405.html'), 405

# Rota para erro interno do servidor (500)
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('Erros/500.html'), 500


@app.route('/logout')
def logout():
    registrar_log(current_user.id, 'logout', details='Usuário saiu do sistema.')
    session.clear()
    return redirect(url_for('login'))


@app.route('/webhook', methods=['GET', 'POST'])
def webhook():
    if request.method == 'GET':
        # Verificação do Facebook para garantir que o webhook é válido
        verify_token = '701517828f08f86f2fcba2e79ed9583f'
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')

        if mode == 'subscribe' and token == verify_token:
            print("Webhook verificado com sucesso!")
            return challenge, 200
        else:
            return 'Token inválido!', 403

    elif request.method == 'POST':
        # Processar notificações recebidas
        data = request.json
        print("Notificação recebida:", data)

        # Aqui você pode exibir ou salvar a notificação em um banco de dados
        return 'EVENT_RECEIVED', 200
    else:
        return 'Método não permitido!', 405

def post_scheduled_posts():
    with app.app_context():  # Configura o contexto do app
        # Busca todos os posts que estão agendados para agora ou antes e não foram postados
        now = datetime.now() + timedelta(hours=2)

        # Busca todos os posts que estão agendados para agora ou antes e não foram postados
        pending_posts = ScheduledPost.query.filter(
            ScheduledPost.scheduled_time <= now,
            ScheduledPost.status == "PENDING"
        ).all()

        for post in pending_posts:
            try:
                # Publicar no Facebook
                response = graph.put_object("me", "feed", message=post.message)
                post.post_id = response['id']
                post.status = "POSTED"

                # Armazenar os detalhes do post na tabela Post
                new_post = Post(
                    post_id=response['id'],
                    name=post.name,  # Aqui, você pode ajustar o que será salvo como 'name'
                    likes=0,  # Inicialmente sem likes
                    comments=0,  # Inicialmente sem comentários
                    shares=0  # Inicialmente sem compartilhamentos
                )
                db.session.add(new_post)
            except Exception as e:
                post.status = "FAILED"
                print(f"Erro ao postar: {e}")
            db.session.commit()
# Executa a função a cada minuto
scheduler.add_job(post_scheduled_posts, 'interval', minutes=1)
@app.route('/logs', methods=['GET'])
@login_required
@admin_required
def listar_logs():
    logs = UserLog.query.order_by(UserLog.timestamp.desc()).all()
    return render_template('logs.html', logs=logs, timedelta=timedelta)


# Rota para listar todos os usuários
@app.route('/usuarios', methods=['GET'])
@login_required
@admin_required
def listar_usuarios():
    # Registrar o acesso à listagem de usuários
    registrar_log(current_user.id, 'access', details='Listagem de usuários acessada.')

    # Buscar usuários do banco de dados
    usuarios = User.query.all()
    return render_template('listar.html', usuarios=usuarios)

# Rota para criar um novo usuário
@app.route('/usuarios/novo', methods=['GET', 'POST'])
def criar_usuario():
    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        role = request.form.get('role')  # Valor padrão caso não seja selecionado

        # Verificar se os campos obrigatórios foram preenchidos
        if not nome or not email:
            flash("Nome e Email são obrigatórios.", "danger")
            return redirect(url_for('criar_usuario'))

        # Verificar se o email já está cadastrado
        if User.query.filter_by(email=email).first():
            flash("Email já cadastrado.", "danger")
            return redirect(url_for('criar_usuario'))

        try:
            # Criar novo usuário
            novo_usuario = User(nome=nome, email=email, role=role)
            novo_usuario.set_password(email)  # Senha inicial como o email (ou use outra lógica)
            db.session.add(novo_usuario)
            db.session.commit()

            # Registrar log
            registrar_log(current_user.id, 'create_user', details=f"Usuário {nome} ({email}) criado.")

            flash("Usuário criado com sucesso!", "success")
            return redirect(url_for('listar_usuarios'))
        except Exception as e:
            # Registrar log de erro
            registrar_log(current_user.id, 'create_user_error', details=f"Erro ao criar usuário {nome}: {str(e)}")
            flash("Erro ao criar usuário. Tente novamente.", "danger")
            return redirect(url_for('criar_usuario'))

    # Renderizar o formulário de criação de usuários
    return render_template('listar.html')


# Rota para editar um usuário
@app.route('/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def editar_usuario(id):
    usuario = User.query.get_or_404(id)

    if request.method == 'POST':
        nome = request.form.get('nome')
        email = request.form.get('email')
        role = request.form.get('role', usuario.role)
        nova_senha = request.form.get('senha')

        # Validações básicas
        if not nome or not email:
            flash("Nome e Email são obrigatórios.", "danger")
            return redirect(url_for('editar_usuario', id=id))

        # Verificar se o email já está sendo usado por outro usuário
        email_existente = User.query.filter_by(email=email).first()
        if email_existente and email_existente.id != id:
            flash("Este email já está em uso por outro usuário.", "danger")
            return redirect(url_for('editar_usuario', id=id))

        try:
            # Atualizar informações do usuário
            usuario.nome = nome
            usuario.email = email
            usuario.role = role

            if nova_senha:  # Atualizar a senha apenas se um valor novo for fornecido
                usuario.set_password(nova_senha)

            db.session.commit()

            # Registrar log
            registrar_log(
                current_user.id,
                'update_user',
                details=f"Usuário {usuario.nome} ({usuario.email}) foi atualizado."
            )

            flash("Usuário atualizado com sucesso!", "success")
            return redirect(url_for('listar_usuarios'))
        except Exception as e:
            # Registrar log de erro
            registrar_log(
                current_user.id,
                'update_user_error',
                details=f"Erro ao atualizar usuário {usuario.nome} ({usuario.email}): {str(e)}"
            )
            flash("Erro ao atualizar usuário. Tente novamente.", "danger")
            return redirect(url_for('editar_usuario', id=id))

    return render_template('editar.html', usuario=usuario)

@app.route('/usuarios/status/<int:id>', methods=['POST'])
@login_required
@admin_required
def alterar_status_usuario(id):
    usuario = User.query.get_or_404(id)
    try:
        # Alterar o status do usuário
        usuario.ativo = not usuario.ativo
        db.session.commit()

        # Registrar log
        registrar_log(
            current_user.id,
            'toggle_user_status',
            details=f"Usuário {usuario.nome} ({usuario.email}) {'ativado' if usuario.ativo else 'desativado'}."
        )

        flash(f"Usuário {'ativado' if usuario.ativo else 'desativado'} com sucesso!", "success")
    except Exception as e:
        # Registrar log de erro
        registrar_log(
            current_user.id,
            'toggle_user_status_error',
            details=f"Erro ao alterar status de {usuario.nome} ({usuario.email}): {str(e)}"
        )
        flash("Erro ao alterar status do usuário. Tente novamente.", "danger")

    return redirect(url_for('listar_usuarios'))

# Rota para deletar um usuário
@app.route('/excluir_usuario/<int:id>', methods=['POST', 'GET'])
@login_required
@admin_required
def excluir_usuario(id):
    usuario = User.query.get_or_404(id)

    # Prevenir exclusão própria
    if usuario.id == current_user.id:
        flash("Você não pode excluir sua própria conta!", "danger")
        return redirect(url_for('listar_usuarios'))

    try:
        db.session.delete(usuario)
        db.session.commit()



        flash(f"Usuário '{usuario.nome}' foi excluído com sucesso!", 'success')
    except Exception as e:

        flash("Erro ao excluir o usuário. Tente novamente.", "danger")

    return redirect(url_for('listar_usuarios'))


# Rota para redefinir senha (usuário redefine a própria senha)
@app.route('/usuarios/redefinir-senha', methods=['GET', 'POST'])
@login_required
def redefinir_senha():
    if request.method == 'POST':
        senha_atual = request.form.get('senha_atual')
        nova_senha = request.form.get('nova_senha')
        confirmar_nova_senha = request.form.get('confirmar_nova_senha')

        # Verificar se a nova senha e a confirmação coincidem
        if nova_senha != confirmar_nova_senha:
            flash("As novas senhas não coincidem.", "danger")
            return redirect(url_for('redefinir_senha'))

        # Verificar se a senha atual está correta
        if not current_user.check_password(senha_atual):
            flash("Senha atual incorreta.", "danger")
            return redirect(url_for('redefinir_senha'))

        # Verificar se a nova senha atende aos requisitos
        if len(nova_senha) < 8 or nova_senha == senha_atual:
            flash("A nova senha deve ter pelo menos 8 caracteres e ser diferente da senha atual.", "danger")
            return redirect(url_for('redefinir_senha'))

        try:
            # Alterar a senha
            current_user.set_password(nova_senha)
            db.session.commit()

            # Registrar log
            registrar_log(current_user.nome, 'change_password', details="Senha alterada com sucesso.")

            flash("Senha alterada com sucesso!", "success")
            return redirect(url_for('dashboard'))  # Redirecionar para a página inicial ou outro local apropriado
        except Exception as e:
            # Registrar log de erro
            registrar_log(current_user.id, 'change_password_error', details=f"Erro ao alterar senha: {str(e)}")
            flash("Erro ao alterar a senha. Tente novamente.", "danger")
            return redirect(url_for('dashboard'))

    return render_template('redefinir_senha.html')

@app.route('/cledner')
@login_required
def cledner():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nome = request.form['nome']
        senha = request.form['senha']
        usuario = User.query.filter_by(nome=nome).first()

        if usuario and usuario.check_password(senha):
            if usuario.ativo:  # Verifica se o usuário está ativo
                login_user(usuario)  # Usando o login_user do Flask-Login
                session['usuario_id'] = usuario.id
                session['nome_usuario'] = usuario.nome
                flash('Login realizado com sucesso!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Sua conta está inativa. Por favor, entre em contato com o administrador para mais informações.', 'warning')
        else:
            flash('Nome de usuário ou senha incorretos.', 'danger')

    return render_template('login.html')

@app.route('/schedule_post', methods=['GET', 'POST'])
@login_required
def schedule_post():
    if request.method == 'POST':
        message = request.form.get('message')
        post_name = request.form.get('post_name')
        scheduled_time_str = request.form.get('scheduled_time')

        # Verificar se todos os campos foram preenchidos
        if not message or not post_name or not scheduled_time_str:
            flash("Todos os campos são obrigatórios.", "danger")
            return redirect(url_for('schedule_post'))

        try:
            # Convertendo a data e hora fornecida para um objeto datetime
            scheduled_time = datetime.strptime(scheduled_time_str, "%Y-%m-%dT%H:%M")

            # Verificar se o horário agendado é no futuro
            if scheduled_time <= datetime.now():
                flash("O horário agendado deve ser no futuro.", "danger")
                return redirect(url_for('schedule_post'))

            # Criar um novo post agendado
            new_scheduled_post = ScheduledPost(
                name=post_name,
                message=message,
                scheduled_time=scheduled_time
            )

            db.session.add(new_scheduled_post)
            db.session.commit()

            # Registrar log
            registrar_log(
                current_user.id,
                'schedule_post',
                details=f"Post agendado com sucesso: {post_name} para {scheduled_time}."
            )

            flash("Post agendado com sucesso!", "success")
        except ValueError:
            flash("Formato de data e hora inválido. Use o formato YYYY-MM-DD HH:MM.", "danger")
        except Exception as e:
            # Registrar log de erro
            registrar_log(
                current_user.id,
                'schedule_post_error',
                details=f"Erro ao agendar post: {str(e)}"
            )
            flash(f"Erro ao agendar o post: {str(e)}", "danger")

        # Redirecionar para a página inicial ou uma rota de sua escolha
        return redirect(url_for('dashboard'))

    return render_template('schedule_post.html')


@app.route('/scheduled_posts')
@login_required
def scheduled_posts():
    try:
        # Buscar todos os posts agendados
        posts = ScheduledPost.query.all()

        # Registrar log de acesso
        registrar_log(
            current_user.id,
            'view_scheduled_posts',
            details=f"Usuário visualizou {len(posts)} posts agendados."
        )

        return render_template('scheduled_posts.html', posts=posts)
    except Exception as e:
        # Registrar erro caso ocorra
        registrar_log(
            current_user.id,
            'view_scheduled_posts_error',
            details=f"Erro ao acessar posts agendados: {str(e)}"
        )
        flash("Erro ao carregar os posts agendados. Tente novamente.", "danger")
        return redirect(url_for('dashboard'))  # Redireciona para o dashboard em caso de erro

@app.route('/cancel_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def cancel_post(post_id):
    try:
        # Buscar o post agendado
        post = ScheduledPost.query.get_or_404(post_id)

        # Verificar se o post já foi cancelado
        if post.status != "CANCELLED":
            post.status = "CANCELLED"
            db.session.commit()

            # Registrar log de cancelamento
            registrar_log(
                current_user.id,
                'cancel_post',
                details=f"Post com ID {post_id} foi cancelado."
            )
        else:
            # Registrar caso o post já tenha sido cancelado
            registrar_log(
                current_user.id,
                'cancel_post_duplicate',
                details=f"Tentativa de cancelamento do post com ID {post_id}, mas o post já estava cancelado."
            )

        return redirect(url_for('scheduled_posts'))
    except Exception as e:
        # Registrar erro ao tentar cancelar o post
        registrar_log(
            current_user.id,
            'cancel_post_error',
            details=f"Erro ao tentar cancelar o post com ID {post_id}: {str(e)}"
        )
        flash("Erro ao cancelar o post. Tente novamente.", "danger")
        return redirect(url_for('scheduled_posts'))



@app.route('/engagement_report')
@login_required
def engagement_report():
    try:
        # Buscar os 5 posts mais curtidos
        posts = Post.query.order_by(Post.likes.desc()).limit(5).all()

        # Buscar os 5 posts agendados mais próximos
        scheduled_posts = ScheduledPost.query.filter(
            ScheduledPost.scheduled_time >= datetime.now(timezone.utc),
            ScheduledPost.status == "PENDING"
        ).order_by(ScheduledPost.scheduled_time.asc()).limit(5).all()

        # Obter o número de seguidores da página do Facebook
        fan_count = 0
        try:
            fb_url = f"https://graph.facebook.com/{PAGE_ID}?fields=fan_count&access_token={ACCESS_TOKEN}"
            fb_response = requests.get(fb_url).json()
            fan_count = fb_response.get("fan_count", 0)
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_facebook_fan_count_error',
                details=f"Erro ao obter o número de seguidores do Facebook: {str(e)}"
            )
            print("Erro ao obter o número de seguidores do Facebook:", str(e))

        # Obter o número de seguidores da conta do Instagram
        ig_followers_count = 0
        try:
            ig_url = f"https://graph.facebook.com/{INSTAGRAM_ACCOUNT_ID}?fields=followers_count&access_token={ACCESS_TOKEN}"
            ig_response = requests.get(ig_url).json()
            ig_followers_count = ig_response.get("followers_count", 0)
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_instagram_followers_count_error',
                details=f"Erro ao obter o número de seguidores do Instagram: {str(e)}"
            )
            print("Erro ao obter o número de seguidores do Instagram:", str(e))

        # Buscar número de seguidores no Instagram e Facebook
        instagram_followers = 0
        facebook_followers = 0

        try:
            # Facebook
            fb_url = f"https://graph.facebook.com/{PAGE_ID}?fields=fan_count&access_token={ACCESS_TOKEN}"
            fb_response = requests.get(fb_url).json()
            facebook_followers = fb_response.get("fan_count", 0)

            # Instagram
            ig_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}?fields=followers_count&access_token={ACCESS_TOKEN}"
            ig_response = requests.get(ig_url).json()
            instagram_followers = ig_response.get("followers_count", 0)
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_social_followers_error',
                details=f"Erro ao obter seguidores: {str(e)}"
            )
            print("Erro ao buscar seguidores:", str(e))

        # Montar dados dos posts recentes para exibição
        recent_posts = [{
            'name': post.name,
            'message': post.post_id,
            'likes': post.likes,
            'comments': post.comments,
            'shares': post.shares,
        } for post in posts]

        # Preparar dados para gráficos e visualizações
        labels = [post.name for post in posts]
        likes_data = [post.likes for post in posts]
        comments_data = [post.comments for post in posts]
        shares_data = [post.shares for post in posts]

        # Registrar log de acesso ao dashboard
        registrar_log(
            current_user.id,
            'view_dashboard',
            details=f"Acessou o dashboard com {len(posts)} posts recentes e {len(scheduled_posts)} posts agendados."
        )

        # Inicializar total de likes
        total_likes_instagram = 0

        try:
            # URL para buscar posts do Instagram
            ig_posts_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=like_count&access_token={ACCESS_TOKEN}"
            response = requests.get(ig_posts_url).json()

            # Iterar pelos posts e somar os likes
            if "data" in response:
                total_likes_instagram = sum(post.get("like_count", 0) for post in response["data"])

        except Exception as e:
            registrar_log(
                current_user.id,
                'get_instagram_likes_error',
                details=f"Erro ao obter likes do Instagram: {str(e)}"
            )
            print("Erro ao buscar likes do Instagram:", str(e))

        # Inicializar contadores
        total_likes_instagram = 0
        total_likes_facebook = 0

        try:
            # Obter likes do Instagram
            ig_posts_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=like_count&access_token={ACCESS_TOKEN}"
            ig_response = requests.get(ig_posts_url).json()
            if "data" in ig_response:
                total_likes_instagram = sum(post.get("like_count", 0) for post in ig_response["data"])

            # Obter likes do Facebook
            fb_posts_url = f"https://graph.facebook.com/v16.0/{PAGE_ID}/posts?fields=likes.summary(true)&access_token={ACCESS_TOKEN}"
            fb_response = requests.get(fb_posts_url).json()
            if "data" in fb_response:
                total_likes_facebook = sum(
                    post["likes"]["summary"]["total_count"]
                    for post in fb_response["data"]
                    if "likes" in post and "summary" in post["likes"]
                )

        except Exception as e:
            registrar_log(
                current_user.id,
                'get_social_media_likes_error',
                details=f"Erro ao obter likes: {str(e)}"
            )
            print("Erro ao buscar likes nas redes sociais:", str(e))

        instagram_comments = 0
        facebook_comments = 0

        try:
            # Facebook
            fb_comments_url = f"https://graph.facebook.com/{PAGE_ID}/feed?fields=comments.summary(true)&access_token={ACCESS_TOKEN}"
            fb_comments_response = requests.get(fb_comments_url).json()
            facebook_comments = sum(
                post["comments"]["summary"]["total_count"] for post in fb_comments_response.get("data", []) if
                "comments" in post)

            # Instagram
            ig_comments_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=comments_count&access_token={ACCESS_TOKEN}"
            ig_comments_response = requests.get(ig_comments_url).json()
            instagram_comments = sum(media.get("comments_count", 0) for media in ig_comments_response.get("data", []))
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_social_comments_error',
                details=f"Erro ao obter comentários: {str(e)}"
            )
            print("Erro ao buscar comentários:", str(e))

        instagram_shares = 0  # Placeholder, pois o Instagram não fornece esse dado diretamente
        facebook_shares = 0

        try:
            # Facebook
            fb_shares_url = f"https://graph.facebook.com/{PAGE_ID}/feed?fields=shares.summary(true)&access_token={ACCESS_TOKEN}"
            fb_shares_response = requests.get(fb_shares_url).json()
            facebook_shares = sum(
                post["shares"]["count"] for post in fb_shares_response.get("data", []) if "shares" in post)

            # Instagram (compartilhamentos geralmente não disponíveis)
            # Caso tenha um método alternativo, pode ser implementado aqui
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_social_shares_error',
                details=f"Erro ao obter compartilhamentos: {str(e)}"
            )
            print("Erro ao buscar compartilhamentos:", str(e))

        # Variáveis para o gráfico
        labels = []
        facebook_likes_data = []
        facebook_comments_data = []
        instagram_likes_data = []
        instagram_comments_data = []

        # Calcula a data mínima (5 dias atrás)
        min_date = (datetime.now() - timedelta(days=500)).date()

        try:
            # Facebook - Likes e Comentários
            fb_engagement_url = f"https://graph.facebook.com/{PAGE_ID}/posts?fields=likes.summary(true),comments.summary(true),created_time&access_token={ACCESS_TOKEN}"
            fb_engagement_response = requests.get(fb_engagement_url).json()

            for post in fb_engagement_response.get("data", []):
                post_date = datetime.strptime(post["created_time"][:10], "%Y-%m-%d").date()
                if post_date >= min_date:  # Verifica se a data está nos últimos 5 dias
                    labels.append(post["created_time"][:10])
                    facebook_likes_data.append(post.get("likes", {}).get("summary", {}).get("total_count", 0))
                    facebook_comments_data.append(post.get("comments", {}).get("summary", {}).get("total_count", 0))

            # Instagram - Likes e Comentários
            ig_engagement_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=like_count,comments_count,timestamp&access_token={ACCESS_TOKEN}"
            ig_engagement_response = requests.get(ig_engagement_url).json()

            for media in ig_engagement_response.get("data", []):
                media_date = datetime.strptime(media["timestamp"][:10], "%Y-%m-%d").date()
                if media_date >= min_date:  # Verifica se a data está nos últimos 5 dias
                    labels.append(media["timestamp"][:10])
                    instagram_likes_data.append(media.get("like_count", 0))
                    instagram_comments_data.append(media.get("comments_count", 0))

        except Exception as e:
            registrar_log(
                current_user.id,
                'get_engagement_data_error',
                details=f"Erro ao obter dados de engajamento: {str(e)}"
            )
            print("Erro ao buscar dados de engajamento:", str(e))

        # Calcular data inicial (últimos 70 dias)
        start_date = (datetime.now() - timedelta(days=30)).date()

        # Inicializar contadores
        new_facebook_followers = 0
        new_instagram_followers = 0
        new_facebook_likes = 0
        new_instagram_likes = 0
        new_facebook_comments = 0
        new_instagram_comments = 0
        new_facebook_shares = 0
        new_instagram_shares = 0

        try:
            # Facebook
            fb_engagement_url = f"https://graph.facebook.com/{PAGE_ID}/posts?fields=likes.summary(true),comments.summary(true),shares.summary(true),created_time&access_token={ACCESS_TOKEN}"
            fb_engagement_response = requests.get(fb_engagement_url).json()

            for post in fb_engagement_response.get("data", []):
                post_date = datetime.strptime(post["created_time"][:10], "%Y-%m-%d").date()
                if post_date >= start_date:
                    new_facebook_likes += post.get("likes", {}).get("summary", {}).get("total_count", 0)
                    new_facebook_comments += post.get("comments", {}).get("summary", {}).get("total_count", 0)
                    new_facebook_shares += post.get("shares", {}).get("count", 0)

            # Instagram
            ig_engagement_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=like_count,comments_count,timestamp&access_token={ACCESS_TOKEN}"
            ig_engagement_response = requests.get(ig_engagement_url).json()

            for media in ig_engagement_response.get("data", []):
                media_date = datetime.strptime(media["timestamp"][:10], "%Y-%m-%d").date()
                if media_date >= start_date:
                    new_instagram_likes += media.get("like_count", 0)
                    new_instagram_comments += media.get("comments_count", 0)

        except Exception as e:
            registrar_log(
                current_user.id,
                'get_70_days_engagement_error',
                details=f"Erro ao obter engajamento dos últimos 70 dias: {str(e)}"
            )
            print("Erro ao buscar engajamento dos últimos 70 dias:", str(e))

        return render_template(
            'engagement_report.html',
            total_likes_instagram=total_likes_instagram,
            total_likes_facebook=total_likes_facebook,
            total_likes=total_likes_facebook + total_likes_instagram,
            total_comments=sum([post.comments for post in posts]),
            total_shares=sum([post.shares for post in posts]),
            fan_count=facebook_followers + instagram_followers,
            facebook_followers=facebook_followers,
            instagram_followers=instagram_followers,
            recent_posts=recent_posts,
            scheduled_posts=scheduled_posts,
            new_facebook_followers=new_facebook_followers,
            new_instagram_followers=new_instagram_followers,
            new_facebook_likes=new_facebook_likes,
            new_instagram_likes=new_instagram_likes,
            new_facebook_comments=new_facebook_comments,
            new_instagram_comments=new_instagram_comments,
            new_facebook_shares=new_facebook_shares,
            new_instagram_shares=new_instagram_shares,
            labels=list(set(labels)),
            facebook_likes_data=facebook_likes_data,
            facebook_comments_data=facebook_comments_data,
            instagram_likes_data=instagram_likes_data,
            instagram_comments_data=instagram_comments_data,
            facebook_comments=facebook_comments,
            instagram_comments=instagram_comments,
            total_commentss=instagram_comments + facebook_comments,
            total_sharess=facebook_shares + instagram_shares,
            facebook_shares=facebook_shares,
            instagram_shares=instagram_shares
        )

    except Exception as e:
        # Registrar erro no dashboard
        registrar_log(
            current_user.id,
            'view_engagement_report_error',
            details=f"Erro ao acessar o dashboard: {str(e)}"
        )
        flash("Erro ao carregar o dashboard. Tente novamente.", "danger")
        return redirect(url_for('engagement_report'))  # Redireciona para a mesma página em caso de erro
# Definindo a rota para o dashboard
# Rota para o dashboard
@app.route('/')
@login_required
def dashboard():
    try:
        # Buscar os 5 posts mais curtidos
        posts = Post.query.order_by(Post.likes.desc()).limit(5).all()

        # Buscar os 5 posts agendados mais próximos
        scheduled_posts = ScheduledPost.query.filter(
            ScheduledPost.scheduled_time >= datetime.now(timezone.utc),
            ScheduledPost.status == "PENDING"
        ).order_by(ScheduledPost.scheduled_time.asc()).limit(5).all()

        # Obter o número de seguidores da página do Facebook
        fan_count = 0
        try:
            fb_url = f"https://graph.facebook.com/{PAGE_ID}?fields=fan_count&access_token={ACCESS_TOKEN}"
            fb_response = requests.get(fb_url).json()
            fan_count = fb_response.get("fan_count", 0)
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_facebook_fan_count_error',
                details=f"Erro ao obter o número de seguidores do Facebook: {str(e)}"
            )
            print("Erro ao obter o número de seguidores do Facebook:", str(e))

        # Obter o número de seguidores da conta do Instagram
        ig_followers_count = 0
        try:
            ig_url = f"https://graph.facebook.com/{INSTAGRAM_ACCOUNT_ID}?fields=followers_count&access_token={ACCESS_TOKEN}"
            ig_response = requests.get(ig_url).json()
            ig_followers_count = ig_response.get("followers_count", 0)
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_instagram_followers_count_error',
                details=f"Erro ao obter o número de seguidores do Instagram: {str(e)}"
            )
            print("Erro ao obter o número de seguidores do Instagram:", str(e))

        # Buscar número de seguidores no Instagram e Facebook
        instagram_followers = 0
        facebook_followers = 0

        try:
            # Facebook
            fb_url = f"https://graph.facebook.com/{PAGE_ID}?fields=fan_count&access_token={ACCESS_TOKEN}"
            fb_response = requests.get(fb_url).json()
            facebook_followers = fb_response.get("fan_count", 0)

            # Instagram
            ig_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}?fields=followers_count&access_token={ACCESS_TOKEN}"
            ig_response = requests.get(ig_url).json()
            instagram_followers = ig_response.get("followers_count", 0)
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_social_followers_error',
                details=f"Erro ao obter seguidores: {str(e)}"
            )
            print("Erro ao buscar seguidores:", str(e))

        # Montar dados dos posts recentes para exibição
        recent_posts = [{
            'name': post.name,
            'message': post.post_id,
            'likes': post.likes,
            'comments': post.comments,
            'shares': post.shares,
        } for post in posts]

        # Preparar dados para gráficos e visualizações
        labels = [post.name for post in posts]
        likes_data = [post.likes for post in posts]
        comments_data = [post.comments for post in posts]
        shares_data = [post.shares for post in posts]

        # Registrar log de acesso ao dashboard
        registrar_log(
            current_user.id,
            'view_dashboard',
            details=f"Acessou o dashboard com {len(posts)} posts recentes e {len(scheduled_posts)} posts agendados."
        )

        # Inicializar total de likes
        total_likes_instagram = 0

        try:
            # URL para buscar posts do Instagram
            ig_posts_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=like_count&access_token={ACCESS_TOKEN}"
            response = requests.get(ig_posts_url).json()

            # Iterar pelos posts e somar os likes
            if "data" in response:
                total_likes_instagram = sum(post.get("like_count", 0) for post in response["data"])

        except Exception as e:
            registrar_log(
                current_user.id,
                'get_instagram_likes_error',
                details=f"Erro ao obter likes do Instagram: {str(e)}"
            )
            print("Erro ao buscar likes do Instagram:", str(e))

        # Inicializar contadores
        total_likes_instagram = 0
        total_likes_facebook = 0

        try:
            # Obter likes do Instagram
            ig_posts_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=like_count&access_token={ACCESS_TOKEN}"
            ig_response = requests.get(ig_posts_url).json()
            if "data" in ig_response:
                total_likes_instagram = sum(post.get("like_count", 0) for post in ig_response["data"])

            # Obter likes do Facebook
            fb_posts_url = f"https://graph.facebook.com/v16.0/{PAGE_ID}/posts?fields=likes.summary(true)&access_token={ACCESS_TOKEN}"
            fb_response = requests.get(fb_posts_url).json()
            if "data" in fb_response:
                total_likes_facebook = sum(
                    post["likes"]["summary"]["total_count"]
                    for post in fb_response["data"]
                    if "likes" in post and "summary" in post["likes"]
                )

        except Exception as e:
            registrar_log(
                current_user.id,
                'get_social_media_likes_error',
                details=f"Erro ao obter likes: {str(e)}"
            )
            print("Erro ao buscar likes nas redes sociais:", str(e))

        instagram_comments = 0
        facebook_comments = 0

        try:
            # Facebook
            fb_comments_url = f"https://graph.facebook.com/{PAGE_ID}/feed?fields=comments.summary(true)&access_token={ACCESS_TOKEN}"
            fb_comments_response = requests.get(fb_comments_url).json()
            facebook_comments = sum(
                post["comments"]["summary"]["total_count"] for post in fb_comments_response.get("data", []) if
                "comments" in post)

            # Instagram
            ig_comments_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=comments_count&access_token={ACCESS_TOKEN}"
            ig_comments_response = requests.get(ig_comments_url).json()
            instagram_comments = sum(media.get("comments_count", 0) for media in ig_comments_response.get("data", []))
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_social_comments_error',
                details=f"Erro ao obter comentários: {str(e)}"
            )
            print("Erro ao buscar comentários:", str(e))

        instagram_shares = 0  # Placeholder, pois o Instagram não fornece esse dado diretamente
        facebook_shares = 0

        try:
            # Facebook
            fb_shares_url = f"https://graph.facebook.com/{PAGE_ID}/feed?fields=shares.summary(true)&access_token={ACCESS_TOKEN}"
            fb_shares_response = requests.get(fb_shares_url).json()
            facebook_shares = sum(
                post["shares"]["count"] for post in fb_shares_response.get("data", []) if "shares" in post)

            # Instagram (compartilhamentos geralmente não disponíveis)
            # Caso tenha um método alternativo, pode ser implementado aqui
        except Exception as e:
            registrar_log(
                current_user.id,
                'get_social_shares_error',
                details=f"Erro ao obter compartilhamentos: {str(e)}"
            )
            print("Erro ao buscar compartilhamentos:", str(e))

        # Variáveis para o gráfico
        labels = []
        facebook_likes_data = []
        facebook_comments_data = []
        instagram_likes_data = []
        instagram_comments_data = []

        # Calcula a data mínima (5 dias atrás)
        min_date = (datetime.now() - timedelta(days=500)).date()

        try:
            # Facebook - Likes e Comentários
            fb_engagement_url = f"https://graph.facebook.com/{PAGE_ID}/posts?fields=likes.summary(true),comments.summary(true),created_time&access_token={ACCESS_TOKEN}"
            fb_engagement_response = requests.get(fb_engagement_url).json()

            for post in fb_engagement_response.get("data", []):
                post_date = datetime.strptime(post["created_time"][:10], "%Y-%m-%d").date()
                if post_date >= min_date:  # Verifica se a data está nos últimos 5 dias
                    labels.append(post["created_time"][:10])
                    facebook_likes_data.append(post.get("likes", {}).get("summary", {}).get("total_count", 0))
                    facebook_comments_data.append(post.get("comments", {}).get("summary", {}).get("total_count", 0))

            # Instagram - Likes e Comentários
            ig_engagement_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media?fields=like_count,comments_count,timestamp&access_token={ACCESS_TOKEN}"
            ig_engagement_response = requests.get(ig_engagement_url).json()

            for media in ig_engagement_response.get("data", []):
                media_date = datetime.strptime(media["timestamp"][:10], "%Y-%m-%d").date()
                if media_date >= min_date:  # Verifica se a data está nos últimos 5 dias
                    labels.append(media["timestamp"][:10])
                    instagram_likes_data.append(media.get("like_count", 0))
                    instagram_comments_data.append(media.get("comments_count", 0))

        except Exception as e:
            registrar_log(
                current_user.id,
                'get_engagement_data_error',
                details=f"Erro ao obter dados de engajamento: {str(e)}"
            )
            print("Erro ao buscar dados de engajamento:", str(e))


        return render_template(
            'dashboard.html',
            total_likes_instagram=total_likes_instagram,
            total_likes_facebook=total_likes_facebook,
            total_likes=total_likes_facebook + total_likes_instagram,
            total_comments=sum([post.comments for post in posts]),
            total_shares=sum([post.shares for post in posts]),
            fan_count=facebook_followers + instagram_followers,
            facebook_followers=facebook_followers,
            instagram_followers=instagram_followers,
            recent_posts=recent_posts,
            scheduled_posts=scheduled_posts,
            labels=list(set(labels)),
            facebook_likes_data=facebook_likes_data,
            facebook_comments_data=facebook_comments_data,
            instagram_likes_data=instagram_likes_data,
            instagram_comments_data=instagram_comments_data,
            facebook_comments=facebook_comments,
            instagram_comments=instagram_comments,
            total_commentss=instagram_comments + facebook_comments,
            total_sharess=facebook_shares + instagram_shares,
            facebook_shares=facebook_shares,
            instagram_shares=instagram_shares
        )

    except Exception as e:
        # Registrar erro no dashboard
        registrar_log(
            current_user.id,
            'view_dashboard_error',
            details=f"Erro ao acessar o dashboard: {str(e)}"
        )
        flash("Erro ao carregar o dashboard. Tente novamente.", "danger")
        return redirect(url_for('dashboard'))  # Redireciona para a mesma página em caso de erro

from flask import render_template

@app.route('/post_form', methods=['GET'])
def post_form():
    return render_template('post_instagram.html')

def upload_image_to_hosting_service(file_path):
    """Envia a imagem para um serviço de hospedagem e retorna a URL."""
    # Substitua por um serviço de hospedagem real, como Cloudinary ou ImgBB
    # Aqui está um exemplo com ImgBB:
    with open(file_path, "rb") as file:
        response = requests.post(
            "https://api.imgbb.com/1/upload",
            params={"key": "bc82e67936f541cc88311ce500bde68b"},
            files={"image": file}
        )
    response_data = response.json()
    if response.status_code == 200:
        return response_data["data"]["url"]
    else:
        raise Exception("Erro ao enviar imagem para o ImgBB.")

@app.route('/post_to_instagram', methods=['POST'])
def post_to_instagram():
    try:
        # Processa o upload do arquivo
        image_file = request.files.get("image_file")
        caption = request.form.get("caption")

        if not image_file or not caption:
            return jsonify({"error": "A imagem e a legenda são obrigatórias."}), 400

        # Salva o arquivo localmente
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], image_file.filename)
        image_file.save(file_path)

        # Faz upload da imagem para o serviço de hospedagem
        image_url = upload_image_to_hosting_service(file_path)

        # Passo 1: Criar container de mídia
        create_media_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media"
        media_data = {
            "image_url": image_url,
            "caption": caption,
            "access_token": ACCESS_TOKEN
        }

        media_response = requests.post(create_media_url, data=media_data).json()

        if "id" not in media_response:
            return jsonify({"error": "Falha ao criar container de mídia.", "details": media_response}), 400

        media_id = media_response["id"]

        # Passo 2: Publicar mídia no Instagram
        publish_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media_publish"
        publish_data = {
            "creation_id": media_id,
            "access_token": ACCESS_TOKEN
        }

        publish_response = requests.post(publish_url, data=publish_data).json()

        if "id" not in publish_response:
            return jsonify({"error": "Falha ao publicar mídia.", "details": publish_response}), 400

        # Remove o arquivo local após o upload
        os.remove(file_path)

        return jsonify({
            "success": True,
            "post_id": publish_response["id"]
        })

    except Exception as e:
        return jsonify({"error": "Ocorreu um erro ao postar no Instagram.", "details": str(e)}), 500

# Rota para Postar Mensagem
@app.route('/post_message', methods=['POST'])
@login_required
def post_message():
    caption = request.form.get('caption')
    post_name = request.form.get('post_name')

    try:
        # Postar mensagem no feed do Facebook
        response = graph.put_object("me", "feed", message=caption)

        # Armazenar o ID do post e o nome na base de dados
        new_post = Post(post_id=response['id'], name=post_name)
        db.session.add(new_post)
        db.session.commit()

        flash("Mensagem postada com sucesso no Facebook!", "success")
    except Exception as e:
        flash(f"Erro ao postar mensagem no Facebook: {str(e)}", "danger")

    # Redirecionar para uma página desejada (substitua 'index' pela rota correta)
    return redirect(url_for('dashboard'))

# Rota para Postar Foto
# Função para verificar extensão permitida
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

from flask import url_for

from flask import url_for, send_from_directory
import json

@app.route('/promote', methods=['POST'])
def promote_post():
    post_id = request.json.get('post_id')  # ID da postagem
    budget = request.json.get('budget', 500)  # Orçamento padrão (500 = $5)

    # Validar o ID da postagem e o orçamento
    if not post_id:
        return jsonify({"success": False, "error": "O ID da postagem é obrigatório."}), 400
    if budget < 100:  # Exemplo: verificar o orçamento mínimo
        return jsonify({"success": False, "error": "Orçamento insuficiente. O valor mínimo é 100 centavos."}), 400

    # Configurar público-alvo
    targeting = {
        "geo_locations": {"countries": ["MZ"]},  # Moçambique
        "age_min": 18,
        "age_max": 45
    }

    # Definir o tempo de execução do anúncio
    start_time = (datetime.now() + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%S%z')
    end_time = (datetime.now() + timedelta(days=5)).strftime('%Y-%m-%dT%H:%M:%S%z')

    try:
        graph = fb.GraphAPI(ACCESS_TOKEN)

        # Criar o Ad Creative
        creative = graph.put_object(
            parent_object=AD_ACCOUNT_ID,
            connection_name="adcreatives",
            object_story_id=post_id  # ID da postagem
        )

        # Criar o Ad Set
        ad_set = graph.put_object(
            parent_object=AD_ACCOUNT_ID,
            connection_name="adsets",
            name="Promoção de Postagem",
            daily_budget=budget,
            start_time=start_time,
            end_time=end_time,
            billing_event="IMPRESSIONS",
            optimization_goal="POST_ENGAGEMENT",
            targeting=json.dumps(targeting)  # Certificar-se de que é JSON válido
        )

        # Criar o Anúncio
        ad = graph.put_object(
            parent_object=AD_ACCOUNT_ID,
            connection_name="ads",
            name="Anúncio da Postagem",
            adset_id=ad_set["id"],
            creative={"creative_id": creative["id"]},
            status="ACTIVE"  # Ativar imediatamente
        )

        return jsonify({"success": True, "ad_id": ad["id"]}), 200
    except fb.GraphAPIError as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/post_to_both', methods=['POST'])
@login_required
def post_to_both():
    try:
        caption = request.form.get("caption")
        post_name = request.form.get("post_name")
        platforms = request.form.getlist("platforms")
        file = request.files.get("file")

        if not platforms:
            flash("Por favor, selecione ao menos uma plataforma para postar.", "danger")
            return redirect(url_for('dashboard'))

        if not file or file.filename == '':
            flash("Nenhuma imagem enviada. Envie uma foto.", "danger")
            return redirect(url_for('dashboard'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            image_url = upload_image_to_hosting_service(filepath)
            success_messages = []
            error_messages = []

            # Postar no Instagram
            if "instagram" in platforms:
                instagram_response = post_to_instagram_api(image_url, caption)
                if instagram_response.get("id"):
                    success_messages.append("Postagem no Instagram bem-sucedida!")
                else:
                    error_messages.append(f"Instagram: {instagram_response.get('details', 'Erro desconhecido')}")

            # Postar no Facebook
            if "facebook" in platforms:
                try:
                    with open(filepath, "rb") as image:
                        facebook_response = graph.put_photo(image, message=caption)
                        if facebook_response.get("post_id"):
                            success_messages.append("Postagem no Facebook bem-sucedida!")
                        else:
                            error_messages.append("Facebook: Erro ao publicar.")
                except Exception as e:
                    error_messages.append(f"Facebook: {str(e)}")

            os.remove(filepath)

            for msg in success_messages:
                flash(msg, "success")
            for msg in error_messages:
                flash(msg, "danger")

            return redirect(url_for('dashboard'))

        flash("Tipo de arquivo não permitido.", "danger")
        return redirect(url_for('dashboard'))

    except Exception as e:
        flash(f"Ocorreu um erro: {str(e)}", "danger")
        return redirect(url_for('dashboard'))

def post_to_instagram_api(image_url, caption):
    # Criar container de mídia
    create_media_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media"
    media_data = {
        "image_url": image_url,
        "caption": caption,
        "access_token": ACCESS_TOKEN
    }

    media_response = requests.post(create_media_url, data=media_data).json()
    if "id" not in media_response:
        return {"error": "Falha ao criar container de mídia.", "details": media_response}

    media_id = media_response["id"]

    # Publicar mídia no Instagram
    publish_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media_publish"
    publish_data = {
        "creation_id": media_id,
        "access_token": ACCESS_TOKEN
    }

    publish_response = requests.post(publish_url, data=publish_data).json()
    return publish_response

from datetime import datetime
import requests


@app.route('/fetch_posts', methods=['GET'])
@login_required
def fetch_posts():
    try:
        # Configuração das URLs das APIs
        facebook_posts_url = f"https://graph.facebook.com/v16.0/{PAGE_ID}/posts"
        instagram_posts_url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media"

        params = {"access_token": ACCESS_TOKEN, "limit": 5}

        # Buscar postagens do Facebook
        fb_response = requests.get(facebook_posts_url, params=params).json()
        fb_posts = [
            {
                "id": post["id"],
                "message": post.get("message", ""),
                "created_time": post["created_time"],
                "platform": "facebook"
            }
            for post in fb_response.get("data", [])
        ]

        # Buscar postagens do Instagram
        ig_response = requests.get(instagram_posts_url, params=params).json()
        ig_posts = [
            {
                "id": post["id"],
                "caption": post.get("caption", ""),
                "created_time": post["timestamp"],
                "platform": "instagram"
            }
            for post in ig_response.get("data", [])
        ]

        # Combinar e identificar postagens cruzadas
        combined_posts = []
        for fb_post in fb_posts:
            fb_created = datetime.fromisoformat(fb_post["created_time"].replace("Z", ""))
            fb_post["platforms"] = ["facebook"]

            for ig_post in ig_posts:
                ig_created = datetime.fromisoformat(ig_post["created_time"].replace("Z", ""))
                time_difference = abs((fb_created - ig_created).total_seconds())

                if time_difference < 60:  # Considerar postagens com até 1 minuto de diferença como sendo a mesma
                    fb_post["platforms"].append("instagram")
                    ig_posts.remove(ig_post)

            combined_posts.append(fb_post)

        # Adicionar postagens restantes do Instagram
        for ig_post in ig_posts:
            ig_post["platforms"] = ["instagram"]
            combined_posts.append(ig_post)

        # Ordenar por data de criação
        combined_posts = sorted(combined_posts, key=lambda x: x["created_time"], reverse=True)

        return jsonify({"posts": combined_posts[:5]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Rota para Postar Foto com Nome do Post
@app.route('/post_photo', methods=['POST'])
@login_required
def post_photo():
    message = request.form.get('message')
    post_name = request.form.get('post_name')
    file = request.files.get('file')

    if not file or file.filename == '':
        flash("Nenhum arquivo foi enviado. Por favor, envie uma foto.", "danger")
        return redirect(url_for('dashboard'))  # Substitua pela rota correta.

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            with open(filepath, "rb") as image:
                # Postar a foto no Facebook
                response = graph.put_photo(image, message=message)
                post_id = response['post_id']

                # Salvar nome e ID do post na base de dados
                new_post = Post(post_id=post_id, name=post_name)
                db.session.add(new_post)
                db.session.commit()

            os.remove(filepath)
            flash("Foto postada com sucesso no Facebook!", "success")
        except Exception as e:
            flash(f"Erro ao postar a foto: {str(e)}", "danger")
            os.remove(filepath)

        return redirect(url_for('dashboard'))  # Substitua pela rota correta.

    flash("Tipo de arquivo não permitido. Envie uma imagem válida.", "danger")
    return redirect(url_for('dashboard'))  # Substitua pela rota correta

# Rota para Comentar em um Post
@app.route('/comment_post', methods=['POST'])
@login_required
def comment_post():
    post_id = request.form.get('post_id')
    comment = request.form.get('comment')
    try:
        response = graph.put_object(post_id, "comments", message=comment)
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Rota para Obter Informações de um Post
@app.route('/get_post', methods=['GET'])
@login_required
def get_post():
    post_id = request.args.get('post_id')
    try:
        response = graph.get_object(post_id)
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Rota para Obter o Número de Curtidas da Página
@app.route('/get_fan_count', methods=['GET'])
@login_required
def get_fan_count():
    try:
        url = f"https://graph.facebook.com/me?fields=fan_count&access_token={ACCESS_TOKEN}"
        response = requests.get(url).json()
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def fetch_engagement_metrics(post_id):
    try:
        metrics = graph.get_object(id=post_id, fields='likes.summary(true),comments.summary(true),shares')
        likes = metrics['likes']['summary']['total_count']
        comments = metrics['comments']['summary']['total_count']
        shares = metrics.get('shares', {}).get('count', 0)
        return likes, comments, shares
    except Exception as e:
        print(f"Erro ao buscar métricas: {e}")
        return 0, 0, 0

def update_post_metrics():
    with app.app_context():
        posts = Post.query.all()
        for post in posts:
            likes, comments, shares = fetch_engagement_metrics(post.post_id)
            post.likes = likes
            post.comments = comments
            post.shares = shares
        db.session.commit()


# Agendar a atualização a cada 10 minutos
scheduler.add_job(update_post_metrics, 'interval', minutes=3)

def fetch_facebook_data():
    """
    Fetches posts and their engagement metrics from the Facebook Page.
    """
    fields = "id,message,insights.metric(post_engaged_users,post_impressions),likes.summary(true),comments.summary(true),shares"
    posts = graph.get_connections(PAGE_ID, 'posts', fields=fields, limit=10)

    data = []
    for post in posts['data']:
        post_data = {
            'id': post['id'],
            'name': post.get('message', 'Sem Título'),
            'likes': post['likes']['summary']['total_count'] if 'likes' in post else 0,
            'comments': post['comments']['summary']['total_count'] if 'comments' in post else 0,
            'shares': post.get('shares', {}).get('count', 0)
        }
        data.append(post_data)

    return data

def fetch_instagram_data():
    """
    Fetches posts and their engagement metrics from the Instagram account.
    """
    fields = "id,caption,media_type,media_url,like_count,comments_count"
    posts = graph.get_connections(INSTAGRAM_ACCOUNT_ID, 'media', fields=fields, limit=10)

    data = []
    for post in posts['data']:
        post_data = {
            'id': post['id'],
            'name': post.get('caption', 'Sem Título'),
            'likes': post.get('like_count', 0),
            'comments': post.get('comments_count', 0),
            'shares': 0  # Instagram não fornece compartilhamentos diretamente
        }
        data.append(post_data)

    return data



@app.route('/select_post_comments', methods=['GET', 'POST'])
@login_required
def select_post_comments():
    if request.method == 'POST':
        # Obtenha o ID do post selecionado
        post_id = request.form.get('post_id')
        return view_comments(post_id=post_id)

    # Se for uma requisição GET, exiba a lista de posts
    posts = Post.query.all()
    return render_template('select_post.html', posts=posts)

@app.route('/view_comments', methods=['GET'])
@login_required
def view_comments(post_id=None):
    if not post_id:
        post_id = request.args.get('post_id')
    try:
        comments_data = graph.get_connections(post_id, 'comments')
        comments = comments_data['data']
        return render_template('render_comments.html', comments=comments, post_id=post_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/reply_comments', methods=['POST'])
@login_required
def reply_comments():
    comment_id = request.form.get('comment_id')
    reply_message = request.form.get('reply_message')

    if not comment_id or not reply_message:
        flash("ID do comentário e mensagem de resposta são obrigatórios.", "danger")
        return redirect(url_for('dashboard'))  # Substitua 'reply_page' pela rota correta.

    try:
        # Responder ao comentário no Facebook
        response = graph.put_object(comment_id, "comments", message=reply_message)
        flash("Comentário respondido com sucesso!", "success")
    except Exception as e:
        flash(f"Erro ao responder ao comentário: {str(e)}", "danger")

    # Redirecionar para uma página desejada
    return redirect(url_for('dashboard'))  # Substitua 'reply_page' pela rota correta.


# Define perguntas frequentes e respostas automáticas
FAQ_ANSWERS = {
    "qual é o horário de atendimento?": "Nosso horário de atendimento é das 9h às 18h, de segunda a sexta.",
    "como posso entrar em contato?": "Você pode entrar em contato conosco pelo telefone 85 7959590/ 82 7786749 ou por mensagem direta.",
    "onde vocês estão localizados?": "Estamos localizados na Rua Correia de Brito N 2156 R/C- Baixa.",
    "Qual é o custo da entrega? É grátis para compras acima de um valor específico?" : "O custo da entrega varia conforme a localização. Os precos partem de 100MZN",
   "Posso trocar ou devolver um produto? Qual é o prazo para isso?" : "Você pode devolver ou trocar produtos dentro de um prazo de 7 a 30 dias após o recebimento"
}

def auto_reply(comment_text):
    # Verifica se o comentário corresponde a uma pergunta frequente
    for question, answer in FAQ_ANSWERS.items():
        if question in comment_text.lower():
            return answer
    return None

def auto_reply_to_faqs():
    with app.app_context():
        posts = Post.query.all()
        for post in posts:
            try:
                comments_data = graph.get_connections(post.post_id, 'comments')
                comments = comments_data['data']
                for comment in comments:
                    auto_reply_message = auto_reply(comment['message'])
                    if auto_reply_message:
                        graph.put_object(comment['id'], "comments", message=auto_reply_message)
            except Exception as e:
                print(f"Erro ao responder automaticamente: {e}")


# Agendar a verificação e resposta automática a cada 5 minutos
scheduler.add_job(auto_reply_to_faqs, 'interval', minutes=5)


@app.route('/get_messages_by_sender', methods=['GET'])
@login_required
def get_messages_by_sender():
    sender_id = request.args.get('sender_id')
    if not sender_id:
        return jsonify({"error": "Sender ID is required"}), 400

    try:
        # Aqui filtramos apenas as mensagens do remetente específico
        url = f"https://graph.facebook.com/v14.0/me/conversations?fields=messages{{message,created_time,from}}&access_token={ACCESS_TOKEN}"
        response = requests.get(url).json()

        messages = [
            {
                "text": msg.get("message", ""),
                "created_time": msg.get("created_time", "Desconhecido"),
            }
            for conversation in response.get('data', [])
            for msg in conversation.get('messages', {}).get('data', [])
            if msg.get("from", {}).get("id") == sender_id
        ]

        return jsonify({"messages": messages})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_messages', methods=['GET'])
@login_required
def get_messages():
    try:
        # ID do usuário autenticado
        user_id = PAGE_ID  # Substitua por uma variável que contenha seu ID ou extraia do token de acesso

        # Chamada à API
        url = f"https://graph.facebook.com/v14.0/me/conversations?fields=participants,messages{{id,from}}&access_token={ACCESS_TOKEN}"
        response = requests.get(url).json()

        unique_senders = {}
        for conversation in response.get('data', []):
            participants = conversation.get('participants', {}).get('data', [])
            for participant in participants:
                sender_id = participant.get('id')
                # Exclui o usuário autenticado
                if sender_id != user_id and sender_id not in unique_senders:
                    unique_senders[sender_id] = {
                        'id': sender_id,
                        'name': participant.get('name', 'Desconhecido'),
                        'picture': participant.get('picture', {}).get('data', {}).get('url',
                                                                                      '/static/images/default-avatar.png')
                    }

        return render_template('messages.html', unique_senders=unique_senders.values())
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/get_full_conversation', methods=['GET'])
@login_required
def get_full_conversation():
    sender_id = request.args.get('sender_id')
    if not sender_id:
        return jsonify({"error": "Sender ID is required"}), 400

    try:
        # Busca todas as mensagens de uma conversa
        url = f"https://graph.facebook.com/v14.0/me/conversations?fields=messages{{message,created_time,from}}&access_token={ACCESS_TOKEN}"
        response = requests.get(url).json()

        messages = []
        for conversation in response.get('data', []):
            for msg in conversation.get('messages', {}).get('data', []):
                is_sent = msg.get('from', {}).get('id') == PAGE_ID
                messages.append({
                    "text": msg.get("message", ""),
                    "type": "sent" if is_sent else "received",
                    "created_time": msg.get("created_time", "Desconhecido")
                })

        # Filtrar mensagens trocadas com o remetente específico
        messages = [msg for msg in messages if msg["type"] == "received" or msg["type"] == "sent"]

        return jsonify({"messages": messages})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def get_responded_messages():
    """
    Função para buscar os IDs das mensagens respondidas usando uma API.
    Retorna uma lista de IDs de mensagens já respondidas.
    """
    try:
        # Configuração do endpoint da API
        url = f"https://graph.facebook.com/v14.0/me/messages?fields=id,to,from,message,reply&access_token={ACCESS_TOKEN}"

        # Fazer a requisição à API
        response = requests.get(url)
        response.raise_for_status()  # Levanta exceção para erros HTTP

        data = response.json()
        responded_messages = []

        # Processar as mensagens para identificar respostas
        for message in data.get('data', []):
            if 'reply' in message:  # Verifica se há uma resposta associada
                responded_messages.append(message['id'])

        return responded_messages

    except requests.exceptions.RequestException as e:
        print(f"Erro ao acessar a API: {e}")
        return []

@app.route('/reply_message', methods=['POST'])
@login_required
def reply_message():
    recipient_id = request.form.get('recipient_id')
    message_text = request.form.get('message_text')

    if not recipient_id or not message_text:
        flash("ID do destinatário e mensagem são obrigatórios.", "danger")
        return redirect(url_for('dashboard'))  # Substitua 'reply_page' pela rota correta.

    try:
        # Endpoint da API para enviar mensagens
        url = f"https://graph.facebook.com/v14.0/me/messages?access_token={ACCESS_TOKEN}"
        data = {
            "recipient": {"id": recipient_id},
            "message": {"text": message_text}
        }
        response = requests.post(url, json=data)

        if response.status_code == 200:
            flash("Mensagem enviada com sucesso!", "success")
        else:
            error_message = response.json().get("error", {}).get("message", "Erro desconhecido")
            flash(f"Erro ao enviar mensagem: {error_message}", "danger")
    except Exception as e:
        flash(f"Erro ao enviar mensagem: {str(e)}", "danger")

    # Redirecionar para a página de resposta
    return redirect(url_for('get_messages'))

@app.route('/get_posts', methods=['GET'])
@login_required
def get_posts():
    try:
        # Obter posts do Facebook
        facebook_posts = graph.get_connections(id='me', connection_name='posts')
        post_data = []

        # Processar posts do Facebook
        for post in facebook_posts['data']:
            post_id = post.get('id', 'N/A')
            message = post.get('message', 'Sem mensagem')
            created_time = post.get('created_time', 'Desconhecido')

            post_details = graph.get_object(id=post_id, fields='likes.summary(true),comments.summary(true),shares')
            likes_count = post_details.get('likes', {}).get('summary', {}).get('total_count', 0)
            comments_count = post_details.get('comments', {}).get('summary', {}).get('total_count', 0)
            shares_count = post_details.get('shares', {}).get('count', 0)

            post_data.append({
                'id': post_id,
                'platform': 'facebook',
                'message': message,
                'created_time': created_time,
                'likes': likes_count,
                'comments': comments_count,
                'shares': shares_count
            })

        # Obter o ID do Instagram vinculado à página
        page_details = graph.get_object(id='me', fields='instagram_business_account')
        instagram_account_id = page_details.get('instagram_business_account', {}).get('id')

        if instagram_account_id:
            # Obter posts do Instagram
            instagram_posts = graph.get_connections(id=instagram_account_id, connection_name='media')

            for post in instagram_posts['data']:
                post_id = post.get('id', 'N/A')
                caption = post.get('caption', 'Sem legenda')
                created_time = post.get('timestamp', 'Desconhecido')

                post_details = graph.get_object(id=post_id, fields='like_count,comments_count')
                likes_count = post_details.get('like_count', 0)
                comments_count = post_details.get('comments_count', 0)

                post_data.append({
                    'id': post_id,
                    'platform': 'instagram',
                    'message': caption,
                    'created_time': created_time,
                    'likes': likes_count,
                    'comments': comments_count,
                    'shares': 0  # O Instagram não fornece "shares"
                })

        return render_template('posts.html', posts=post_data)

    except Exception as e:
        return f"Erro ao obter posts: {e}"


def get_facebook_posts():
    url = f"https://graph.facebook.com/v16.0/{PAGE_ID}/posts"
    params = {
        "fields": "id,message,created_time,likes.summary(true),comments.summary(true),shares,attachments",
        "access_token": ACCESS_TOKEN
    }
    response = requests.get(url, params=params).json()

    # Retorna os dados dos posts
    return response.get("data", [])


def get_instagram_posts():
    url = f"https://graph.facebook.com/v16.0/{INSTAGRAM_ACCOUNT_ID}/media"
    params = {
        "fields": "id,caption,media_type,media_url,timestamp,like_count,comments_count",
        "access_token": ACCESS_TOKEN
    }
    response = requests.get(url, params=params).json()
    return response.get("data", [])

from collections import defaultdict
from datetime import datetime


def group_posts_by_time(posts):
    grouped_posts = defaultdict(list)

    for post in posts:
        # Converter o horário para um formato padronizado
        post_time = datetime.fromisoformat(post["created_time"]).strftime("%Y-%m-%d %H:%M")
        grouped_posts[post_time].append(post)

    return grouped_posts

@app.route('/posts')
def fetch_postss():
    facebook_posts = get_facebook_posts()
    instagram_posts = get_instagram_posts()

    posts = []
    for fb_post in facebook_posts:
        # Verifique se há mídia no post
        media_url = None
        if "attachments" in fb_post:
            attachments = fb_post["attachments"]["data"]
            for attachment in attachments:
                if "media" in attachment and "image" in attachment["media"]:
                    media_url = attachment["media"]["image"].get("src")
                    break

        # Adicione o post processado
        posts.append({
            "id": fb_post["id"],
            "message": fb_post.get("message", "Sem mensagem."),
            "created_time": fb_post["created_time"],
            "likes": fb_post.get("likes", {}).get("summary", {}).get("total_count", 0),
            "comments": fb_post.get("comments", {}).get("summary", {}).get("total_count", 0),
            "shares": fb_post.get("shares", {}).get("count", 0),
            "source": "Facebook",
            "media_url": media_url  # Incluindo a URL de mídia
        })

    for ig_post in instagram_posts:
        posts.append({
            "id": ig_post["id"],
            "message": ig_post.get("caption", "Sem legenda."),
            "created_time": ig_post["timestamp"],
            "likes": ig_post.get("like_count", 0),
            "comments": ig_post.get("comments_count", 0),
            "shares": "N/A",  # Compartilhamentos não se aplicam no Instagram
            "source": "Instagram",
            "media_url": ig_post.get("media_url", None),
        })

    grouped_posts = group_posts_by_time(posts)
    return render_template("posts.html", grouped_posts=grouped_posts)

@app.route('/delete_posts/<post_id>', methods=['POST'])
def delete_posts(post_id):
    source = request.form.get('source')  # Facebook ou Instagram
    if source == "Facebook":
        url = f"https://graph.facebook.com/v16.0/{post_id}"
    elif source == "Instagram":
        url = f"https://graph.facebook.com/v16.0/{post_id}"
    else:
        return {"error": "Fonte não identificada."}, 400

    response = requests.delete(url, params={"access_token": ACCESS_TOKEN})
    if response.status_code == 200:
        return {"message": "Post excluído com sucesso."}
    else:
        return {"error": "Erro ao excluir o post."}, 400

@app.route('/get_comments/<post_id>', methods=['GET'])
@login_required
def get_comments(post_id):
    try:
        # Obter os comentários do post
        comments = graph.get_connections(id=post_id, connection_name='comments')

        # Extrair as informações relevantes dos comentários
        comment_data = []
        for comment in comments.get('data', []):
            comment_data.append({
                'id': comment.get('id', 'N/A'),
                'message': comment.get('message', 'Sem mensagem'),
                'created_time': comment.get('created_time', 'Desconhecido'),
                'from': comment.get('from', {}).get('name', 'Anônimo'),
                'avatar': f"https://graph.facebook.com/{comment['from']['id']}/picture?type=square"
            })

        return {'comments': comment_data}

    except Exception as e:
        return {'error': str(e)}, 500

@app.route('/reply_comment/<comment_id>', methods=['POST'])
@login_required
def reply_comment(comment_id):
    try:
        data = request.get_json()
        message = data.get('message', '')

        if not message:
            flash("A mensagem de resposta não pode estar vazia.", "danger")
            return redirect(url_for('dashboard'))  # Substitua pela rota adequada.

        # Publicar uma resposta ao comentário
        graph.put_comment(object_id=comment_id, message=message)
        flash("Comentário respondido com sucesso!", "success")
    except Exception as e:
        flash(f"Erro ao responder ao comentário: {str(e)}", "danger")

    # Redirecionar para a página de comentários ou outra de sua escolha
    return redirect(url_for('dashboard'))  # Substitua pela rota adequada.

@app.route('/edit_post/<post_id>', methods=['POST'])
@login_required
def edit_post(post_id):
    try:
        data = request.form  # Alterado para capturar dados do formulário HTML
        message = data.get('caption')

        if not message:
            flash("A mensagem não pode estar vazia.", "danger")
            return redirect(url_for('get_posts', post_id=post_id))  # Substitua pela rota da página de edição.

        # Atualizar o post usando a Graph API
        graph.put_object(parent_object=post_id, connection_name='', message=message)
        flash("Post atualizado com sucesso!", "success")
    except Exception as e:
        flash(f"Erro ao atualizar o post: {str(e)}", "danger")

    # Redirecionar para a página de edição ou uma página de listagem
    return redirect(url_for('get_posts', post_id=post_id))  # Substitua pela rota correta.

@app.route('/delete_post/<post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    try:
        # Excluir o post usando a Graph API
        graph.delete_object(id=post_id)
        flash("Post excluído com sucesso!", "success")
        return jsonify({"message": "Post excluído com sucesso!"}), 200
    except Exception as e:
        return jsonify({"message": f"Erro ao excluir o post: {str(e)}"}), 500

# Página de campanhas
@app.route('/campanhas', methods=['GET'])
@login_required
@admin_required
def listar_campanhas():
    try:
        # Obter lista de campanhas
        response = graph.get_connections(id=AD_ACCOUNT_ID, connection_name='campaigns',
                                         fields='id,name,status,objective')
        campanhas = response.get('data', [])

        return render_template('campanhas.html', campanhas=campanhas)

    except Exception as e:
        flash(f"Erro ao listar campanhas: {e}", "danger")
        return redirect(url_for('listar_campanhas'))

@app.route('/campanhas/criar', methods=['POST'])
@login_required
@admin_required
def criar_campanha():
    try:
        # Obter valores do formulário
        nome = request.form.get('nome')
        objetivo = request.form.get('objetivo', 'OUTCOME_TRAFFIC')
        status = request.form.get('status', 'PAUSED')
        orçamento_diario = request.form.get('orcamento_diario', '1000')  # Valor padrão
        data_inicio = request.form.get('data_inicio')
        data_fim = request.form.get('data_fim')
        post_id = request.form.get('post_id')  # ID do post no Facebook

        # Criar parâmetros da campanha
        campanha_params = {
            'name': nome,
            'status': status,
            'objective': objetivo,
            'special_ad_categories': ['NONE'],
            'daily_budget': int(orçamento_diario),  # Em centavos
        }

        # Adicionar datas se fornecidas
        if data_inicio:
            campanha_params['start_time'] = data_inicio + "T00:00:00-0000"
        if data_fim:
            campanha_params['stop_time'] = data_fim + "T23:59:59-0000"

        # Criar campanha
        campanha = graph.put_object(
            parent_object=AD_ACCOUNT_ID,
            connection_name='campaigns',
            **campanha_params
        )

        # Validação da campanha criada
        if not campanha or 'id' not in campanha:
            flash("Erro ao criar campanha: retorno inválido da API", "danger")
            return redirect(url_for('listar_campanhas'))

        # Criar conjunto de anúncios
        ad_set = None  # Inicialize a variável
        ad_set_params = {
            'name': f"{nome} - Conjunto de Anúncios",
            'campaign_id': campanha['id'],
            'daily_budget': int(orçamento_diario),
            'billing_event': 'IMPRESSIONS',
            'optimization_goal': 'REACH',
            'status': 'PAUSED',
            'targeting': json.dumps({
                'geo_locations': {'countries': ['MZ']},
                'age_min': 18,
                'age_max': 65,
            }),
        }

        try:
            ad_set = graph.put_object(
                parent_object=AD_ACCOUNT_ID,
                connection_name='adsets',
                **ad_set_params
            )

            if not ad_set or 'id' not in ad_set:

                return redirect(url_for('listar_campanhas'))
        except Exception as e:

            return redirect(url_for('listar_campanhas'))

        # Criar criativo do anúncio
        ad_creative_params = {
            'name': f"{nome} - Criativo",
            'object_story_id': post_id,  # Post existente no formato PAGE_ID_POST_ID
        }
        ad_creative = graph.put_object(
            parent_object=AD_ACCOUNT_ID,
            connection_name='adcreatives',
            **ad_creative_params
        )

        # Validação do criativo criado
        if not ad_creative or 'id' not in ad_creative:
            flash("Erro ao criar criativo do anúncio: retorno inválido da API", "danger")
            return redirect(url_for('listar_campanhas'))

        # Criar anúncio
        ad_params = {
            'name': f"{nome} - Anúncio",
            'adset_id': ad_set['id'],
            'creative': {'creative_id': ad_creative['id']},
            'status': 'PAUSED',
        }
        graph.put_object(
            parent_object=AD_ACCOUNT_ID,
            connection_name='ads',
            **ad_params
        )

        flash("Campanha e anúncio vinculados ao post com sucesso!", "success")
        return redirect(url_for('listar_campanhas'))

    except Exception as e:
        flash(f"Erro ao criar campanha: {e}", "danger")
        return redirect(url_for('listar_campanhas'))



@app.route('/postsss', methods=['GET'])
@login_required
@admin_required
def obter_posts():
    try:
        # Buscar posts da página
        posts = graph.get_connections(
            id=PAGE_ID,
            connection_name='posts',
            fields='id,message,created_time'
        )

        # Retornar lista de posts
        return jsonify(posts['data'])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Editar campanha
@app.route('/campanhas/editar/<campanha_id>', methods=['POST'])
@login_required
@admin_required
def editar_campanha(campanha_id):
    try:
        nome = request.form.get('nome')
        status = request.form.get('status', 'PAUSED')  # Pode ser 'ACTIVE', 'PAUSED'

        # Atualizar campanha
        params = {
            'name': nome,
            'status': status
        }
        graph.put_object(parent_object=campanha_id, connection_name='', **params)

        flash("Campanha atualizada com sucesso!", "success")
        return redirect(url_for('listar_campanhas'))

    except Exception as e:
        flash(f"Erro ao editar campanha: {e}", "danger")
        return redirect(url_for('listar_campanhas'))

# Excluir campanha
@app.route('/campanhas/excluir/<campanha_id>', methods=['POST'])
@login_required
@admin_required
def excluir_campanha(campanha_id):
    try:
        # Excluir campanha
        graph.delete_object(id=campanha_id)

        flash("Campanha excluída com sucesso!", "success")
        return redirect(url_for('listar_campanhas'))

    except Exception as e:
        flash(f"Erro ao excluir campanha: {e}", "danger")
        return redirect(url_for('listar_campanhas'))

def send_reset_email(usuario):
    token = usuario.reset_token
    msg = Message('Redefinir Senha', sender='storeexecutivo@gmail.com', recipients=[usuario.email])
    msg.body = f'''Para redefinir sua senha, visite o seguinte link:
{url_for('reset_token', token=token, _external=True)}

Se você não solicitou essa mudança, ignore este email.
------------------------------------------------------------
ELECTRO ZONE-2024.
'''
    mail.send(msg)


@app.route('/esqueceu_senha', methods=['GET', 'POST'])
def esqueceu_senha():
    if request.method == 'POST':
        email = request.form.get('email')  # Obtém o email diretamente do formulário HTML
        usuario = User.query.filter_by(email=email).first()
        if usuario:
            token = str(uuid.uuid4())
            usuario.reset_token = token
            usuario.reset_token_expira_em = datetime.utcnow() + timedelta(minutes=15)
            db.session.commit()
            send_reset_email(usuario)  # Certifique-se de que esta função está implementada corretamente
            flash('Um e-mail com instruções para redefinir sua senha foi enviado.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email não encontrado.', 'danger')
    return render_template('esqueceu_senha.html')  # Não precisa passar `form`


@app.route('/reset_token/<token>', methods=['GET', 'POST'])
def reset_token(token):
    usuario = User.query.filter_by(reset_token=token).first_or_404()
    if usuario.reset_token_expira_em < datetime.utcnow():
        flash('O token para redefinição de senha expirou. Por favor, solicite um novo.', 'danger')
        return redirect(url_for('esqueceu_senha'))

    if request.method == 'POST':
        nova_senha = request.form.get('senha')  # Obtém a nova senha diretamente do formulário HTML
        confirmar_senha = request.form.get('confirmar_senha')

        if nova_senha != confirmar_senha:
            flash('As senhas não coincidem. Tente novamente.', 'danger')
        else:
            usuario.set_password(nova_senha)
            usuario.reset_token = None
            usuario.reset_token_expira_em = None
            db.session.commit()
            flash('Sua senha foi atualizada com sucesso!', 'success')
            return redirect(url_for('login'))

    return render_template('reset_token.html', token=token)  # Não precisa passar `form`


if __name__ == '__main__':
    app.run(debug=True)
