from flask import Flask, render_template, request, jsonify
import facebook as fb
import requests
from flask import Flask, render_template, request, jsonify
import facebook as fb
import requests
import os
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Configurações
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
# Configurações do Flask e SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///facebook_posts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Verifique se a pasta de upload existe, se não, crie
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)

# Token de Acesso da API do Facebook
ACCESS_TOKEN = "EAA6jGHZB8lvkBOZC4XhpotHzfuuWT9OJ4gka0C3Fi5n925ORE32VLZAyCNMP5ifymwy0LzQQZBc6cNyYRbaJdvNTi2TZAgHSn6zw43ecAAYQlzlmmhtvKAGbUvAjK7KspwNnSrbzqSR0FAPTQTtI0myl0SCE4TF7W854lCgWYtqnZBc4ZANC5rvikPz4KHFsgkZD"
ACCESS_TOKEN = "EAA6jGHZB8lvkBOZCtbRVmgINrynWLHN3RrQ60ZAuMPMcJNZBRu6EZAxHJErCp4UBSVLl6qgcAulGPLGca2mugHRI8TwZBpi0lYdKOfcNVwVg9mc4jlK58L3RxZCPmLDX7r1pvqpZAW16JjN54N5iZC8UWDhsEuLZBVe1Mg7eBGqBFLiJPPqMUURsVke5gbhj1Pwr7t6fcmDsK10p0NbKtRuAZDZD"

graph = fb.GraphAPI(ACCESS_TOKEN)


# Modelo de Dados
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


# Banco de dados (no arquivo principal)
from datetime import datetime



class ScheduledPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.String(100), unique=True, nullable=True)
    name = db.Column(db.String(150), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    scheduled_time = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default="PENDING")  # Status: PENDING, POSTED, FAILED

    def __repr__(self):
        return f'<ScheduledPost {self.name}>'

from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    atualizado_em = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    ativo = db.Column(db.Boolean, default=True, nullable=False)
    role = db.Column(db.String(50), default='Admin', nullable=False)  # Exemplos: 'admin', 'usuario', 'moderador'

    def __repr__(self):
        return f'<User {self.nome} ({self.email})>'

    def set_password(self, senha):
        """Hash da senha."""
        self.senha = generate_password_hash(senha)

    def check_password(self, senha):
        """Verifica se a senha corresponde ao hash armazenado."""
        return check_password_hash(self.senha, senha)

# Criar a base de dados
with app.app_context():
    db.create_all()




from apscheduler.schedulers.background import BackgroundScheduler

# Configuração do scheduler
scheduler = BackgroundScheduler()
scheduler.start()


def post_scheduled_posts():
    with app.app_context():  # Configura o contexto do app
        # Busca todos os posts que estão agendados para agora ou antes e não foram postados
        now = datetime.now()
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
            except Exception as e:
                post.status = "FAILED"
                print(f"Erro ao postar: {e}")
            db.session.commit()


# Executa a função a cada minuto
scheduler.add_job(post_scheduled_posts, 'interval', minutes=1)


@app.route('/schedule_post', methods=['GET', 'POST'])
def schedule_post():
    if request.method == 'POST':
        message = request.form.get('message')
        post_name = request.form.get('post_name')
        scheduled_time_str = request.form.get('scheduled_time')

        # Convertendo a data e hora fornecida para um objeto datetime
        scheduled_time = datetime.strptime(scheduled_time_str, "%Y-%m-%dT%H:%M")

        # Criar um novo post agendado
        new_scheduled_post = ScheduledPost(name=post_name, message=message, scheduled_time=scheduled_time)
        db.session.add(new_scheduled_post)
        db.session.commit()

        return jsonify({"message": "Post agendado com sucesso"}), 200

    return render_template('schedule_post.html')


@app.route('/scheduled_posts')
def scheduled_posts():
    posts = ScheduledPost.query.all()
    return render_template('scheduled_posts.html', posts=posts)


# Página Inicialj
@app.route('/')
def index():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)


# Rota para Postar Mensagem
@app.route('/post_message', methods=['POST'])
def post_message():
    message = request.form.get('message')
    post_name = request.form.get('post_name')
    try:
        # Postar mensagem no feed do Facebook
        response = graph.put_object("me", "feed", message=message)

        # Armazenar o ID do post e o nome na base de dados
        new_post = Post(post_id=response['id'], name=post_name)
        db.session.add(new_post)
        db.session.commit()

        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Rota para Postar Foto
# Função para verificar extensão permitida
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Rota para Postar Foto com Nome do Post
@app.route('/post_photo', methods=['POST'])
def post_photo():
    message = request.form.get('message')
    post_name = request.form.get('post_name')
    file = request.files.get('file')

    if not file or file.filename == '':
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        try:
            with open(filepath, "rb") as image:
                response = graph.put_photo(image, message=message)
                post_id = response['post_id']
                # Salvar nome e ID do post na base de dados
                new_post = Post(post_id=post_id, name=post_name)
                db.session.add(new_post)
                db.session.commit()
            os.remove(filepath)
            return jsonify(response), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    return jsonify({"error": "Arquivo não permitido"}), 400


# Rota para Comentar em um Post
@app.route('/comment_post', methods=['POST'])
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
def get_post():
    post_id = request.args.get('post_id')
    try:
        response = graph.get_object(post_id)
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Rota para Obter o Número de Curtidas da Página
@app.route('/get_fan_count', methods=['GET'])
def get_fan_count():
    try:
        url = f"https://graph.facebook.com/me?fields=fan_count&access_token={ACCESS_TOKEN}"
        response = requests.get(url).json()
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Rota para Obter Comentários de um Post
@app.route('/get_comments', methods=['GET'])
def get_comments():
    post_id = request.args.get('post_id')
    try:

        url = f"dd"
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
scheduler.add_job(update_post_metrics, 'interval', minutes=1)


@app.route('/engagement_report')
def engagement_report():
    # Obtenha todos os posts do banco de dados
    posts = Post.query.order_by(Post.likes.desc()).limit(10).all()

    # Limpando dados e garantindo que sejam números inteiros
    post_data = []
    for post in posts:
        likes = post.likes if post.likes is not None else 0
        comments = post.comments if post.comments is not None else 0
        shares = post.shares if post.shares is not None else 0

        # Adicionando ao array para passar ao template
        post_data.append({
            'name': post.name,
            'likes': likes,
            'comments': comments,
            'shares': shares
        })

    # Renderiza o template com a lista corrigida
    return render_template('engagement_report.html', posts=post_data)


@app.route('/select_post_comments', methods=['GET', 'POST'])
def select_post_comments():
    if request.method == 'POST':
        # Obtenha o ID do post selecionado
        post_id = request.form.get('post_id')
        return view_comments(post_id=post_id)

    # Se for uma requisição GET, exiba a lista de posts
    posts = Post.query.all()
    return render_template('select_post.html', posts=posts)


@app.route('/view_comments', methods=['GET'])
def view_comments(post_id=None):
    if not post_id:
        post_id = request.args.get('post_id')
    try:
        comments_data = graph.get_connections(post_id, 'comments')
        comments = comments_data['data']
        return render_template('render_comments.html', comments=comments, post_id=post_id)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/reply_comment', methods=['POST'])
def reply_comment():
    comment_id = request.form.get('comment_id')
    reply_message = request.form.get('reply_message')
    try:
        response = graph.put_object(comment_id, "comments", message=reply_message)
        return jsonify({"message": "Comentário respondido com sucesso!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# Define perguntas frequentes e respostas automáticas
FAQ_ANSWERS = {
    "qual é o horário de atendimento?": "Nosso horário de atendimento é das 9h às 18h, de segunda a sexta.",
    "como posso entrar em contato?": "Você pode entrar em contato conosco pelo telefone (XX) XXXX-XXXX ou por mensagem direta.",
    "onde vocês estão localizados?": "Estamos localizados em [Endereço da Empresa]."
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
scheduler.add_job(auto_reply_to_faqs, 'interval', minutes=1)

