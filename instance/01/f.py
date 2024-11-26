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
graph = fb.GraphAPI(ACCESS_TOKEN)


# Modelo de Dados
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)

    def __repr__(self):
        return f'<Post {self.name}>'



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



# Rota para Obter o Número de Curtidas da Página
@app.route('/get_fan_count', methods=['GET'])
def get_fan_count():
    try:
        url = f"https://graph.facebook.com/me?fields=fan_count&access_token={ACCESS_TOKEN}"
        response = requests.get(url).json()
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400





# Criar a base de dados
with app.app_context():
    db.create_all()







if __name__ == '__main__':
    app.run(debug=True)