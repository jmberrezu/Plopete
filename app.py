from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import base64
import bcrypt
import psycopg2

app = Flask(__name__)
app.secret_key = '1234'  # Cambia esto a una clave secreta fuerte en producción

# Configuración de la base de datos PostgreSQL
DB_HOST = 'localhost'
DB_NAME = 'plopete'
DB_USER = 'postgres'
DB_PASSWORD = 'matilda13'

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
db = SQLAlchemy(app)

# Registro del filtro personalizado 'b64encode'
app.jinja_env.filters['b64encode'] = base64.b64encode

# Configuración del manejo de inicio de sesión
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# Modelo de usuarios


class User(UserMixin, db.Model):
    __tablename__ = 'users'  # Nuevo nombre de la tabla

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    # Aumentar el tamaño del campo password
    password = db.Column(db.String(255), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)

    # Método para encriptar la contraseña antes de almacenarla en la base de datos
    def set_password(self, password):
        # Generar un salt (valor aleatorio) para fortalecer la encriptación
        salt = bcrypt.gensalt()
        # Encriptar la contraseña y guardar el hash resultante as a base64-encoded string
        self.password = base64.b64encode(bcrypt.hashpw(
            password.encode('utf-8'), salt)).decode('utf-8')

    # Método para verificar la contraseña desencriptada con el hash almacenado
    def check_password(self, password):
        # Convert self.password to bytes if it's not already
        stored_password_bytes = base64.b64decode(self.password.encode('utf-8'))

        # Ensure that the provided password is encoded as bytes
        password_bytes = password.encode('utf-8')

        return bcrypt.checkpw(password_bytes, stored_password_bytes)


def get_current_username():
    return current_user.username if current_user.is_authenticated else None

# Función para conectar a la base de datos


def connect_to_database():
    conn = psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ruta para registrar un nuevo usuario


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_type = request.form['user_type']

        if not all([username, password, user_type]):
            return "Error: Todos los campos son obligatorios."

        new_user = User(username=username, user_type=user_type)
        # Encriptamos la contraseña antes de almacenarla
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash("Usuario " + username + " registrado!", "success")
        return redirect(url_for('login'))

    return render_template('/login/register.html')

# Ruta para iniciar sesión


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        # Verificamos la contraseña encriptada
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash("Credenciales incorrectas. Por favor, inténtalo de nuevo.", "danger")
            return render_template('/login/login.html')

    return render_template('/login/login.html')

# Ruta para cerrar sesión


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Ruta para mostrar la página principal


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')


@app.route('/events')
def events():
    # Connect to the database
    conn = connect_to_database()
    cursor = conn.cursor()

    # Fetch all events from the database
    cursor.execute("SELECT * FROM events")
    events = cursor.fetchall()

    # Close the cursor and database connection
    cursor.close()
    conn.close()

    # Convert the events to a JSON-serializable format
    events_list = []
    for event in events:
        event_data = {
            "id": event[0],
            "name": event[1],
            "organizer": event[2],
            "attendees": event[3],
            "benefiting_company": event[4],
            "event_date": event[5].isoformat(),
            "event_location": event[6],
            "event_photo": base64.b64encode(event[7]).decode('utf-8') if event[7] else None
        }
        events_list.append(event_data)

    # Obtenemos el nombre de usuario actual
    current_username = get_current_username()

    # Pasamos el nombre de usuario actual a la plantilla para mostrarlo si está loggeado
    return render_template('events/events.html', events_data=events_list, current_username=current_username)

# Ruta para mostrar la lista de eventos y el formulario para agregar eventos


@app.route('/events_crud', methods=['GET', 'POST'])
@login_required
def events_crud():
    if current_user.user_type != 'admin':
        flash("Acceso no autorizado. Solo los administradores pueden acceder a esta página.", "danger")
        return render_template('index.html')

    # Fetch user data for rendering in the template
    current_username = get_current_username()

    if request.method == 'POST':
        # Obtener los datos del formulario y guardar el evento en la base de datos
        nombre = request.form['nombre']
        organizador = request.form['organizador']
        asistentes = int(request.form['asistentes'])
        empresa_beneficiada = request.form['empresaBeneficiada']
        fecha_evento = request.form['fechaEvento']
        ubicacion_evento = request.form['ubicacionEvento']
        foto_evento = request.files['fotoEvento'].read()

        if not all([nombre, organizador, asistentes, empresa_beneficiada, fecha_evento, ubicacion_evento, foto_evento]):
            return "Error: Todos los campos son obligatorios."

        conn = connect_to_database()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO events (event_name, organizer, attendees, benefiting_company, event_date, event_location, event_photo) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                       (nombre, organizador, asistentes, empresa_beneficiada, fecha_evento, ubicacion_evento, foto_evento))
        conn.commit()
        cursor.close()
        conn.close()

    # Conectar a la base de datos y obtener todos los eventos
    conn = connect_to_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events")
    eventos = cursor.fetchall()
    cursor.close()
    conn.close()

    # Después de obtener los eventos de la base de datos
    eventos_modificados = []  # Creamos una lista para contener los eventos modificados

    for evento in eventos:
        # Convertir el objeto de fecha a una cadena para la serialización JSON
        evento = list(evento)
        evento[5] = evento[5].isoformat()

        # Convertir el objeto bytes a una cadena base64 (si hay foto)
        if evento[7] is not None:
            evento[7] = base64.b64encode(evento[7]).decode('utf-8')
        else:
            evento[7] = None

        # Agregamos el evento modificado a la nueva lista
        eventos_modificados.append(evento)

    # Pass the current_username to the template
    return render_template('events_crud/events_crud.html', eventos=eventos_modificados, current_username=current_username)

# Ruta para editar un evento


@app.route('/editar_evento/<int:event_id>', methods=['GET', 'POST'])
def editar_evento(event_id):
    if request.method == 'POST':
        # Obtener los datos del formulario y actualizar el evento en la base de datos
        nombre = request.form['nombreEdit']
        organizador = request.form['organizadorEdit']
        asistentes = int(request.form['asistentesEdit'])
        empresa_beneficiada = request.form['empresaBeneficiadaEdit']
        fecha_evento = request.form['fechaEventoEdit']
        ubicacion_evento = request.form['ubicacionEventoEdit']

        # Obtener la foto del evento (si se ha seleccionado una nueva)
        foto_evento = None
        foto_evento_file = request.files['fotoEventoEdit']
        if foto_evento_file and foto_evento_file.filename:
            foto_evento = foto_evento_file.read()

        conn = connect_to_database()
        cursor = conn.cursor()

        # Construir la consulta SQL para actualizar el evento
        if foto_evento:
            cursor.execute(
                "UPDATE events SET event_name = %s, organizer = %s, attendees = %s, benefiting_company = %s, event_date = %s, event_location = %s, event_photo = %s WHERE event_id = %s",
                (nombre, organizador, asistentes, empresa_beneficiada,
                 fecha_evento, ubicacion_evento, foto_evento, event_id)
            )
        else:
            cursor.execute(
                "UPDATE events SET event_name = %s, organizer = %s, attendees = %s, benefiting_company = %s, event_date = %s, event_location = %s WHERE event_id = %s",
                (nombre, organizador, asistentes, empresa_beneficiada,
                 fecha_evento, ubicacion_evento, event_id)
            )

        conn.commit()
        cursor.close()
        conn.close()

        # Después de actualizar el evento, redirigir a la página principal
        return redirect(url_for('events_crud'))

    # Conectar a la base de datos y obtener el evento a editar
    conn = connect_to_database()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events WHERE event_id = %s", (event_id,))
    evento = cursor.fetchone()
    cursor.close()
    conn.close()

    if evento:
        # Convertir el objeto de fecha a una cadena para la serialización JSON
        evento = list(evento)
        evento[5] = evento[5].isoformat()

        # Convertir el objeto bytes a una cadena base64 (si hay foto)
        if evento[7] is not None:
            evento[7] = base64.b64encode(evento[7]).decode('utf-8')

        # Devolver la respuesta JSON usando jsonify
        return jsonify(evento=evento)
    else:
        return jsonify(error='Event not found'), 404

# Ruta para eliminar un evento


@app.route('/eliminar_evento/<int:event_id>')
def eliminar_evento(event_id):
    # Conectar a la base de datos y eliminar el evento
    conn = connect_to_database()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM events WHERE event_id = %s", (event_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return redirect(url_for('events_crud'))

# Ruta para incrementar el contador de asistentes para un evento


@app.route('/increment_attendees/<int:event_id>', methods=['POST'])
@login_required  # Aseguramos que solo usuarios autenticados puedan interactuar con esta ruta
def increment_attendees(event_id):
    conn = connect_to_database()
    cursor = conn.cursor()

    # Fetch the current number of attendees for the event
    cursor.execute(
        "SELECT attendees FROM events WHERE event_id = %s", (event_id,))
    current_attendees = cursor.fetchone()[0]

    # Increment the attendee count and update the database
    new_attendees = current_attendees + 1
    cursor.execute(
        "UPDATE events SET attendees = %s WHERE event_id = %s", (new_attendees, event_id))
    conn.commit()

    cursor.close()
    conn.close()

    # Return the updated attendee count as a response
    return jsonify({'attendees': new_attendees})

# Ruta para decrementar el contador de asistentes para un evento


@app.route('/decrement_attendees/<int:event_id>', methods=['POST'])
def decrement_attendees(event_id):
    conn = connect_to_database()
    cursor = conn.cursor()

    # Fetch the current number of attendees for the event
    cursor.execute(
        "SELECT attendees FROM events WHERE event_id = %s", (event_id,))
    current_attendees = cursor.fetchone()[0]

    # Decrement the attendee count, but ensure it doesn't go below 0
    new_attendees = max(0, current_attendees - 1)

    # Update the database with the new attendee count
    cursor.execute(
        "UPDATE events SET attendees = %s WHERE event_id = %s", (new_attendees, event_id))
    conn.commit()

    cursor.close()
    conn.close()

    # Return the updated attendee count as a response
    return jsonify({'attendees': new_attendees})


if __name__ == '__main__':
    app.run()
