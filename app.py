import hashlib
import functools
import os # Para generar el aleatorio
from flask import Flask, render_template, flash, request, redirect, url_for, jsonify, session, send_file, current_app, g
from wtforms import StringField
from flask_wtf import FlaskForm
from db import get_db, close_db
from message import mensajes
#from werkzeug import secure_filename
import yagmail
import utils
import werkzeug
# Para lo de las imágenes:
FOLDER_CARGA = os.path.abspath("resources") # carpeta donde se cargarán las imágenes.
from werkzeug.utils import secure_filename # para obtener el nombre del archivo de forma segura.


app = Flask(__name__)
app.secret_key = os.urandom( 24 )
app.config["FOLDER_CARGA"] = FOLDER_CARGA
# app.config['UPLOAD_FOLDER'] = './Portafolio'

if __name__ == '__main__':
    app.run()


#ESTA FUNCIÓN ES LA QUE LLAMAMOS SI VAMOS A ENTRAR A UNA VISTA QUE REQUIERE LOGIN ACTIVO
def login_required(view):
    @functools.wraps( view )
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect( url_for( 'login' ) )
        return view( **kwargs )
    return wrapped_view

#ESTA FUNCIÓN CARGA EN USER_ID CUÁL ES EL USUARIO LOGUEADO ACTUALMENTE
@app.before_request
def load_logged_in_user():
    user_id = session.get( 'user_id' )
    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
        'SELECT * FROM usuario WHERE id_usuario = ?', (user_id,)
        ).fetchone()


#SI ESCRIBEN INICIO SIMPLEMENTE SE REDIRECCIONA AL A FUNCIÓN RAÍZ
@app.route( '/inicio/' )
@login_required #significa que requiere de login activo
def inicio():

    db = get_db()

    portafolio = db.execute('SELECT path FROM imagen ').fetchall()
    
    return render_template('index.html',portafolio = portafolio)

#LA RAÍZ
@app.route( '/' )
def index():
    if g.user: #acá valido que haya un usuario logueado
        return redirect( url_for( 'inicio' ) )
    return render_template( 'login.html' )#sino vaya al login

#REGISTRAR USUARIO
@app.route( '/registro/', methods=('GET', 'POST') )
def registro():
    if g.user:
        return redirect( url_for( 'inicio' ) )
    try:
        if request.method == 'POST':
            username = request.form['usuario']
            password = request.form['clave']
            email = request.form['correo']
            repitaclave = request.form['repitaclave']
            error = None
            db = get_db()
            
            if not utils.isUsernameValid( username ):
                error = "El usuario debe ser alfanumerico o incluir solo '.','_','-'"
                flash( error )
                return render_template( 'registro.html' )

            if not utils.isPasswordValid( password ):
                error = 'La contraseña debe contenir al menos una minúscula, una mayúscula, un número y 8 caracteres'
                flash( error )
                return render_template( 'registro.html' )

            if not utils.isEmailValid( email ):
                error = 'Correo invalido'
                flash( error )
                return render_template( 'registro.html' )

            if db.execute( 'SELECT id_usuario FROM usuario WHERE email = ?', (email,)).fetchone() is not None:
                error = "El correo {} ya existe".format( email )
                flash( error )
                return render_template( 'registro.html' )

            oculta = str(hashlib.sha256(password.encode()).hexdigest())

            db.execute('INSERT INTO usuario (nombre_usuario, email, password,estado) VALUES (?,?,?,0)',(username, email, oculta))
            db.commit()

            #vamos a crear el link de activación
            llave = hashlib.sha256(email.encode())
            enlace = 'http://127.0.0.1:5000/activacion/'+llave.hexdigest()
            yag = yagmail.SMTP('amadov@uninorte.edu.co', 'uninorte1234') #modificar con tu informacion personal
            yag.send(to=email, subject='Activa tu cuenta - GRUPO F UNINORTE',contents='Hola! Puedes activar tu cuenta dando clic en el siguiente enlace: '+enlace)
            flash( 'Revisa tu correo para activar tu cuenta' )
            return render_template( 'login.html' )
        return render_template( 'registro.html' )
    except:
        return render_template( 'registro.html' )

#LOGIN
@app.route( '/login/', methods=('GET', 'POST') )
def login():
    try:
        if g.user:
            return redirect( url_for( 'inicio' ) )
        if request.method == 'POST':
            db = get_db()
            error = None
            username = request.form['usuario']
            password = request.form['clave']

            if not username:
                error = 'Debes ingresar el usuario'
                flash( error )
                return render_template( 'login.html' )

            if not password:
                error = 'Contraseña requerida'
                flash( error )
                return render_template( 'login.html' )

            oculta = str(hashlib.sha256(password.encode()).hexdigest())
            user = db.execute('SELECT * FROM usuario WHERE nombre_usuario = ? AND password = ?', (username, oculta)).fetchone()

            if user is None:
                error = 'Usuario o contraseña inválidos'
                flash( error )
                return render_template( 'login.html' )
            else:
                session.clear()
                session['user_id'] = user[0]
                return redirect( url_for( 'inicio' ) )
            
        return render_template( 'login.html' )
    except:
        return render_template( 'login.html' )

#cerrar sesión
@app.route( '/logout/' )
def logout():
    session.clear()
    return redirect( url_for( 'login' ) )

#RECUPERAR CLAVE
@app.route( '/recuperarClave/', methods=('GET', 'POST') )
def recuperar():
    if g.user:
        return redirect( url_for( 'inicio' ) )
    try:
        if request.method == 'POST':
            email = request.form['correo']
            error = None
            db = get_db()

            if not utils.isEmailValid( email ):
                error = 'Correo invalido'
                flash( error )
                return render_template( 'recuperarclave.html' )

            if db.execute( 'SELECT id_usuario FROM usuario WHERE email = ?', (email,) ).fetchone() is None:
                error = f"Lo sentimos. El correo {email} no existe entre nuestros usuarios registrados."
                flash( error )
                return render_template( 'recuperarclave.html' )

            clave = db.execute( 'SELECT password FROM usuario WHERE email = ?', (email,) ).fetchone()

            #vamos a crear el link de activación
            enlace = 'http://127.0.0.1:5000/recuperacion/'+clave
            yag = yagmail.SMTP('amadov@uninorte.edu.co', 'uninorte1234') #modificar con tu informacion personal
            yag.send(to=email, subject='Activa tu cuenta - GRUPO F UNINORTE',contents='Hola! Puedes actualizar tu clave dando clic en el siguiente enlace: '+enlace)
            flash('Revisa tu correo para recuperar tu clave')
            return render_template( 'login.html' )
        return render_template( 'recuperarclave.html' )
    except:
        return render_template( 'recuperarclave.html' )

#RUTA PARA ACTIVAR USUARIOS
@app.route('/activacion/<string:llave>')
def activemos(llave):
    db = get_db()
    #buscamos todos los email de los usuario que no han activado su cuenta
    user = db.execute('SELECT email FROM usuario WHERE estado = 0').fetchall()
    for correo in user:
        v1 = hashlib.sha256(str(correo[0]).encode())
        v2 = v1.hexdigest()
        if  v2 == llave:
            db.execute('UPDATE usuario SET estado = 1 WHERE email = ?',[str(correo[0])])
            db.commit()
            return 'Usuario activado!'
            break
    return 'Lo sentimos. Este enlace no está habilitado'
    
#CREAR O ACTUALIZAR IMAGEN
@app.route('/crear/', methods=['GET','POST'])
@login_required #significa que requiere de login activo
def crear():
    
    try:
        path = ''
        if request.method == 'POST':
            nombre = request.form['nombre']
            descripcion = request.form['descripcion']
            
            archivo=request.files["archivo"]
            
            #return render_template( 'crear_actualizar.html' )
            
            error = None
            
            db = get_db()

            if len(nombre)>20:
                error = 'Error. Nombre muy largo.'
                flash( error )
                return render_template( 'crear_actualizar.html' )

            if len(descripcion)>60:
                error = 'Error. Descripción muy larga.'
                flash( error )
                return render_template( 'crear_actualizar.html' )

            if archivo is None:
                error = 'Error. No hay archivo.'
                flash( error )
                return render_template( 'crear_actualizar.html' )

            filename = secure_filename(archivo.filename)   
            path = os.path.join(app.config["FOLDER_CARGA"], filename) # ruta de la imagen, incluyendola.

            if db.execute( 'SELECT id_imagen FROM imagen WHERE path = ?', (str(path),) ).fetchone() is not None:
                error = "Lo sentimos. Ese archivo ya se subió para otra imagen."
                flash( error )
                return render_template( 'crear_actualizar.html' )

            archivo.save(path)      
            user_id = session.get( 'user_id' )
            publica = imgpublica=request.form['imgpublica']
            pub = str(0)
            if str(publica) == 'on':
                pub = str(1)
            
            db.execute('INSERT INTO imagen (id_usuario, nombre_imagen, descripcion,publica,path) VALUES (?,?,?,?,?)',((user_id),nombre,descripcion,pub,str(path)))
            db.commit()
            flash('La imagen se cargó exitosamente')  
                                   
            
            #return render_template( 'crear_actualizar.html' )
        return render_template( 'crear_actualizar.html', path=path)
    except:
        return render_template( 'crear_actualizar.html' )





"""
#VER IMAGEN DEL PORTAFOLIO
@app.route('/visualizar/') # URL
@login_required #significa que requiere de login activo
#@app.before_request
def visualizar():
    return render_template('visualizar.html')
   """ 