import functools
import os # Para generar el aleatorio
from flask import Flask, render_template, flash, request, redirect, url_for, jsonify, session, send_file, current_app, g
#from wtforms import StringField
#from flask_wtf import FlaskForm
from db import get_db, close_db
from message import mensajes
import yagmail
import utils

app = Flask(__name__)
app.secret_key = os.urandom( 24 )

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
        'SELECT * FROM usuario WHERE id = ?', (user_id,)
        ).fetchone()

#SI ESCRIBEN INICIO SIMPLEMENTE SE REDIRECCIONA AL A FUNCIÓN RAÍZ
@app.route( '/inicio/' )
@login_required #significa que requiere de login activo
def inicio():
   return render_template('index.html')

#LA RAÍZ
@app.route( '/' )
def index():
   if g.user: #acá valido que haya un usuario logueado
      return redirect( url_for( '/inicio/' ) )
   return render_template( 'login.html' )#sino vaya al login

#REGISTRAR USUARIO
@app.route( '/registro/', methods=('GET', 'POST') )
def register():
    if g.user:
        return redirect( url_for( '/inicio/' ) )
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

            if password != repitaclave:
                error = 'No coinciden las contraseñas... revise por favor.'
                flash( error )
                return render_template( 'registro.html' )

            if db.execute( 'SELECT id FROM usuario WHERE correo = ?', (email,) ).fetchone() is not None:
                error = 'El correo ya existe'.format( email )
                flash( error )
                return render_template( 'registro.html' )

            db.execute(
                'INSERT INTO usuario (usuario, correo, contraseña) VALUES (?,?,?)',
                (username, email, password)
                )
            db.commit()

            # yag = yagmail.SMTP('micuenta@gmail.com', 'clave') #modificar con tu informacion personal
            # yag.send(to=email, subject='Activa tu cuenta',
            #        contents='Bienvenido, usa este link para activar tu cuenta ')
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
         return redirect( url_for( '/inicio/' ) )
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

         user = db.execute(
               'SELECT * FROM usuario WHERE usuario = ? AND contraseña = ?', (username, password)
            ).fetchone()

         if user is None:
            error = 'Usuario o contraseña inválidos'
         else:
            session.clear()
            session['user_id'] = user[0]
            return redirect( url_for( '/inicio/' ) )
         flash( error )
      return render_template( 'login.html' )
   except:
      return render_template( 'login.html' )

#cerrar sesión
@app.route( '/logout/' )
def logout():
   session.clear()
   return redirect( url_for( 'login' ) )




@app.route('/registro/', methods=['GET','POST'])
def registro():
    try:
        if request.method == 'POST':
            usuario = request.form['usuario']
            clave = request.form['clave']
            repitaclave = request.form['clave']
            email = request.form['correo']
            if utils.isEmailValid(email):         
                if utils.isUsernameValid(usuario):            
                    if (clave):          
                        if clave == repitaclave:
                            #yag = yagmail.SMTP('penarandah@uninorte.edu.co','TuClavePersonal')
                            #yag.send(to=email,subject='Validar cuenta',
                            #contents='Acá va el enlace para activar tu cuenta.') 
                            return render_template('registro.html', mensajito = "Registro exitoso! A su correo debe llegar el link de activación... (IMPORTANTE: ingresar clave del correo en el archivo app.py)")    
                        else:
                            return render_template('registro.html', mensajito = "Las claves no coinciden... revise!")    
                    else:
                        return render_template('registro.html', mensajito = "La clave no era válida... revise!")
                else:
                    return render_template('registro.html', mensajito = "El usuario no era válido... revise!")
            else:
                return render_template('registro.html', mensajito = "El correo no era válido... revise!")
        else:
            return render_template('registro.html')
    except:
        return render_template('registro.html')

@app.route('/recuperarClave/', methods=['GET','POST'])
def recuperarClave():
    try:
        if request.method == 'POST':
            email = request.form['correo']
            if utils.isEmailValid(email):         
                #yag = yagmail.SMTP('penarandah@uninorte.edu.co','TuClavePersonal')
                #yag.send(to=email,subject='Recuperar clave',
                #contents='Recuperando la contraseña. Acá deberíamos enviarte tu clave') 
                return render_template('recuperarclave.html', mensajito = "Recuperación exitosa! A su correo debe llegar la clave... (IMPORTANTE: ingresar clave del correo en el archivo app.py)")                    
            else:
                return render_template('recuperarclave.html', mensajito = "El correo no era válido... revise!")
        else:
            return render_template('recuperarclave.html')
    except:
        return render_template('recuperarclave.html')

@app.route('/crear/', methods=['GET','POST'])
def crear():
    return render_template('crear_actualizar.html')

@app.route('/visualizar/') # URL
def mostrar_foto():
    return render_template('visualizar.html')
    