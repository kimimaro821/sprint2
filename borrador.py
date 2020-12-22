import hashlib
import functools
import os # Para generar el aleatorio
from flask import Flask, render_template, flash, request, redirect, url_for, jsonify, session, send_file, current_app, g,send_from_directory
from wtforms import StringField
from flask_wtf import FlaskForm
from db import get_db, close_db
from message import mensajes
#from werkzeug import secure_filename
import yagmail
import utils
import werkzeug
# Para lo de las imágenes:
#FOLDER_CARGA = os.path.abspath("resources") # carpeta donde se cargarán las imágenes.
from werkzeug.utils import secure_filename # para obtener el nombre del archivo de forma segura.


app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = 'foticos'
app.secret_key = os.urandom( 24 )
app.config["paginacion"] = '1'

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

#ESTA FUNCION ES PARA VALIDAR SI PUEDO AVANZAR EN SIGUIENTE O NO
def hay_para_mas_fotos():
    db = get_db()
    filas = 0
    num_publicas = db.execute( 'SELECT path FROM imagen WHERE publica = 1').fetchall()
    for aux in num_publicas:
        filas+=1                
    paginacion_actual = int(session['pagina'])
    if filas>(10*(paginacion_actual)):#miro si alcanzan las fotos para una siguiente página
        return True #significa que 
    return False

#ESTA FUNCIÓN ME IMPRIME EN QUÉ PAGINA DE FOTOS ESTOY PARADO
def estado_paginacion():
    db = get_db()
    filas = 0
    num_publicas = db.execute( 'SELECT path FROM imagen WHERE publica = 1').fetchall()
    for aux in num_publicas:
        filas+=1
    paginacion_actual = int(session['pagina'])
    return f"Portafolio de imágenes públicas - Página {session['pagina']}  de {str(int(filas/10)+1)}"

    
#SI ESCRIBEN INICIO SIMPLEMENTE SE REDIRECCIONA AL A FUNCIÓN RAÍZ
@app.route( '/inicio/' , methods=('GET', 'POST') )
@login_required #significa que requiere de login activo
def inicio():
    num_fotos_portafolio = 10
    try:
        if request.method == 'POST':
            paginacion_actual = int(session['pagina'])
            if "Siguiente" in request.form:
                if hay_para_mas_fotos():#miro si alcanzan las fotos para una siguiente página
                    paginacion_actual+=1
                
            elif "Anterior" in request.form:
                
                if(paginacion_actual>1):
                    paginacion_actual-=1

            session['pagina'] = str(paginacion_actual)
            db = get_db()
            todos_los_path = db.execute('SELECT path, id_imagen FROM imagen WHERE publica =1').fetchall()
            maximo = paginacion_actual*num_fotos_portafolio
            minimo = (paginacion_actual-1)*num_fotos_portafolio
            contador = 0
            portafolio = []
            for path in todos_los_path:
                if contador>=minimo and contador<maximo:
                    
                    portafolio.append(path)
                contador+=1
                if contador>=maximo:
                    break
            flash(estado_paginacion())
            return render_template('index.html',pagina_foto = str(paginacion_actual),portafolio=portafolio)    

        #ESTO ES SI ENTRA POR GET OSEA POR PRIMERA VEZ
        session['pagina'] = '1'
        db = get_db()
        todos_los_path = db.execute('SELECT path, id_imagen FROM imagen WHERE publica =1').fetchall()
        contador = 0
        portafolio = []
        for path in todos_los_path:
            if contador<num_fotos_portafolio:
                
                portafolio.append(path)
            if contador>=num_fotos_portafolio:
                break
            contador+=1
        flash(estado_paginacion())
        return render_template('index.html',pagina_foto = session['pagina'],portafolio=portafolio)    
        
        
    except:
        session['pagina'] = '1'
        db = get_db()
        todos_los_path = db.execute('SELECT path, id_imagen FROM imagen WHERE publica =1').fetchall()
        contador = 0
        portafolio = []
        for path in todos_los_path:
            if contador<num_fotos_portafolio:
                
                portafolio.append(path)
            
            if contador>=num_fotos_portafolio:
                break
            contador+=1
        flash(estado_paginacion())
        return render_template('index.html',pagina_foto = session['pagina'],portafolio=portafolio)    



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
        if request.method == 'POST':
            nombre = request.form['nombre']
            descripcion = request.form['descripcion']
            archivo=request.files["archivo"]
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
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename) # ruta de la imagen, incluyendola.
            
            if db.execute( 'SELECT id_imagen FROM imagen WHERE path = ?', (path,) ).fetchone() is not None:
                error = "Lo sentimos. Ese archivo ya se subió para otra imagen."
                flash( error )
                return render_template( 'crear_actualizar.html' )
            
            archivo.save(path)
            user_id = session.get( 'user_id' )
            publica = request.form['privacidad']
            pub = str(0)
            if str(publica) == 'on':
                pub = str(1)
            
            db.execute('INSERT INTO imagen (id_usuario, nombre_imagen, descripcion,publica,path) VALUES (?,?,?,?,?)',(user_id,nombre,descripcion,pub,'/static/imguser/'+str(filename)))
            db.commit()
            flash('La imagen se cargó exitosamente')  
            return render_template( 'crear_actualizar.html' )
        return render_template( 'crear_actualizar.html')
    except:
        return render_template( 'crear_actualizar.html' )





#VER IMAGEN DEL PORTAFOLIO
@app.route('/visualizar/<int:id>', methods=['GET','POST']) # URL
@login_required #significa que requiere de login activo
def visualizar(id):
    
    if request.method == 'POST':
        if "Descargar" in request.form:
            db = get_db()
            img = db.execute( 'SELECT publica, path FROM imagen WHERE id_imagen = ?' , (id,)).fetchone()
            if img is None:    
                return redirect( url_for( 'inicio' ) )#lo mando a inicio porque la imagen no existe
            if img[0] == 0: #si la imagen es privada debemos validar que el usuario logueado sea el dueño
                if db.execute( 'SELECT publica FROM imagen WHERE id_imagen = ? AND id_usuario = ?' , (id,session.get( 'user_id' ))).fetchone() is None:
                    return redirect( url_for( 'inicio' ) )#lo mando a inicio por tramposo
            return send_from_directory('img.jpg' )#le mando bajar la imagen con el path
    
    db = get_db()
    img = db.execute( 'SELECT path, nombre_imagen, descripcion, publica, id_usuario, id_imagen FROM imagen WHERE id_imagen = ?', (id,)).fetchone()
    if img is None:    
        return redirect( url_for( 'inicio' ) )#lo mando a inicio si la id de la imagen no existe en la base de datos
    
    if img[3] == '0' and img[4] != session.get( 'user_id' ):
        return redirect( url_for( 'inicio' ) )#lo mando a inicio porque la imagen es privada y no es el dueño
    
    path = img[0]
    nombre_imagen = img[1]
    descripcion = img[2]
    publica = img[3]
    id_usuario = img[4]
    id_imagen = img[5]
    propietario = None
    if id_usuario == session.get( 'user_id' ): #miramos si es el dueño de la imagen para darle permisos de ELIMINAR y de ACTUALIZAR
        propietario = "dueño"

    return render_template('visualizar.html', path = path, nombre_imagen = nombre_imagen, descripcion = descripcion, publica = publica, id_usuario = id_usuario,propietario=propietario,id_imagen=id_imagen)
    

@app.route( '/descargar/<int:id>', methods=['GET','POST'])
@login_required
def descargar(id):


    db = get_db()
    img = db.execute( 'SELECT publica, path FROM imagen WHERE id_imagen = ?' , (id,)).fetchone()
    
    if img is None:    
        return redirect( url_for( 'inicio' ) )#lo mando a inicio porque la imagen no existe
    
    if img[0] == 0: #si la imagen es privada debemos validar que el usuario logueado sea el dueño
        if db.execute( 'SELECT publica FROM imagen WHERE id_imagen = ? AND id_usuario = ?' , (id,session.get( 'user_id' ))).fetchone() is None:
            return redirect( url_for( 'inicio' ) )#lo mando a inicio por tramposo

    return send_file( img[1], as_attachment=True )#le mando bajar la imagen con el path



if __name__ == '__main__':
    app.run()

"""
#RUTA PARA RECUPERAR CLAVE
@app.route('/recuperacion/<string:llave>')
def recuperala(llave):
    try:
        db = get_db()
        #buscamos todos los email de los usuario que no han activado su cuenta
        user = db.execute('SELECT email FROM usuario WHERE password = ?', [llave]).fetchone()
        return render_template('recuperacion.html',correo =str(user[0]))
    except:
        return 'Lo sentimos. Este enlace no está habilitado'
"""


#RUTA PARA RECUPERAR CLAVE
@app.route('/nuevaclave/')
def nuevaclave():
   
    try:
        if g.user:
            return redirect( url_for( 'inicio' ) )
        if request.method == 'POST':
            db = get_db()
            error = None
            password = request.form['clave']
            repassword = request.form['repitaclave']

            if not password:
                error = 'Contraseña requerida'
                flash( error )
                return render_template( 'recuperacion.html' )

            if not repassword:
                error = 'Repetir Contraseña requerida'
                flash( error )
                return render_template( 'recuperacion.html' )


            if password != repassword:
                error = 'No coinciden las claves.'
                flash( error )
                return render_template( 'recuperacion.html' )

            if not utils.isPasswordValid( password ):
                error = 'La contraseña debe contenir al menos una minúscula, una mayúscula, un número y 8 caracteres'
                flash( error )
                return render_template( 'recuperacion.html' )

            oculta = str(hashlib.sha256(password.encode()).hexdigest())
            db.execute('UPDATE usuario SET password = ? WHERE email = ?',[oculta])
            db.commit()

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


