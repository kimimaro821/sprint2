import os # Para generar el aleatorio
from flask import Flask, render_template, request, redirect, url_for, flash
from wtforms import StringField
from flask_wtf import FlaskForm
import yagmail
import utils

app = Flask(__name__)

SECRET_KEY = os.urandom(32) # Para generar la llave aleatoria
app.config['SECRET_KEY'] = SECRET_KEY

@app.route('/', methods=['GET','POST'])
def inicio(): #SI NO HAY UN LOGIN VÁLIDO ENTONCES NO ENTRA A INICIO Y SE REDIRECCIONA A LOGIN CON UN MENSAJE
    try:
        if request.method == 'POST':
            usuario = request.form['usuario']
            clave = request.form['clave']
            if utils.isUsernameValid(usuario):  
                if (clave):          
                    return render_template('index.html', mensajito = "Logueado correctamente")
                else:
                    return render_template('login.html', mensajito = "La clave no era válida... revise!")
            else:
                return render_template('login.html', mensajito = "El usuario no era válido... revise!")
        else:
            return render_template('login.html',mensajito="Parece que intentó entrar a inicio por GET... no se vale! INICIE SESIÓN PRIMERO")
    except:
        return render_template('login.html', mensajito ="Ojo! No puede entrar sin loguearse.")

@app.route('/login/', methods=['GET','POST'])
def logueo():
    return render_template('login.html')

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
    