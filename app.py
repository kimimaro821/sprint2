import os # Para generar el aleatorio
from flask import Flask, render_template, request, redirect, url_for, flash
from wtforms import StringField
from flask_wtf import FlaskForm
from formularios import FormContactenos
import yagmail
import utils

app = Flask(__name__)

SECRET_KEY = os.urandom(32) # Para generar la llave aleatoria
app.config['SECRET_KEY'] = SECRET_KEY

@app.route('/')
def inicio(): #SI NO HAY UN LOGIN VÁLIDO ENTONCES NO ENTRA A INICIO Y SE REDIRECCIONA A LOGIN CON UN MENSAJE
   try:
      if request.method == 'POST':
         usuario = request.form['usuario']
         clave = request.form['clave']
         email = request.form['email']
         if utils.isEmailValid(email):         
            if utils.isUsernameValid(usuario):  
                if utils.isPasswordValid(clave):          
                    return render_template('index.html', mensajito = "Logueado correctamente")
                else:
                    return render_template('login.html', mensajito = "La clave no era válida... revise!")
            else:
               return render_template('login.html', mensajito = "El usuario no era válido... revise!")
         else:
            return render_template('login.html', mensajito = "El correo no era válido... revise!")
      else:
         return render_template('login.html',mensajito="Parece que intentó entrar a inicio por GET... no se vale!")
   except:
      return render_template('login.html', mensajito ="Ojo! No puede entrar sin loguearse.")

@app.route('/login/')
def login():
    return render_template('login.html')

@app.route('/registro/')
def login():
    return render_template('registro.html')

@app.route('/recuperarClave/')
def recuperarClave():
    return render_template('recuperarclave.html')
