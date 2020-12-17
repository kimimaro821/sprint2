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
def inicio():
   try:
      if request.method == 'POST':
         usuario = request.form['usuario']
         clave = request.form['clave']
         email = request.form['email']
         if utils.isEmailValid(email):         
            if utils.isUsernameValid(usuario):            
               yag = yagmail.SMTP('penarandah@uninorte.edu.co','TuClavePersonal')
               yag.send(to=email,subject='Validar cuenta',
               contents='Revisa tur correo para activar tu cuenta.') 
               return "Correo enviado a:  " + email
            else:
               return "Usuario no valido.  " + usuario
         else:
            return "Correo no valido.  " + usuario
      else:
         return 'Entra con GET' 
   except:
      return render_template('login.html')

@app.route('/login/')
def login():
    return render_template('login.html')

@app.route('/registro/')
def login():
    return render_template('registro.html')

@app.route('/recuperarClave/')
def recuperarClave():
    return render_template('recuperarclave.html')
