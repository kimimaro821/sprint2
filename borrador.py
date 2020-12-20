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
"""

