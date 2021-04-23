from flask import Flask, render_template,flash,redirect,url_for,session,logging,request
from flask_mysqldb import MySQL
from wtforms import Form, TextAreaField,StringField, PasswordField,validators
from passlib.hash import sha256_crypt
from functools import wraps
from flask_wtf import Form, RecaptchaField
from flask import Flask, render_template, request
from authlib.integrations.flask_client import OAuth


#Kullanıcı giriş decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu sayfayı görüntüleyebilmek için lütfen giriş yapınız..","danger")
            return redirect(url_for("login"))
    return decorated_function

class RegisterForm(Form):
    name = StringField("Ad Soyad ",validators = [validators.Length(min=4,max=25),validators.DataRequired(message="Lütfen ad soyad giriniz")])
    username = StringField("Kullanıcı Adı",validators = [validators.Length(min=5,max=25),validators.DataRequired(message="Lütfen bir kullanıcı adı giriniz")])
    email = StringField("E-Mail Adresi ",validators = [validators.Email(message="Lütfen Geçerli bir Email adresi giriniz")])
    password = PasswordField("Parola",validators = [validators.DataRequired(message="Lütfen bir parola belirleyiniz"), validators.EqualTo(fieldname="confirm",message="Parolanız uyuşmamaktadır")])
    confirm = PasswordField("Parola Doğrula")
    
app = Flask(__name__)
app.config["SECRET_KEY"] = "ybblog"
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "ybblog"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

app.config["RECAPTCHA_USE_SSL"]= False
app.config["RECAPTCHA_PUBLIC_KEY"] = '6LeG6q4aAAAAAIniTfq2w4hJMrc3u5BSzel-vjkc'
app.config["RECAPTCHA_PRIVATE_KEY"] = '6LeG6q4aAAAAALooHXLrdCzZrzJvBwgNJJfDZYFx'
app.config['RECAPTCHA_OPTIONS']= {'theme':'black'}

mysql = MySQL(app)
oauth = OAuth(app)
google = oauth.register( 
    name='google',
    client_id= '1025692296284-qmess7j49rtphb20sl4oh1shc2pk4age.apps.googleusercontent.com',
    client_secret= '8zg46I8spSsTS4T9m1vw7Kyo',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)

class LoginForm(Form):
    username = StringField("Kullanıcı adı",validators=[validators.length(min=1, max= 50),validators.DataRequired(message="Lütfen kullanıcı adını giriniz")])
    password = PasswordField("Parola",validators=[validators.length(min=1, max= 50),validators.DataRequired(message="Lütfen parola giriniz")])
    recaptcha = RecaptchaField()

@app.route("/")
def index():
    email = dict(session).get('email',None)
    return render_template("index.html")

@app.route("/about")
@login_required
def about():
    return render_template("about.html")

@app.route("/articles")
@login_required
def article():
    return render_template("articles.html")
    
@app.route("/articles/ishukuku")
@login_required
def ishukuku():
    return render_template("ishukuku.html")

@app.route("/articles/ticarethukuku")
@login_required
def ticarethukuku():
    return render_template("ticarethukuku.html")

@app.route("/articles/internethukuku")
@login_required
def internethukuku():
    return render_template("internethukuku.html")

@app.route("/articles/cezahukuku")
@login_required
def cezahukuku():
    return render_template("cezahukuku.html")

@app.route("/articles/icraiflashukuku")
@login_required
def icrahukuku():
    return render_template("icraiflashukuku.html")

@app.route("/articles/borclarhukuku")
@login_required
def borclarhukuku():
    return render_template("borclarhukuku.html")

@app.route("/articles/anayasahukuku")
@login_required
def anayasahukuku():
    return render_template("anayasahukuku.html")

@app.route("/satinal")
@login_required
def satinal():
    return render_template("satinal.html")

@app.route("/forum",methods =["GET","POST"])
@login_required
def forum():
    form = forum(request.form)
    if request.method == "POST" and form.validate():
        email = form.email.data
        yazi = form.yazi.data

        cursor = mysql.connection.cursor()

        sorgu = "Insert into forum(email,yazi) VALUES(%s,%s)"
        cursor.execute(sorgu,(email,yazi))

        mysql.connection.commit()
        cursor.close()
        return redirect(url_for("forum"))
    return render_template("forum.html",form = form)

@app.route("/forum")
@login_required
def verial():
    cursor = mysql.connection.cursor()
    sorgu = "Select * From forum"
    result = cursor.execute(sorgu,)
    if result > 0:
        forum = cursor.fetchall()
        return render_template("forum.html", forum = forum)
    else:
        return render_template("forum.html")

    

class forum(Form):
    email = StringField("email", validators=[validators.length(min=10, max= 50)])
    yazi = TextAreaField("yazi", validators= [validators.length(min=10)])
    
#Kayıt olma
@app.route("/register",methods = ["GET","POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)

        cursor = mysql.connection.cursor()
        
        cursor.execute('''Insert into users (name,email,username,password) VALUES(%s,%s,%s,%s)''',(name,email,username,password))
        mysql.connection.commit()

        cursor.close()

        flash("Başarıyla kayıt oldunuz..","success")
        return redirect(url_for("login"))

    else:

        return render_template("register.html", form = form)


#login işlemi

@app.route("/login", methods = ["GET","POST"])
def login():
    
    form = LoginForm(request.form)
    if request.method == "POST":
        username = form.username.data
        password_entered = form.password.data 

        cursor = mysql.connection.cursor()
        sorgu = "Select * from users where username = %s"

        result = cursor.execute(sorgu,(username,))
        

        if result > 0:
            data = cursor.fetchone()
            real_password = data["password"]

            if sha256_crypt.verify(password_entered,real_password):
                flash("Başarıyla giriş yaptınız..","success")

                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("index"))

            else:
                flash("Parolanızı yanlış girdiniz..","danger")
                return redirect(url_for("login"))
        else:
            flash("Böyle bir kullanıcı bulunmuyor..","danger")
            return redirect(url_for("login"))
        
    return render_template("login.html", form = form)

@app.route("/googleGetLogin", methods = ["GET","POST"])
def googleGetLogin():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/googlePostLogin", methods = ["GET","POST"])
def googlePostLogin():
    flash("Başarıyla giriş yaptınız..","success")
    session["logged_in"] = True

    name = "??"
    username = "??"
    email = "??"
    password = sha256_crypt.encrypt("??")

    cursor = mysql.connection.cursor()
    
    cursor.execute('''Insert into users (name,email,username,password) VALUES(%s,%s,%s,%s)''',(name,email,username,password))
    mysql.connection.commit()

    cursor.close()
   
    return redirect(url_for("index"))

@app.route('/authorize')
def authorize():
    
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    resp.raise_for_status()
    user_info = resp.json()
    # do something with the token and profile
    user = oauth.google.userinfo()
    session['email'] = user_info['email']
    return redirect('/googlePostLogin')

#logout işlemi

@app.route("/logout")
def logout():
    for key in list(session.keys()):
        session.pop(key)
    session.clear()
    flash("Başarıyla Çıkış Yaptınız. İyi Günler Dileriz","success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)