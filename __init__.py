import random
from flask import Flask, request
from datetime import datetime
import mysql.connector as mconnect
from getpass import getpass
from mysql.connector import connect, Error
import re
import smtplib, ssl

email_from = 'no-reply@xn-----6kccnbhd7bxaidnbcayje0c.xn--p1ai'
password = 'mdfgnfgjgjfkf'

context = ssl.SSLContext(ssl.PROTOCOL_TLS)

server = smtplib.SMTP('smtp.xn-----6kccnbhd7bxaidnbcayje0c.xn--p1ai', 587)
server.starttls(context=context)
server.login(email_from, password)

app = Flask(__name__)

def create_connection(host, user, password, database): #значением функии create_connection будет подключение к базе
    connection = None
    try:
        connection = mconnect.connect(
            host=host,
            user=user,
            password=password,
            database=database
        )
        print("Connection to MySQL DB successful")
        return connection
    except Error as e:
        print(f"The error '{e}' occurred")

conn = create_connection(
    host="norn.from.sh",
    user="a0595760_SmariCityScaner",
    password="123456789",
    database="a0595760_SmariCityScaner"
)
cur = conn.cursor(buffered=True)

def token_generator():
    chars = list('abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    length = int(15)
    token = None
    cur.execute(''f'SELECT token FROM users''')
    tokens = cur.fetchall()
    print(list(map(lambda x: x[0], tokens)))
    while (token in list(tokens[0])) or (not token):
        random.shuffle(chars)
        token = ''.join([random.choice(chars) for x in range(length)])
    print(f'Token: {token}')
    return token

def code_generator():
    chars = list('1234567890')
    length = int(6)
    random.shuffle(chars)
    code = ''.join([random.choice(chars) for x in range(length)])
    return int(code)

@app.route('/')
def test():
    return 'Hello, World!'

@app.route('/register_user.json/', methods=['POST', 'GET'])
def reg():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        company = request.form.get('company')
        job = request.form.get('job')
        phone = request.form.get('phone')
        email = request.form.get('email')
        token = token_generator()

        cur.execute(''f'SELECT phone, email FROM users''')
        info = cur.fetchall()
        phone_list = [list(i)[0] for i in info]
        email_list = [list(i)[1] for i in info]
        print(f"{phone_list}\n{email_list}")
        if phone in phone_list:
            return '{"error": "Этот номер уже используется (004)"}'
        if email in email_list:
            return '{"error": "Этот e-mail уже используется (004)"}'

        try:
            code = code_generator()
            print(code)
            letter = f'Код подтверждения: {code}'
            server.sendmail(email_from, email, letter.encode('utf-8'))
            server.quit()
            cur.execute(
                f"INSERT INTO users (token, login, password, company, job, phone, email, permissions, code) VALUES ('{token}', '{login}', '{password}', '{company}', '{job}', '{phone}', '{email}', 0, '{code}')")
            conn.commit()
            return '{' + f'"token": {token}, "permissions": 0' + '}'
        except Exception as e:
            print(e)
            return '{"error": "Внутреняя ошибка сервера (001)"}'

    elif request.method == 'GET':
        login = request.args.get('login')
        password = request.args.get('password')
        company = request.args.get('company')
        job = request.args.get('job')
        phone = request.args.get('phone')
        email = request.args.get('email')
        token = token_generator()

        cur.execute(''f'SELECT phone, email FROM users''')
        info = cur.fetchall()
        phone_list = [list(i)[0] for i in info]
        email_list = [list(i)[1] for i in info]
        print(f"{phone_list}\n{email_list}")
        if phone in phone_list:
            return '{"error": "Этот номер уже используется (004)"}'
        if email in email_list:
            return '{"error": "Этот e-mail уже используется (004)"}'

        try:
            code = code_generator()
            print(code)
            letter = f'Код подтверждения: {code}'
            server.sendmail(email_from, email, letter.encode('utf-8'))
            server.quit()
            cur.execute(f"INSERT INTO users (token, login, password, company, job, phone, email, permissions, code) VALUES ('{token}', '{login}', '{password}', '{company}', '{job}', '{phone}', '{email}', 0, '{code}')")
            conn.commit()
            return '{'+f'"token": {token}, "permissions": 0'+'}'
        except Exception as e:
            print(e)
            return '{"error": "Внутреняя ошибка сервера (001)"}'


    return '{"error": "Внутреняя ошибка сервера (000)"}'

@app.route('/commit_reg.json/')
def commit_reg():
    if request.method == 'POST':
        code_1 = request.form.get('code')
        token = request.form.get('token')
        cur.execute(f"SELECT code FROM users WHERE token={token}")
        code_2 = int(cur.fetchall()[0][0])
        if code_1 == code_2:
            cur.execute(""f"UPDATE users SET code='verification' WHERE token={token}""")
            conn.commit()
        else:
            return '{"error": "Не удалось подтвердить подлинность аккаунта (003)"}'

@app.route('/login.json/')
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        try:
            match = re.search(r'\w+[^а-я]@\w+[^а-я]\.\w+[^а-я]', login)
            login_type = 'email'
            if match == None:
                match = re.search(r'\b[\w\-_\d]+\s+\b[\w\-_\d]+\s+\b[\w\-_\d]+', login)
                login_type = 'name'
                if match == None:
                    match = re.search(r'\+7[0-9]{10}', login)
                    login_type = 'phone'
                    if match == None:
                        return '{"error": "Внутреняя ошибка сервера"}'

            cur.execute(''f'SELECT token, permissions FROM users WHERE {login_type}={login}''')
            result = cur.fetchall()
            return '{"token": "'+result[0][0]+'", "permissions":'+result[0][1]+'}'

        except Exception:
            return '{"error": "Внутреняя ошибка сервера"}'

    return '{"error": "Внутреняя ошибка сервера"}'

"""@app.route('/add_user_data/')
def add_user_data():  # put application's code here
    if request.method == 'POST':
        id = request.form.get('id')
        town = request.form.get('town')
        date = datetime.today()
        db.execute(''f'INSERT INTO results (id, city, date) VALUES {id}, {town}, {date}''')
        count = int(request.form.get('count'))
        for i in range(count):
            category = request.form.get(str(i))
            count2 = category['count']
            for j in range(count2):
                value = category[f'{i}'][f'{j}']
                db.execute(''f'UPDATE results SET "{i}.{j}"={value} WHERE id={id}''')
"""




if __name__ == '__main__':
    app.run()
