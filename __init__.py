import random
from email.header import Header
from email.mime.text import MIMEText

from flask import Flask, request
from datetime import datetime
from mysql.connector import connect, Error
import re
import smtplib, ssl
import logging
from logging import FileHandler

logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)
handler = FileHandler('serverlog.log', )
logger.addHandler(handler)

app = Flask(__name__)

def send_email(to_mail, from_mail, message): # Функция отправки e-mail

    email_from = f'{from_mail}@xn-----6kccnbhd7bxaidnbcayje0c.xn--p1ai'
    password = 'mdfgnfgjgjfkf'

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    server = smtplib.SMTP('smtp.xn-----6kccnbhd7bxaidnbcayje0c.xn--p1ai:587')
    server.starttls(context=context)
    server.login(email_from, password)
    msg = MIMEText(message, 'plain', 'utf-8')
    msg['Subject'] = Header(u'Сканер Умного Города РФ', 'utf-8')
    msg['From'] = 'no-reply@xn-----6kccnbhd7bxaidnbcayje0c.xn--p1ai'

    server.sendmail(email_from, to_mail, msg.as_string())
    logger.info(f'Email successful sent to {to_mail}')
    server.quit()

def sql_select(request):
    logger.debug('Connection to database')
    conn = connect(
        host="norn.from.sh",
        user="a0595760_SmariCityScaner",
        password="123456789",
        database="a0595760_SmariCityScaner"
    )
    cur = conn.cursor(buffered=True)
    logger.debug('Successful connect to database')
    cur.execute(request)
    result = cur.fetchall()
    logger.debug('Successful request to database')
    cur.close()
    conn.close()
    logger.debug('Connection to database closed')
    return result

def sql_update(request):
    logger.debug('Connection to database')
    conn = connect(
        host="norn.from.sh",
        user="a0595760_SmariCityScaner",
        password="123456789",
        database="a0595760_SmariCityScaner"
    )
    cur = conn.cursor(buffered=True)
    logger.debug('Successful connect to database')
    cur.execute(request)
    conn.commit()
    logger.debug('Successful request to database')
    cur.close()
    conn.close()
    logger.debug('Connection to database closed')
    return 'OK'

def token_generator(): # Генератор случайного токена пользователя и проверка на его уникальность
    chars = list('abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    length = int(15)
    token = None
    tokens = sql_select(''f'SELECT token FROM users''')
    while (token in list(tokens)) or (not token):
        random.shuffle(chars)
        token = ''.join([random.choice(chars) for x in range(length)])
    return token

def code_generator(): # Генератор 6-значного кода для подтверждения телефона или почты
    chars = list('1234567890')
    length = int(6)
    random.shuffle(chars)
    code = ''.join([random.choice(chars) for x in range(length)])
    return int(code)

@app.route('/') # Тестовая страница
def test():
    send_email('lumanvr@yandex.ru', 'no-reply', 'Hello!')
    send_email('mr.lumanavr348@gmail.com', 'no-reply', 'Hello!')
    return 'Hello, World!'

@app.route('/register_user.json/', methods=['POST', 'GET']) # Регистрация
def reg():

    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        company = request.form.get('company')
        job = request.form.get('job')
        phone = request.form.get('phone')
        email = request.form.get('email')
        token = token_generator()
        logger.info(f'New request from user {login} {token}')
        info = sql_select(''f'SELECT phone, email FROM users''')
        phone_list = [list(i)[0] for i in info]
        email_list = [list(i)[1] for i in info]
        if phone in phone_list:
            return '{"error": "Этот номер уже используется (004)"}'
        if email in email_list:
            return '{"error": "Этот e-mail уже используется (004)"}'

        try:
            code = code_generator()
            print(code)
            letter = f'Добрый день, {login.split(" ")[1]} {login.split(" ")[2]}!\nДобро пожаловать в ваш новый Умный Город!\nДля продолжения регистрации введите этот код подтверждения: {code}\n\nСпасибо за участие в программе!'
            send_email(email, 'no-reply', letter)
            logger.info(f'New user add [{token}, {email}, {code}]')
            sql_update(
                f"INSERT INTO users (token, login, password, company, job, phone, email, permissions, code) VALUES ('{token}', '{login}', '{password}', '{company}', '{job}', '{phone}', '{email}', 0, '{code}')")
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
        logger.info(f'New request from user {login} {token}')
        info = sql_select(''f'SELECT phone, email FROM users''')
        phone_list = [list(i)[0] for i in info]
        email_list = [list(i)[1] for i in info]
        if phone in phone_list:
            return '{"error": "Этот номер уже используется (004)"}'
        if email in email_list:
            return '{"error": "Этот e-mail уже используется (004)"}'

        try:
            code = code_generator()
            print(code)
            letter = f'Добрый день, {login.split(" ")[1]} {login.split(" ")[2]}!\nДобро пожаловать в ваш новый Умный Город!\nДля продолжения регистрации введите этот код подтверждения: {code}\n\nСпасибо за участие в программе!'
            send_email(email, 'no-reply', letter)
            logger.info(f'New user add [{token}, {email}, {code}]')
            sql_update(
                f"INSERT INTO users (token, login, password, company, job, phone, email, permissions, code) VALUES ('{token}', '{login}', '{password}', '{company}', '{job}', '{phone}', '{email}', 0, '{code}')")
            return '{' + f'"token": {token}, "permissions": 0' + '}'
        except Exception as e:
            print(e)
            return '{"error": "Внутреняя ошибка сервера (001)"}'


    return '{"error": "Внутреняя ошибка сервера (000)"}'


@app.route('/commit_reg.json/') # Подтверждение почты
def commit_reg():
    if request.method == 'POST':
        code_1 = int(request.args.get('code'))
        token = request.args.get('token')
        code = sql_select(f"SELECT code FROM users WHERE token='{token}'")
        code_2 = int(code[0][0])
        print(f"{code_1}\n{code_2}")
        if code_1 == code_2:
            sql_update(f"UPDATE users SET code='verification' WHERE token='{token}'")
            return 'OK'
        else:
            return '{"error": "Не удалось подтвердить подлинность аккаунта (003)"}'

    elif request.method == 'GET':
        code_1 = int(request.args.get('code'))
        token = request.args.get('token')
        code = sql_select(f"SELECT code FROM users WHERE token='{token}'")
        code_2 = int(code[0][0])
        print(f"{code_1}\n{code_2}")
        if code_1 == code_2:
            sql_update(f"UPDATE users SET code='verification' WHERE token='{token}'")
            return 'OK'
        else:
            return '{"error": "Не удалось подтвердить подлинность аккаунта (003)"}'


@app.route('/login.json/') # Вход в аккаунт
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

            result = sql_select(''f'SELECT token, permissions FROM users WHERE {login_type}={login}, password={password}, code=`verification`''')
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
