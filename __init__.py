import random
from email.header import Header
from email.mime.text import MIMEText
from flask import Flask, request
from datetime import datetime
import re
import smtplib, ssl
import logging
from logging import FileHandler
import pymysql
import pymysql.cursors
from flask_cors import CORS, cross_origin
import SmartCitiScannerWeb.html_email
import math

Log_Format = "%(levelname)s %(asctime)s - %(message)s"

logging.basicConfig(
    filename="logfile.log",
    filemode="a",
    format=Log_Format,
    level=logging.DEBUG)

logger = logging.getLogger('logger')
logger.setLevel(logging.DEBUG)

app = Flask(__name__)

cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

db = pymysql.connect(host='193.168.131.40',
                     user='a0595760_SmariCityScaner',
                     password='bPBfcflW',
                     database='a0595760_SmariCityScaner',
                     cursorclass=pymysql.cursors.DictCursor)


def send_email(to_mail, from_mail, message):  # Функция отправки e-mail

    try:
        rus_letters = "абвгдеёжзийклмнопрстуфхцчшщъьэюя"
        for i in rus_letters:
            if i in to_mail[:to_mail.find("@")]:
                return 0
        email_from = f'{from_mail}@xn-----6kccnbhd7bxaidnbcayje0c.xn--p1ai'
        password = 'mdfgnfgjgjfkf'

        html = html_email.generate_mail(message)

        logger.info(html)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS)

        server = smtplib.SMTP('smtp.xn-----6kccnbhd7bxaidnbcayje0c.xn--p1ai:587')
        server.starttls(context=context)
        server.login(email_from, password)
        msg = MIMEText(html, 'html')
        msg['Subject'] = Header(u'Сканер Умного Города РФ', 'utf-8')
        msg['From'] = 'no-reply@xn-----6kccnbhd7bxaidnbcayje0c.xn--p1ai'

        server.sendmail(email_from, to_mail, msg.as_string())
        logger.info(f'Email successful sent to {to_mail}')
        server.quit()

        return 1

    except Exception as e:
        return 0
        logger.error(e)


def sql_select(request):
    logger.debug('Connection to database')
    try:
        cursor = db.cursor()
        cursor.execute(request)
        result = cursor.fetchall()
        logger.debug('Successful request to database')
        cursor.close()
        return result
    except Exception as e:
        logger.error(e)


def sql_update(request):
    logger.debug('Connection to database')
    try:
        cursor = db.cursor()
        cursor.execute(request)
        db.commit()
        logger.debug('Successful request to database')
        cursor.close()
        return 'OK'
    except Exception as e:
        logger.error(e)


def token_generator():  # Генератор случайного токена пользователя и проверка на его уникальность
    chars = list('abcdefghijklnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    length = int(15)
    token = None
    tokens = sql_select(''f'SELECT token FROM users''')
    logger.info(tokens)
    while (token in list(tokens)) or (not token):
        random.shuffle(chars)
        token = ''.join([random.choice(chars) for x in range(length)])
    return token


def code_generator():  # Генератор 6-значного кода для подтверждения телефона или почты
    chars = list('1234567890')
    length = int(6)
    random.shuffle(chars)
    code = ''.join([random.choice(chars) for x in range(length)])
    return int(code)


@app.route('/')  # Тестовая страница
def test():
    send_email('3vefaaaa@mail.ru', 'no-reply', '666666')
    send_email('mr.lumanavr348@gmail.com', 'no-reply', '666666')
    return 'Hello, World!'


@app.route('/register_user.json/', methods=['POST', 'GET'])  # Регистрация
@cross_origin()
def reg():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']
        company = request.form['company']
        job = request.form['job']
        phone = request.form['phone']
        email = request.form['email']
        token = token_generator()
        logger.info(f'New request from user {login} {token} {password} {company} {job} {phone} {email}')
        info = sql_select(''f'SELECT phone, email FROM users''')
        logger.info(info)
        phone_list = [i['phone'] for i in info]
        email_list = [i['email'] for i in info]
        if phone in phone_list:
            return '{"error": "Этот номер уже используется (004)"}'
        if email in email_list:
            return '{"error": "Этот e-mail уже используется (004)"}'

        try:
            code = code_generator()
            print(code)
            letter = f'Добрый день, {login.split(" ")[1]} {login.split(" ")[2]}!\nДобро пожаловать в ваш новый Умный Город!\nДля продолжения регистрации введите этот код подтверждения: {code}\n\nСпасибо за участие в программе!'
            mail = send_email(email, 'no-reply', letter)
            if mail == 0:
                return '{"error": "Недействительный e-mail {005}"}'
            logger.info(f'New user add [{token}, {email}, {code}]')
            sql_update(
                f"INSERT INTO users (token, login, password, company, job, phone, email, permissions, code) VALUES ('{token}', '{login}', '{password}', '{company}', '{job}', '{phone}', '{email}', 0, '{code}')")
            return '{' + f'"token": "{token}", "permissions": 0, "email": 0' + '}'
        except Exception as e:
            print(e)
            return '{' + f'"error": "Внутреняя ошибка сервера (001) {e}"' + '}'

    elif request.method == 'GET':
        login = request.args.get('login')
        password = request.args.get('password')
        city = request.args.get('city')
        phone = f"8{request.args.get('phone')}"
        email = request.args.get('email')
        if login == None or password == None or city == None or phone == None or email == None:
            return '{"error": "Один или несколько показателей отсутсвуют"}'
        elif len(login.split(' ')) != 3:
            return '{"error": "ФИО должно содержать ровно три слова"}'
        token = token_generator()
        logger.info(f'New request from user {login} {token} {password} {city} {phone} {email}')
        info = sql_select(''f'SELECT phone, email FROM users''')
        logger.info(info)
        phone_list = [i['phone'] for i in info]
        email_list = [i['email'] for i in info]
        if phone in phone_list:
            return '{"error": "Этот номер уже используется (004)"}'
        if email in email_list:
            return '{"error": "Этот e-mail уже используется (004)"}'

        try:
            code = code_generator()
            print(code)
            mail = send_email(email, 'no-reply', code)
            if mail == 0:
                return '{"error": "Недействительный e-mail {005}"}'
            logger.info(f'New user add [{token}, {email}, {code}]')
            sql_update(
                f"INSERT INTO users (token, login, password, city, phone, email, permissions, code) VALUES ('{token}', '{login}', '{password}', '{city}', '{phone}', '{email}', 0, '{code}')")
            return '{' + f'"token": "{token}", "permissions": 0, "email": 0' + '}'
        except Exception as e:
            print(e)
            return '{' + f'"error": "Внутреняя ошибка сервера (001) {e}"' + '}'

    return '{"error": "Внутреняя ошибка сервера (000)"}'


@app.route('/commit_reg.json/')  # Подтверждение почты
@cross_origin()
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
        if len(code) == 0:
            return '{"error": "Не верный код подтверждения (006)"}'
        code_2 = int(code[0]['code'])
        print(f"{code_1}\n{code_2}")
        if code_1 == code_2:
            sql_update(f"UPDATE users SET code='verification' WHERE token='{token}'")
            return 'OK'
        elif code_1 != code_2:
            return '{"error": "Код подтверждения не верный"}'
        else:
            return '{"error": "Не удалось подтвердить подлинность аккаунта (003)"}'


@app.route('/login.json/')  # Вход в аккаунт
@cross_origin()
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
                        if (not (' ' in login)) and (len(login) == 15):
                            login_type = 'token'
                        else:
                            return '{"error": "Некорректный логин"}'

            result = sql_select(
                ''f'SELECT token, permissions FROM users WHERE {login_type}={login}, password={password}, code=`verification`''')
            return '{"token": "' + result[0][0] + '", "permissions":' + result[0][1] + '}'

        except Exception:
            return '{"error": "Внутреняя ошибка сервера"}'
    elif request.method == 'GET':
        login = request.args.get('login')
        password = request.args.get('password')
        try:
            match = re.search(r'\w+[^а-я]@\w+[^а-я]\.\w+[^а-я]', login)
            login_type = 'email'
            if match == None:
                match = re.search(r'\b[\w\-_\d]+\s+\b[\w\-_\d]+\s+\b[\w\-_\d]+', login)
                login_type = 'login'
                if match == None:
                    match = re.search(r'\+7[0-9]{10}', login)
                    login_type = 'phone'
                    if match == None:
                        if (not (' ' in login)) and (len(login) == 15):
                            login_type = 'token'
                        else:
                            return '{"error": "Некорректный логин"}'

            logger.info(f"Вход по {login_type}: {login}")

            result = sql_select(
                f'SELECT token, permissions, code FROM users WHERE `{login_type}`=`{login}` AND `password`={password}')
            if len(result) == 0:
                return '{"error": "Такой аккаунт не найден проверьте правильность ввода данных"}'
            elif result[0]["code"] != 'verification':
                return '{' + f'"token": "{result[0]["token"]}", "permissions":"{result[0]["permissions"]}, "email": 0' + '}'

            elif result[0]["code"] == 'verification':
                return '{' + f'"token": "{result[0]["token"]}", "permissions":"{result[0]["permissions"]}, "email": 1' + '}'


        except Exception:
            return '{"error": "Внутреняя ошибка сервера {001}"}'

    return '{"error": "Внутреняя ошибка сервера {000}"}'



#TODO: СТАНДАРТ МИНСТРОЯ

@app.route('/обратная_связь_с_жителями/')  # Обратная связь с жителями
@cross_origin()
def обратная_связь_с_жителями():
    if request.method == 'GET':
        L1 = int(request.args.get('L1'))
        SL1 = int(request.args.get('SL1'))
        N1 = (L1 / SL1) * 100

        L2 = int(request.args.get('L2'))
        G2 = int(request.args.get('G2'))
        I2 = int(request.args.get('I2'))
        P2 = int(request.args.get('P2'))
        SL2 = int(request.args.get('SL2'))
        SG2 = int(request.args.get('SG2'))
        SI2 = int(request.args.get('SI2'))
        SP2 = int(request.args.get('SP2'))
        N2 = ((L2 + G2 + I2 + P2) / (SL2 + SG2 + SI2 + SP2)) * 100

        L3 = int(request.args.get('L3'))
        SL3 = int(request.args.get('SL3'))
        N3 = (L3 / SL3) * 100

        M4 = int(request.args.get('M4'))
        SM4 = int(request.args.get('SM4'))
        N4 = (M4 / SM4) * 100

        Si = int(request.args.get('Si'))

        M6 = int(request.args.get('M6'))
        V6 = int(request.args.get('V6'))
        SM6 = int(request.args.get('SM6'))
        SV6 = int(request.args.get('SV6'))
        N6 = ((M6 + V6) / (SM6 + SV6)) * 100

        L7 = int(request.args.get('L7'))
        SL7 = int(request.args.get('SL7'))
        N7 = (L7 / SL7) * 100

        E8 = int(request.args.get('E8'))
        SE8 = int(request.args.get('SE8'))
        N8 = (E8 / SE8) * 100

        G9 = int(request.args.get('Si'))
        M9 = int(request.args.get('Si'))
        SG9 = int(request.args.get('Si'))
        SM9 = int(request.args.get('Si'))





    return





if __name__ == '__main__':
    app.run(debug=True)