from flask import Flask, request
import sqlite3
from datetime import datetime

app = Flask(__name__)

#db = sqlite3.connect('test.db').cursor()

@app.route('/')
def test():
    return 'Hello, World!'

#@app.route('/add_user_data/')
#def add_user_data():  # put application's code here
#    if request.method == 'POST':
#        id = request.form.get('id')
#        town = request.form.get('town')
#        date = datetime.today()
#        db.execute(''f'INSERT INTO results (id, city, date) VALUES {id}, {town}, {date}''')
#        count = int(request.form.get('count'))
#        for i in range(count):
#            category = request.form.get(str(i))
#            count2 = category['count']
#            for j in range(count2):
#                value = category[f'{i}'][f'{j}']
#                db.execute(''f'UPDATE results SET "{i}.{j}"={value} WHERE id={id}''')


if __name__ == '__main__':
    app.run()
