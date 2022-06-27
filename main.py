import os
import threading
from base64 import b64decode, b64encode
from datetime import date
import operator
import random
import string
import hashlib

import configparser
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

app = Flask('app')
CORS(app)

strPublicRSAKey = os.getenv('PUBLICRSAKEY')
strPrivateRSAKey = os.getenv('PRIVATERSAKEY')
if strPublicRSAKey == None or strPrivateRSAKey == None:
  print('No RSA keys found!')
  quit()

encryptor = PKCS1_OAEP.new(RSA.importKey(strPublicRSAKey))
decryptor = PKCS1_OAEP.new(RSA.importKey(strPrivateRSAKey))

def decryptHelper(ciphertext):
  length = RSA.importKey(strPrivateRSAKey).size_in_bytes()
  res = []
  for i in range(0, len(ciphertext), length):
      decrypted_block = decryptor.decrypt(ciphertext[i : i + length])
      res.append(decrypted_block)
  return b"".join(res)


def signup_user(username, email, password):
  if not os.path.isfile('user_accounts/' + username + '.ini'):
    token = ''.join(random.choices(string.ascii_lowercase, k = 10))
    file = configparser.ConfigParser(interpolation=None)
    file['DEFAULT'] = {
      'username': b64encode(encryptor.encrypt(username.encode())),
      'email': b64encode(encryptor.encrypt(email.encode())),
      'password': b64encode(encryptor.encrypt(password.encode()))
    }
    file['SESSION'] = {
      'token': hashlib.sha256(token.encode('utf-8')).hexdigest(),
      'logindate': date.today().strftime("%d/%m/%Y"),
      'rememberme': False
    }
    file['BEST_SCORE_PC'] = {
      'score': 0,
      'resolution': "800x600",
      'difficulty': "easy"
    }
    file['BEST_SCORE_MOBILE'] = {
      'score': 0,
      'resolution': "800x600",
      'difficulty': "easy"
    }
    with open('user_accounts/' + username + '.ini', 'w') as f:
      file.write(f)
    return {"msg": "Signed up successfully", "token": token}
  else:
    return "Signup error: user with same name already exists"

def login_user(username, password, remember_me):
  if os.path.isfile('user_accounts/' + username + '.ini'):
    token = ''.join(random.choices(string.ascii_lowercase, k = 10))
    file = configparser.ConfigParser(interpolation=None)
    file.read('user_accounts/' + username + '.ini')

    if password != decryptHelper(b64decode(file['DEFAULT']['password'][2:-1])).decode():
      return {"msg": "Login error: wrong password"}
    else:
      # TODO: Add login functionality
      today = date.today().strftime("%d/%m/%Y")
      file['SESSION'] = {
        'token': hashlib.sha256(token.encode('utf-8')).hexdigest(),
        'logindate': today,
        'rememberme': remember_me
      }

      with open('user_accounts/' + username + '.ini', 'w') as f:
        file.write(f)
      return {"msg": "Logged in", "token": token}
  else:
    return {"msg": "Login error: user does not exist"}

def login_user_bysession(username, token):
  if os.path.isfile('user_accounts/' + username + '.ini'):
    file = configparser.ConfigParser(interpolation=None)
    file.read('user_accounts/' + username + '.ini')

    if file['SESSION']['token'] == hashlib.sha256(token.encode('utf-8')).hexdigest():
      if file['SESSION'].getboolean('rememberme') == True:
        return {"username": decryptHelper(b64decode(file['DEFAULT']['username'][2:-1])).decode(), "password": decryptHelper(b64decode(file['DEFAULT']['password'][2:-1])).decode(), "msg": "Login: success"}
      elif date.today().strftime("%d/%m/%Y") == file['SESSION']['logindate']:
        return {"username": decryptHelper(b64decode(file['DEFAULT']['username'][2:-1])).decode(), "password": decryptHelper(b64decode(file['DEFAULT']['password'][2:-1])).decode(), "msg": "Login: success"}
      else:
        return {"msg": "Login error: user session expired"}
    else:
      return {"msg": "Login error: user session expired"}
  else:
    return {"msg": "Login error: user does not exist"}

def is_best_score_test(username, score, ismob):
  if os.path.isfile('user_accounts/' + username + '.ini'):
    file = configparser.ConfigParser(interpolation=None)
    file.read('user_accounts/' + username + '.ini')

    if ismob and int(file['BEST_SCORE_MOBILE']['score']) < score:
      return True
    if not ismob and int(file['BEST_SCORE_PC']['score']) < score:
      return True
  else:
    print("User does not exist")
    return False

def get_sorted_usr_byscore(ismob):
  scores_unsorted = []
  filenames = []
  for filename in os.listdir('user_accounts/'):
    if filename.endswith(".ini"):
      file = configparser.ConfigParser(interpolation=None)
      file.read('user_accounts/' + filename)
      if ismob:
        scores_unsorted.append(int(file['BEST_SCORE_MOBILE']['score']))
      else:
        scores_unsorted.append(int(file['BEST_SCORE_PC']['score']))
      filenames.append(filename)

  sorted_indices = []
  for index, element in sorted(enumerate(scores_unsorted), key=operator.itemgetter(1)):
    sorted_indices.append(index)
  
  usernames_sorted = []
  for i in sorted_indices:
    usernames_sorted.append(filenames[i])
  return usernames_sorted


@app.route('/')
def game():
  return """
        <p>Game is on this site:</p>
        <a href="https://jelka33.github.io/hardest-snake-game/">https://jelka33.github.io/hardest-snake-game/</a>
        """

@app.route('/signup-user', methods=['GET', 'POST'])
def signup_user_page():
  data = request.form
  if data['username'] != None and data['username'] != "" and data['password'] != None and data['password'] != "":
    return signup_user(data['username'], data['email'], data['password'])
  else:
    return {"msg": "Signup failed"}

@app.route('/login-user', methods=['GET', 'POST'])
def login_user_page():
  data = request.form

  if data['username'] != None and data['username'] != "" and data['password'] != None and data['password'] != "":
    if 'remember me' in data:
      return login_user(data['username'], data['password'], data['remember me'])
    else:
      return login_user(data['username'], data['password'], False)
  else:
    return {"msg": "Login failed"}

@app.route('/login-user-bysession', methods=['GET', 'POST'])
def login_user_bysession_page():
  data = request.json

  if data['username'] != None and data['username'] != "" and data['token'] != None and data['token'] != "":
    return jsonify(login_user_bysession(data['username'], data['token']))
  else:
    return {"msg": "Login failed"}

@app.route('/get-leaderboard', methods=['GET', 'POST'])
def get_leaderboard_page():
  users_info_pc = {}
  users_info_mobile = {}
  file = configparser.ConfigParser(interpolation=None)

  j = 0
  sorted_usr = list(reversed(get_sorted_usr_byscore(False)))
  for i in sorted_usr:
    file.read('user_accounts/' + i)
    users_info_pc[f"{j}"] = {"rank": j+1, "username": i[:-4], "best-score": file['BEST_SCORE_PC']['score'], "resolution": file['BEST_SCORE_PC']['resolution'], "difficulty": file['BEST_SCORE_PC']['difficulty']}
    j += 1
  
  j = 0
  sorted_usr = list(reversed(get_sorted_usr_byscore(True)))
  for i in sorted_usr:
    file.read('user_accounts/' + i)
    users_info_mobile[f"{j}"] = {"rank": j+1, "username": i[:-4], "best-score": file['BEST_SCORE_MOBILE']['score'], "resolution": file['BEST_SCORE_MOBILE']['resolution'], "difficulty": file['BEST_SCORE_MOBILE']['difficulty']}
    j += 1

  ret = {"numvalues": len(sorted_usr)}
  ret['pc'] = users_info_pc
  ret['mobile'] = users_info_mobile
  return ret

@app.route('/evaluate-score', methods=['GET', 'POST'])
def evaluate_score_page():
  data = request.json

  if os.path.isfile('user_accounts/' + data['username'] + '.ini'):
    if is_best_score_test(data['username'], data['score'], data['ismob']):
      file = configparser.ConfigParser(interpolation=None)
      file.read('user_accounts/' + data['username'] + '.ini')

      if data['ismob']:
        file['BEST_SCORE_MOBILE'] = {
          'score': data['score'],
          'resolution': data['resolution'],
          'difficulty': data['difficulty']
        }
      else:
        file['BEST_SCORE_PC'] = {
          'score': data['score'],
          'resolution': data['resolution'],
          'difficulty': data['difficulty']
        }

      with open('user_accounts/' + data['username'] + '.ini', 'w') as f:
          file.write(f)
      
      return {"msg": "Best score"}
    else:
      return {"msg": "Not best score"}
  else:
    return {"msg": "User does not exist"}

@app.route('/get-userinfo', methods=['GET', 'POST'])
def get_userinfo_page():
  data = request.json

  if data['username'] != None and data['username'] != "" and data['token'] != None and data['token'] != "":
    if os.path.isfile('user_accounts/' + data['username'] + '.ini'):
      file = configparser.ConfigParser(interpolation=None)
      file.read('user_accounts/' + data['username'] + '.ini')
      
      if file['SESSION']['token'] == hashlib.sha256(data['token'].encode('utf-8')).hexdigest():
        return {"msg": "Success", "email": decryptHelper(b64decode(file['DEFAULT']['email'][2:-1])).decode()}
      else:
        return {"msg": "User not authenticated"}
    else:
      return {"msg": "User does not exist"}
  else:
    return {"msg": "Need more informations"}

@app.route('/change-userinfo', methods=['GET', 'POST'])
def change_userinfo_page():
  data = request.json

  if data['username'] != None and data['username'] != "" and data['token'] != None and data['token'] != "":
    if os.path.isfile('user_accounts/' + data['username'] + '.ini'):
      file = configparser.ConfigParser(interpolation=None, allow_no_value=True)
      file.read('user_accounts/' + data['username'] + '.ini')
      
      if file['SESSION']['token'] == hashlib.sha256(data['token'].encode('utf-8')).hexdigest():
        if data['type'] == 'username':
          file['DEFAULT']['username'] = b64encode(encryptor.encrypt(str(data['newusername']).encode()))
          os.rename('user_accounts/' + data['username'] + '.ini', 'user_accounts/' + data['newusername'] + '.ini')

          with open('user_accounts/' + data['username'] + '.ini', 'w') as f:
            file.write(f)
          return {"msg": "Success", "newusername": data['newusername']}
        
        if data['type'] == 'email':
          file['DEFAULT']['email'] = b64encode(encryptor.encrypt(str(data['newemail']).encode()))

          with open('user_accounts/' + data['username'] + '.ini', 'w') as f:
            file.write(f)
          return {"msg": "Success", "newemail": data['newemail']}
        
        if data['type'] == 'password' and data['oldpassword'] == decryptHelper(b64decode(file['DEFAULT']['password'][2:-1])).decode():
          file['DEFAULT']['password'] = b64encode(encryptor.encrypt(str(data['newpassword']).encode()))

          with open('user_accounts/' + data['username'] + '.ini', 'w') as f:
            file.write(f)
          return {"msg": "Success", "newpassword": data['newpassword']}
      else:
        return {"msg": "User not authenticated"}
    else:
      return {"msg": "User does not exist"}
  else:
    return {"msg": "Need more informations"}

app.run(host='0.0.0.0', port=8080)
