import sys
from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room
from pymongo.errors import DuplicateKeyError
from datetime import datetime
from bson.json_util import dumps
from Encryption import decrypt_rsa, rsa_ds_verifier
from db import get_user, save_user, save_room, add_room_members, get_rooms_for_user, get_room, is_room_member, \
    get_room_members, is_room_admin, update_room, remove_room_members, save_message, get_messages, get_priv_key

app = Flask(__name__)
app.secret_key = "my_very_secret_key"
socketio = SocketIO(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)


@app.route('/')
def index():
    rooms = []
    if current_user.is_authenticated:
        rooms = get_rooms_for_user(current_user.username)
    return render_template('index.html', rooms=rooms)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    message = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password_input = request.form.get('password')
        user = get_user(username)
        if user and user.check_password(password_input):
            login_user(user)
            session["room_aes_key"] = ""
            return redirect(url_for('index'))
        else:
            message = "failed to login"

    return render_template('login.html', message=message)


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    message = ""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        try:
            save_user(username, email, password)
            session["username"] = username
            session.permanent = True
            return redirect(url_for('login'))
        except DuplicateKeyError:
            message = "User Already Exists!"
    return render_template('signup.html', message=message)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route("/error/<message>")
def error(message):
    return render_template('Error.html', message=message if message else "")


@app.route('/create_room', methods=['GET', 'POST'])
@login_required
def create_room():
    message = ''

    if request.method == 'POST':
        room_name = request.form.get('room_name')
        usernames = [username.strip()
                     for username in request.form.get('members').split(',')]

        if len(room_name) and len(usernames):
            flag = 0
            if current_user.username in usernames:
                usernames.remove(current_user.username)
                message = ''
            for username in usernames:
                if get_user(username):
                    continue
                else:
                    flag = -1
                    message += 'user '+username+' does not exist\n'
            if flag == 0:
                room_id = save_room(room_name, current_user)
                add_room_members(room_id, room_name, usernames,
                                 current_user)
                return redirect(url_for('view_room', room_id=room_id))
        else:
            message = 'Failed To Create Room'
    return render_template('create_room.html', message=message)


@app.route('/room/<room_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_room(room_id):
    room = get_room(room_id)
    if room and is_room_admin(room_id, current_user.username):
        existing_room_members = [member['_id']['username']
                                 for member in get_room_members(room_id)]
        room_members_str = ",".join(existing_room_members)
        message = ""
        if request.method == 'POST':
            room_name = request.form.get('room_name')
            room['name'] = room_name
            update_room(room_id, room_name)

            new_members = [username.strip()
                           for username in request.form.get('members').split(',')]

            members_to_add = list(
                set(new_members) - set(existing_room_members))
            members_to_remove = list(
                set(existing_room_members) - set(new_members))
            if len(members_to_add) >= 1:
                flag = 0
                message = ''
                for username in members_to_add:
                    if get_user(username):
                        continue
                    else:
                        flag = -1
                        message += 'user '+username+' does not exist\n'
            else:
                flag = -1
            if flag != -1:
                add_room_members(room_id, room_name, members_to_add,
                                 current_user)
                message += "Updated Successfully"
            if len(members_to_remove) >= 1:
                remove_room_members(room_id, members_to_remove)
                message += "Updated Successfully"
            room_members_str = ",".join(new_members)
        return render_template('edit_room.html', room=room, room_members_str=room_members_str,
                               message=message)
    else:
        return redirect(url_for('error', message="Admin Access Required"))


# @app.route('/room/<room_id>/reset_key', methods=['POST'])
# @login_required
# def reset_key(room_id):
#     room = get_room(room_id)
#     print('reached to python', flush=True)
#     if room and is_room_admin(room_id, current_user.username):
#         reset_room_aes_key(room_id)
#         print('back to python', flush=True)
#         return redirect(url_for('view_room', room_id=room_id))
#     return redirect(url_for('error', message="Admin Access Required"))


@app.route('/room/<room_id>')
@login_required
def view_room(room_id):
    room = get_room(room_id)
    if room and is_room_member(room_id, current_user.username):
        room_members = get_room_members(room_id)
        messages = get_messages(room_id)
        admin = is_room_admin(room_id, current_user.username)
        return render_template('view_room.html', username=current_user.username, room=room, room_members=room_members,
                               messages=messages, admin=admin)
    else:
        return redirect(url_for('error', message="Room Not Found"))


@app.route('/room/<room_id>/messages/')
@login_required
def get_older_messages(room_id):
    room = get_room(room_id)
    if room and is_room_member(room_id, current_user.username):
        page = int(request.args.get('page', 0))
        messages = get_messages(room_id, page)
        return dumps(messages)
    else:
        return redirect(url_for('error', message="Room Not Found"))


@socketio.on('join room')
def handle_join_room_event(data):
    room_members = get_room_members(data['room'])
    room = get_room(data['room'])
    for member in room_members:
        if member['_id']['username'] == current_user.username:
            room_aes_key = decrypt_rsa(
                member['room_aes_key'], get_priv_key(current_user))
            print('Aes Key Verifier: ', rsa_ds_verifier(
                room_aes_key, member['created_dsa'], room['creator_pub_key']))
            session["room_aes_key"] = room_aes_key
            session.modified = True
            session.permanent = True
    app.logger.info("{} has joined the room {}".format(
        data['username'], data['room']))
    data['room_aes_key'] = session["room_aes_key"].decode('latin-1')
    join_room(data['room'])
    socketio.emit('join_room_announcement', data)


@socketio.on('send_message')
def handle_send_message_event(data):
    app.logger.info("{} has sent the message to the room {}:{}".format(
        data['username'], data['room'], data['message']))
    data['created_at'] = datetime.now().strftime('%d %b, %H:%M')
    save_message(data['room'], data['message'], data['username'])
    socketio.emit('receive_message', data, room=data['room'])


@login_manager.user_loader
def load_user(username):
    return get_user(username)


if __name__ == '__main__':
    socketio.run(app, debug=True)
