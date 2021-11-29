from bson import ObjectId
from pymongo import MongoClient, DESCENDING
from user import User
from werkzeug.security import generate_password_hash
from datetime import datetime
from Encryption import generate_rsa_keys, generate_aes_key, encrypt_rsa, decrypt_rsa, rsa_ds_signer, sha_md_create, rsa_ds_verifier

client = MongoClient(
    "mongodb+srv://test_1:Test1@chatapp.tgi3t.mongodb.net/Chat_DB?retryWrites=true&w=majority",
    tlsAllowInvalidCertificates=True)

chat_db = client.get_database("Chat_DB")
users_collection = chat_db.get_collection("users")
rooms_collection = chat_db.get_collection("rooms")
room_members_collection = chat_db.get_collection("room_members")
messages_collection = chat_db.get_collection("messages")
private_key_collection = chat_db.get_collection("private_key")
hash_table_collection = chat_db.get_collection("hash_table")

hash_table_public_key, hash_table_private_key = generate_rsa_keys()


def save_user(username, email, password):
    password_hash = generate_password_hash(password)
    # RSA key gen
    rsa_pub_key, rsa_priv_key = generate_rsa_keys()
    print(type(rsa_pub_key), flush=True)
    add_to_hash_table(username, rsa_pub_key)
    save_priv_key(username, rsa_priv_key)
    users_collection.insert_one(
        {'_id': username, 'email': email, 'password': password_hash, 'rsa_pub_key': rsa_pub_key})


def get_user(username):
    user_data = users_collection.find_one({'_id': username})
    return User(user_data['_id'], user_data['email'], user_data['password'],
                user_data['rsa_pub_key']) if user_data else None


def save_room(room_name, created_by):
    # aes key gen
    aes_key = generate_aes_key()
    print(created_by.rsaPubKey)
    print(type(created_by.rsaPubKey))
    room_aes_key_encrypted = encrypt_rsa(aes_key, created_by.rsaPubKey)
    room_id = rooms_collection.insert_one(
        {'name': room_name, 'created_by': created_by.username, 'creator_pub_key': created_by.rsaPubKey,
         'room_aes_key': room_aes_key_encrypted, 'created_at': datetime.now()}).inserted_id
    add_room_member(room_id, room_name, created_by,
                    created_by, is_room_admin=True)
    return room_id


def update_room(room_id, room_name):
    rooms_collection.update_one({'_id': ObjectId(room_id)}, {
        '$set': {'name': room_name}})
    room_members_collection.update_many({'_id.room_id': ObjectId(room_id)}, {
        '$set': {'room_name': room_name}})


def add_room_member(room_id, room_name, member, added_by, is_room_admin=False):
    user = get_user(member.username)
    creator = get_user(added_by.username)
    # check with hash table to be done
    if (user.rsaPubKey):
        room = get_room(room_id)
        aes_key = decrypt_rsa(room['room_aes_key'], get_priv_key(creator))
        room_aes_key = encrypt_rsa(aes_key, user.rsaPubKey)
        # create dsa sign
        aes_key_sign = rsa_ds_signer(aes_key, get_priv_key(creator))
        room_members_collection.insert_one({'_id': {'room_id': ObjectId(room_id), 'username': member.username},
                                            'room_name': room_name,
                                            'room_aes_key': room_aes_key,
                                            'created_dsa': aes_key_sign,
                                            'added_by': added_by.username, 'added_at': datetime.now(),
                                            'is_room_admin': is_room_admin})


def add_room_members(room_id, room_name, usernames, added_by):
    for user in usernames:
        member = get_user(user)
        # check with hash table
        print(get_and_verify_pub_key_sign_from_hash_table(
            added_by.username, added_by.rsaPubKey), flush=True)
        if (member.rsaPubKey):
            room = get_room(room_id)
            aes_key = decrypt_rsa(room['room_aes_key'], get_priv_key(added_by))
            room_aes_key = encrypt_rsa(aes_key, member.rsaPubKey)
            # create dsa sign
            aes_key_sign = rsa_ds_signer(aes_key, get_priv_key(added_by))
            room_members_collection.insert_one({'_id': {'room_id': ObjectId(room_id), 'username': member.username},
                                                'room_name': room_name,
                                                'room_aes_key': room_aes_key,
                                                'created_dsa': aes_key_sign,
                                                'added_by': added_by.username, 'added_at': datetime.now(),
                                                'is_room_admin': False})
    # room_members_collection.insert_many([{'_id': {'room_id': ObjectId(room_id), 'username': username},
    #                                       'room_name': room_name,
    #                                       'added_by': added_by.username, 'added_at': datetime.now(),
    #                                       } for username in usernames])


def remove_room_members(room_id, usernames):
    room_members_collection.delete_many(
        {'_id': {'$in': [{'room_id': ObjectId(room_id), 'username': username} for username in usernames]}})
    reset_room_aes_key(room_id)


def save_priv_key(user, priv_key):
    private_key_collection.insert_one(
        {'_id': user, 'priv_key': priv_key})


def get_priv_key(user):
    return private_key_collection.find_one({'_id': user.username})['priv_key']


def add_to_hash_table(username, rsa_pub_key):
    hash_table_collection.insert_one(
        {'_id': username, 'hash_pub_key': rsa_ds_signer(rsa_pub_key, hash_table_private_key)})


def get_and_verify_pub_key_sign_from_hash_table(username, client_side_pub_key):
    signature = hash_table_collection.find_one({'_id': username})[
        'hash_pub_key']
    return rsa_ds_verifier(client_side_pub_key, signature, hash_table_public_key)


def get_room(room_id):
    return rooms_collection.find_one({'_id': ObjectId(room_id)})


def get_room_members(room_id):
    return list(room_members_collection.find({'_id.room_id': ObjectId(room_id)}))


def get_rooms_for_user(username):
    return list(room_members_collection.find({'_id.username': username}))


def is_room_member(room_id, username):
    return room_members_collection.count_documents({'_id': {'room_id': ObjectId(room_id), 'username': username}})


def is_room_admin(room_id, username):
    return room_members_collection.count_documents(
        {'_id': {'room_id': ObjectId(room_id), 'username': username}, 'is_room_admin': True})


def save_message(room_id, text, sender):
    messages_collection.insert_one(
        {'room_id': room_id, 'text': text, 'sender': sender, 'created_at': datetime.now()})


MESSAGE_FETCH_LIMIT = 3


def get_messages(room_id, page=0):
    offset = page * MESSAGE_FETCH_LIMIT
    messages = list(
        messages_collection.find({'room_id': room_id}).sort('_id', DESCENDING).limit(MESSAGE_FETCH_LIMIT).skip(offset))
    for message in messages:
        message['created_at'] = message['created_at'].strftime('%d %b, %H:%M')
    return messages[::-1]


def reset_room_aes_key(room_id):
    room = get_room(room_id)
    aes_key = generate_aes_key()
    room_members = get_room_members(room_id)
    for member in room_members:
        if member['is_room_admin']:
            admin = get_user(member['_id']['username'])
            room_aes_key_enc = encrypt_rsa(aes_key, admin.rsaPubKey)
            rooms_collection.update_one({'_id': ObjectId(room_id)}, {
                '$set': {'room_aes_key': room_aes_key_enc}})
            for user in room_members:
                room_aes_key, aes_key_sign = create_user_aes_key(
                    room_aes_key_enc, admin, user)
                room_members_collection.update_one({'_id.room_id': ObjectId(room_id), '_id.username': user['_id']['username']}, {
                    '$set': {'room_aes_key': room_aes_key, 'created_dsa': aes_key_sign}})
        print('databse sucess', flush=True)


def create_user_aes_key(enc_aes_key, creator, member):
    member = get_user(member['_id']['username'])
    aes_key = decrypt_rsa(enc_aes_key, get_priv_key(creator))
    user_enc_aes_key = encrypt_rsa(aes_key, member.rsaPubKey)
    aes_key_sign = rsa_ds_signer(aes_key, get_priv_key(creator))
    print('user_Aeskey created', flush=True)
    return user_enc_aes_key, aes_key_sign
