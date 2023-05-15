######################################################################
##  KRY - Project 2 - Hybrid cryptosystem - RSA and AES encryption  ##
##  Author: Filip Brna, xbrnaf00, 221923                            ##
##  Date: 14.4.2023                                                 ##
######################################################################

# import libraries
import socket
import sys
import os
import hashlib
import secrets
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# localhost
HOST = '127.0.0.1'

# Function to create and store private and public RSA keys of sender and reciever into cert folder
def create_and_store_keys():
    # generation of RSA keys
    keys_sender = RSA.generate(2048)
    keys_reciever = RSA.generate(2048)

    if not os.path.exists('cert'):
        os.makedirs('cert')

    # storing of senders private and public keys
    private_key_send = keys_sender.export_key()
    with open("cert/private_keys_sender.pem", "wb") as f:
        f.write(private_key_send)

    public_key_send = keys_sender.publickey().export_key()
    with open("cert/public_keys_sender.pem", "wb") as f:
        f.write(public_key_send)

    # storing of reciver private and public keys
    private_key_recieve = keys_reciever.export_key()
    with open("cert/private_keys_recieve.pem", "wb") as f:
        f.write(private_key_recieve)

    public_key_recieve = keys_reciever.publickey().export_key()
    with open("cert/public_key_recieve.pem", "wb") as f:
        f.write(public_key_recieve)
    
    return

# Function to encryt data using public key of reciever
def sign_data_publickey(data, public_key):
    n, e = public_key.n, public_key.e
    data_int = int.from_bytes(data, byteorder='big')
    signature = pow(data_int, e, n)
    return signature.to_bytes(256, byteorder='big')

# Function to decrypt cipher data using private key of reciever
def decrypt_data_privatekey(cipher, private_key):
    n, d = private_key.n, private_key.d
    cipher_int = int.from_bytes(cipher, byteorder='big')
    decrypted_cipher = pow(cipher_int, d, n)
    return decrypted_cipher.to_bytes(256, byteorder='big')

# Function to sign padded MD5 hash with senders private key
def sign_data_privatekey(data, private_key):
    n, d = private_key.n, private_key.d
    data_hash = int.from_bytes(data, byteorder='big')
    signature = pow(data_hash, d, n)
    return signature.to_bytes(256, byteorder='big')

# Function to decrypt padded MD5 using public key of sender
def decrypt_data_publickey(signature, public_key):
    n, e = public_key.n, public_key.e
    signature_int = int.from_bytes(signature, byteorder='big')
    decrypted_cipher = pow(signature_int, e, n)
    return decrypted_cipher.to_bytes(256, byteorder='big')


# Function to calculate MD5 hash and add random bytes as padding
def md5_plus_padding(message):
    msg_md5 = hashlib.md5(message.encode())
    print('MD5=', msg_md5.hexdigest())
    hex_string = secrets.token_hex(240) 
    msg_md5_padding = msg_md5.hexdigest()+hex_string
    print('MD5_padding=', msg_md5_padding)

    return bytes.fromhex(msg_md5_padding)

# Function to add random bytes as padding to AES key
def AES_padding(key):    
    padding = secrets.token_bytes(240)
    after_padding = key + padding

    return after_padding

def client(PORT):

    # create a client socket of IPv4, TCP type
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try: 
        client_socket.connect((HOST, PORT))
        print('Successfully connected server')
    except ConnectionRefusedError:
        print('Connection refused')
        sys.exit(1)

    # Load and store RSA keys, public key of reciever
    with open("cert/public_key_recieve.pem", "rb") as f:
        public_key_recieve = RSA.import_key(f.read())

    # Load and store RSA keys, private key of sender
    with open("cert/private_keys_sender.pem", "rb") as f:
        private_key_send = RSA.import_key(f.read())

    # Load and store RSA keys, public key of sender
    with open("cert/public_keys_sender.pem", "rb") as f:
        public_key_send = RSA.import_key(f.read())

    print('RSA_public_key_sender=', public_key_send.export_key().decode())
    print('RSA_private_key_sender=', private_key_send.export_key().decode())
    print('RSA_public_key_receiver=', public_key_recieve.export_key().decode())

    while True:
        # message from input
        message = input('Enter input: ')

        if not message:   # if message is empty
            break

        AES_key = secrets.token_bytes(16); # AES key of 128 bits
        AES_key_padding = AES_padding(AES_key) # AES key with padding
        print('AES_key=', AES_key.hex())
        print('AES_key_padding=', AES_key_padding.hex())


        msg_md5_padding = md5_plus_padding(message) # MD5 hash with padding
        RSA_MD5_hash = sign_data_privatekey(msg_md5_padding, private_key_send) # RSA signature of MD5 hash with padding
        print('RSA_MD5_hash=', RSA_MD5_hash.hex())


        AES_text_input = message.encode() + RSA_MD5_hash; 
        cipher = AES.new(AES_key, AES.MODE_EAX) # AES cipher of message with RSA signature
        ciphertext, tag = cipher.encrypt_and_digest(AES_text_input)
        print('AES_cipher=', ciphertext.hex())

        cipher_key = sign_data_publickey(AES_key_padding, public_key_recieve) # RSA cipher of AES key with padding
        print('RSA_AES_key=', cipher_key.hex())

        packet = ciphertext + cipher.nonce + cipher_key # ciphertext (packet) to send (nonce is used for AES decpryption, can be transmitted in plaintext) 
        print('ciphertext=', packet.hex())

        # send ciphertext (packet) to server
        client_socket.sendall(packet)

        # confirmation of message delivery
        data = (client_socket.recv(1024)).decode()
        if data == 'Recieved':
            print('The message was successfully delivered')
        else:
            client_socket.sendall(packet)
            print('The message was sent one more time, due to compromised intergrity')
            data = (client_socket.recv(1024)).decode()

    # close client socket
    client_socket.close()
    
    return

def server(PORT):
    # create of server socket of IPv4, TCP type
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)

    # confirmation of client connection
    client_socket, client_address = server_socket.accept()
    print('Client has joined')

    # Load and store RSA keys, private key of reciever
    with open("cert/private_keys_recieve.pem", "rb") as f:
        private_key_recieve = RSA.import_key(f.read())

    # Load and store RSA keys, public key of sender
    with open("cert/public_keys_sender.pem", "rb") as f:
        public_key_send = RSA.import_key(f.read())

    # Load and store RSA keys, public key of reciever
    with open("cert/public_key_recieve.pem", "rb") as f:
        public_key_recieve = RSA.import_key(f.read())

    print('RSA_public_key_receiver=', public_key_recieve.export_key().decode())
    print('RSA_private_key_reciever=', private_key_recieve.export_key().decode())
    print('RSA_public_key_sender=', public_key_send.export_key().decode())

    while True:
        # Data received from client
        data = client_socket.recv(4096)

        if not data: # if data empty
            break
        print('ciphertext=', data.hex())

        RSA_AES_key = data[-256:] # RSA cipher of AES key with padding
        others = data[:-256] 
        nonce = others [-16:] # nonce, used for AES decryption
        AES_cipher = others [:-16] # AES cipher of message with RSA signature

        print("RSA_AES_key=", RSA_AES_key.hex())
        print("AES_cipher:", AES_cipher.hex())

        AES_key_padding = decrypt_data_privatekey(RSA_AES_key, private_key_recieve) # RSA decryption with reciever private key of AES key with padding
        AES_key = AES_key_padding[:16] # AES key of 128 bits

        print('AES_key=', AES_key.hex())

        cipher = AES.new(AES_key, AES.MODE_EAX, nonce) 
        AES_text_output = cipher.decrypt(AES_cipher) # AES decryption of message with RSA signature

        print('text_hash=', AES_text_output)

        RSA_MD5_hash = AES_text_output[-256:] # RSA signature of MD5 hash with padding
        message = AES_text_output[:-256]  # message

        try:
            print('plaintext=', message.decode())
        except:
            print('plaintext=', message)

        MD5_padded_decrypted = decrypt_data_publickey(RSA_MD5_hash, public_key_send) # RSA decryption with sender public key of MD5 hash with padding
        MD5_decrypted = MD5_padded_decrypted[:16] # MD5 hash of message

        MD5_recieved_msg = hashlib.md5(message).digest() # calculation of MD5 hash of recieved message
        print('MD5=', MD5_recieved_msg.hex())

        # comparing MD5 hashes
        if MD5_recieved_msg == MD5_decrypted:
            print('The integrity of the message has not been compromised.')
            response = 'Recieved'.encode()
        else:
            print('The integrity of the report has been compromised.')
            response = 'Compromised'.encode()

        # confirmation of message delivery
        client_socket.sendall(response)

    # close sockets
    client_socket.close()
    server_socket.close()

    return

def main(): 
    # set port number
    if len(sys.argv) > 2:
        PORT = int(sys.argv[2].split('=')[1])

    # create and store keys
    create_and_store_keys()

    # client
    if sys.argv[1] == 'TYPE=c':
        client(PORT)

    # server
    elif sys.argv[1] == 'TYPE=s':
        server(PORT)

    else:
        print('Unknown argument:', sys.argv[1])
        sys.exit(1)

main()