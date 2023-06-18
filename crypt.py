import os, pyaes, sys, argparse

def encrypt(pub_key, plain_text, secret_cip):
    n, e = open(pub_key, 'r').read().split(',')
    plain_text = open(plain_text, 'rb').read()
    aes_key = os.urandom(16)
    cipher_text = pyaes.AESModeOfOperationCTR(aes_key).encrypt(plain_text)
    p = int.from_bytes(aes_key, sys.byteorder)
    e, n = int(e), int(n)
    cipher_key = pow(p, e, n)
    cipher_key = bytes(str(cipher_key).encode())
    secret_file = open(secret_cip, 'wb')
    secret_file.write(b'%b %b' % (cipher_text, cipher_key))
    secret_file.close()
    #return plain_text

def decrypt(prv_key, secret_cip, plain_text):
    n, d = open(prv_key, 'r').read().split(',')
    c_items = open(secret_cip, 'rb').read().split(b' ')
    cipher_text = b' '.join(c_items[:-1])
    cipher_key = c_items[-1]
    cipher_key, d, n = int(cipher_key), int(d), int(n)
    aes_key = pow(cipher_key, d, n)
    aes = pyaes.AESModeOfOperationCTR(aes_key.to_bytes(16, sys.byteorder))
    decrypted = aes.decrypt(cipher_text)
    plain_text_file = open(plain_text, 'wb')
    plain_text_file.write(decrypted)
    plain_text_file.close()
    #return decrypted

parser = argparse.ArgumentParser(prog="My RSA Encryptor/Decryptor.")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-e", help="Encrypt with public key")
group.add_argument("-d", help="Decrypt with private key")

parser.add_argument("source", help="Source File")
parser.add_argument("destination", help="Destination File")

args = parser.parse_args()

if args.e:
    encrypt(args.e, args.source, args.destination)
elif args.d:
    decrypt(args.d, args.source, args.destination)
