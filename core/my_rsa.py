from core.utils import *


def generate_keypair(p = 512, q = 512, bit_length = 1024):
    """ Функция создает публичный и приватный ключи.
    Возвращает public_key, private_key
    """
    p = gen_prime(bit_length)
    q = gen_prime(bit_length)

    n = p * q
    phi = (p-1) * (q-1)

    # Выбираем открытый ключ e, такой что 1 < e < phi и e взаимно прост с phi
    e = random.randrange(2, phi)
    while m.gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # Вычисляем закрытый ключ d, такой что d * e ≡ 1 (mod phi)
    d = inverse(e, phi)

    return ((e, n), (d, n))

# def encrypt(public_key, plaintext):
#     e, n = public_key
#     ciphertext = [pow(ord(char), e, n) for char in plaintext]
#     return ciphertext
#
#
# def decrypt(private_key, ciphertext):
#     d, n = private_key
#     plaintext = [chr(pow(char, d, n)) for char in ciphertext]
#     return ''.join(plaintext)

def sign(private_key: tuple, plaintext: str):
    """ Функция получает закрытый ключ и текст и шифрует его.
    Возвращает зашифрованный текст
    """
    d, n = private_key
    return ' '.join([str(pow(ord(char), d, n)) for char in plaintext])

def verify (public_key, ciphertext, plaintext):
    """ Функция проверяет соответствие зашифрованного текста заданному.
    Возвращает True или False
    """
    e, n = public_key
    decrypt_text=''
    for char in ciphertext.split(' '):
        number = pow(int(char), e, n)
        letter = chr(number)
        decrypt_text += letter
    # decrypt_text = ''.join([chr(pow(int(char), e, n)) for char in ciphertext])
    # decrypt_text = ''.join([chr(pow(int(char), e, n)) for char in ciphertext])
    return decrypt_text == plaintext

# public_key, private_key = generate_keypair()
# text = "alala lalala"
# sign_text = sign(private_key, text)
# print(verify(public_key, sign_text, 'text'))