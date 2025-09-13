from core.utils import *


def generate_keypair(t: int = 8):
    """
    Функция генерирует закрытый и открытый ключи

    :param t: Число значений в списках v и s
    :return: Открытый ключ, закрытый ключ
    """
    p, q = generate_p_q()
    n = p * q

    s = [generate_coprime(n) for _ in range(t)]
    v = [pow(s_val, -2, n) for s_val in s]

    return (n, v), (n, s)


def sign(private_key: tuple, message: str):
    """
    Функция подписывает сообщение

    :param private_key: Приватный ключ и n
    :param message: Сообщение, которое необходимо подписать
    :return: Подпись в формате b_ij и y_i
    """
    n, s = private_key
    t = len(s)
    k = random.randint(7, t)

    r = [random.randint(1, n) for _ in range(t)]
    x = [pow(r_val, 2, n) for r_val in r]

    hash_val = get_hash_fiat_shamir(message.encode('utf-8'), x, n)
    binary_hash = ''.join([format(byte, '08b') for byte in hash_val])

    b = [[int(binary_hash[i * k + j]) for j in range(k)] for i in range(t)]

    y = []
    for i in range(t):
        y_val = r[i]
        for j in range(k):
            if b[i][j]:
                y_val = (y_val * s[j]) % n
        y.append(y_val)

    return b, y


def verify(public_key: tuple, sign: tuple, message: str) -> bool:
    """
    Функция проверяет подпись по протоколу Фиата-Шамира

    :param public_key: Публичный ключ и n
    :param sign: Подпись
    :message sign: Сообщение, которое нужно проверить
    :return: True - все верно, False - Нет
    """
    n, v = public_key
    b, y = sign
    t, k = len(v), len(b[0])

    z = []
    for i in range(t):
        z_val = pow(y[i], 2, n)
        for j in range(k):
            if b[i][j]:
                z_val = (z_val * v[j]) % n
        z.append(z_val)

    # Вычисляем хеш от (message, z) и получаем b_new
    hash_val = get_hash_fiat_shamir(message.encode('utf-8'), z, n)
    binary_hash = ''.join([format(byte, '08b') for byte in hash_val])

    b_new = [[int(binary_hash[i * k + j]) for j in range(k)] for i in range(t)]

    return b == b_new


if __name__ == '__main__':
    # Пример использования:
    public_key, private_key = generate_keypair(1024)
    message = "Hello, Fiat-Shamir!"
    b, y = sign(private_key, message)
    is_valid = verify(public_key, (b, y), message)
    print(is_valid)


