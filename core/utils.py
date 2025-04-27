import math
import random
from hashlib import sha256 as hash_func


def is_prime(num: int) -> bool:
    """
    Функция проверяет число на простоту

    :param num: Число
    :return: True - простое, False - составное
    """
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True


def generate_prime(min_value: int, max_value: int) -> int | None:
    """
    Функция генерирует простое число на заданном отрезке или None, если не нашлось число на отрезке

    :param min_value: Нижняя граница отрезка
    :param max_value: Верхняя граница отрезка
    :return: Простое число на заданном отрезке
    """
    for i in range(100):
        num = random.randint(min_value, max_value)
        if is_prime(num):
            return num
    return None


def generate_p_q(min_n: int, max_n: int) -> tuple[int, int] | None:
    """
    Функция генерирует два простых числа, в произведении дающих от min_n (512) до max_n (1024)

    :param min_n: Минимальное значение произведения простых чисел
    :param max_n: Максимальное значение произведения простых чисел
    :return: q, p - простые числа
    """
    attempts, max_attempts = 0, 1000

    while attempts < max_attempts:
        p = generate_prime(2, max_n // 2 + 1)  # Генерируем p так, чтобы q было не меньше 2

        if not p:
            attempts += 1
            continue

        max_q = max_n // p
        q = generate_prime(2, max_q)

        if not q:
            attempts += 1
            continue

        if min_n <= p * q <= max_n:
            return q, p
        else:
            attempts += 1
            continue

    return generate_p_q(min_n, max_n)


def generate_coprime(n: int) -> int:
    """
    Функция генерирует взаимно простое с n число

    :param n: Число, для которого нужно найти взаимно простое
    :return: взаимно простое число
    """
    if n == 1:
        return 1

    while True:
        m = random.randint(2, n - 1)  # Генерируем число от 2 до n - 1
        if math.gcd(n, m) == 1:  # Проверяем, взаимно ли просто
            return m


def get_hash_fiat_shamir(message: bytes, x: list[int], n: int) -> bytes:
    """
    Функция получает хэш (по алгоритму sha256) сообщения и всех Х чисел

    :param message: Сообщение, которое нужно подписать
    :param x: x_i = (r_i ** 2) % n, где r_i - случайное число от 1
    :param n: произведение двух простых чисел p * q
    :return: хэш
    """
    data = message

    for x_val in x:
        data += x_val.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

    return hash_func(data).digest()


if __name__ == '__main__':
    print(generate_p_q(512, 9128))
