import math
import random
from hashlib import sha256


# def is_prime(n: int, k: int = 5) -> bool:
#     """
#     Функция проверяет число на простоту. Иногда ошибается
#
#     :param n: Число
#     :param k: Количество итераций
#     :return: True - простое, False - составное
#     """
#     if n <= 1:
#         return False
#
#     if n <= 3:
#         return True
#
#     r, s = 0, n - 1
#     while s % 2 == 0:
#         r += 1
#         s //= 2
#
#     for _ in range(k):
#         a = random.randint(2, n - 1)
#         x = pow(a, s, n)
#         if x == 1 or x == n - 1:
#             continue
#         for _ in range(r - 1):
#             x = pow(x, 2, n)
#         if x == n - 1:
#             break
#         else:
#             return False
#     return True
def is_prime(n: int) -> bool:
    """
    Детерминированная функция проверки числа на простоту.
    Гарантированно правильная для всех чисел до 2^64.

    :param n: Число для проверки
    :return: True - простое, False - составное
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    # Проверка делением на все числа вида 6k ± 1
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6

    return True


def generate_prime(min_val: int, max_val: int) -> int | None:
    """
    Генерирует простое число в заданном диапазоне

    :param min_val: минимальное значение (включительно)
    :param max_val: максимальное значение (включительно)
    :return: простое число или None, если не найдено
    """
    for _ in range(100):
        num = random.randint(min_val, max_val)
        num |= 1  # делаем нечетным
        if is_prime(num):
            return num
    return None


def generate_p_q() -> tuple[int, int]:
    """
    Генерирует два простых числа p и q, такие что:
    - 512 ≤ bit_length(p * q) ≤ 1024
    - p и q имеют примерно одинаковый размер (для безопасности)

    :return: Кортеж (p, q) простых чисел
    :raises RuntimeError: Если не удалось найти подходящие простые числа
    """
    max_attempts = 1000

    for _ in range(max_attempts):
        # Выбираем случайную целевую длину для n в диапазоне 512-1024 бит
        target_n_bits = random.randint(512, 1024)

        # Чтобы p и q были примерно одинакового размера
        p_bits = target_n_bits // 2
        q_bits = target_n_bits - p_bits

        # Генерируем p (с небольшим запасом, чтобы точно попасть в диапазон)
        p_min = 2 ** (p_bits - 1)
        p_max = 2 ** p_bits - 1
        p = generate_prime(p_min, p_max)
        if not p:
            continue

        # Вычисляем допустимый диапазон для q
        min_n = 2 ** (target_n_bits - 1)
        max_n = 2 ** target_n_bits - 1

        q_min = max(2 ** (q_bits - 1), (min_n + p - 1) // p)  # ceil(min_n / p)
        q_max = min(2 ** q_bits - 1, max_n // p)  # floor(max_n / p)

        if q_min > q_max:
            continue

        q = generate_prime(q_min, q_max)
        if not q:
            continue

        n = p * q
        if 512 <= n.bit_length() <= 1024:
            return p, q

    raise RuntimeError(f"Не удалось найти подходящие простые числа за {max_attempts} попыток")


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
    :param x: Набор чисел, которые также нужно захэшировать
    :param n: произведение двух простых чисел p * q
    :return: хэш
    """
    data = message

    for x_val in x:
        data += x_val.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

    return sha256(data).digest()


if __name__ == '__main__':
    print(generate_p_q())
