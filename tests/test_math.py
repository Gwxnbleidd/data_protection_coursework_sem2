from app.core.utils import generate_prime, is_prime


def test_is_prime():
    assert is_prime(131) == True
    assert is_prime(4) == False
    assert is_prime(131232342) == False
    assert is_prime(131232347) == True


def test_generate_prime():
    for _ in range(15):
        assert is_prime(generate_prime(0, 1000)) == True