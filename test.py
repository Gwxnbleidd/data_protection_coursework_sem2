import rsa

public_key, private_key = rsa.newkeys(2**9)
message = 'alalal'
sign = rsa.sign(message.encode(), private_key, 'SHA-1')
if __name__ == '__main__':
    print(rsa.verify('alala'.encode(), sign, public_key))