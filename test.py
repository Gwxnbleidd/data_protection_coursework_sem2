import rsa
from core.file_info import FileInfo

public_key, private_key = rsa.newkeys(2**9)

with open('public_key', 'wb') as f:
    f.write(public_key.save_pkcs1('DER'))
with open('private_key', 'wb') as f:
    f.write(private_key.save_pkcs1('DER'))
pb1 = public_key
pr1 = private_key

message = FileInfo.collect('requirements.txt')
mes = message.to_json()
sign = rsa.sign(mes.encode(), private_key, 'SHA-1')

del public_key
del private_key

with open('public_key', 'rb') as f:
    public_key_val = f.read()
public_key = rsa.PublicKey.load_pkcs1(public_key_val, 'DER')

with open('private_key', 'rb') as f:
    private_key_val = f.read()
private_key = rsa.PrivateKey.load_pkcs1(private_key_val, 'DER')

message = FileInfo.collect('requirements.txt')
mes = message.to_json()
pb2 = public_key
pr2 = private_key

print( pb1==pb2 and pr1==pr2 )

if __name__ == '__main__':
    print(rsa.verify(mes.encode(), sign, public_key))