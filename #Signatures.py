#Signatures.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def generate_keys():
    
    private = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
)
    
    public = private.public_key()
    return private, public

def sign(message, private) :
    
    sig = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
)
    
    return sig

def verify(message, sig, public):
    try:   
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )  
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing public key.verify")
        return False
    return retval


if __name__ == '__main__':
    pr, pu = generate_keys()
    print(pr)
    print(pu)
    message = b'this is a secret'
    sig = sign(message, pr)
    print(sig)
    correct = verify(message, sig, pu)

    if correct:
        print("Success! Good signature")
    else:
        print ("Error! Signature is bad")

    pr2, pu2 = generate_keys()

    sig2 = sign(message, pr2)

    correct = verify(message, sig2, pu)
    if correct:
        print("Error! Bad signature checks out!")
    else:
        print("Success! Bad signature detected!")
    

    
