#pip install pycryptodome
from Crypto.PublicKey import RSA

def generate_and_print(label):
    key = RSA.generate(1024)  # atau 2048 kalau mau lebih besar
    print(f"=== {label} ===")
    print("N =", key.n)
    print("E =", key.e)
    print("D =", key.d)
    print()

if __name__ == "__main__":
    generate_and_print("SERVER")
    generate_and_print("CLIENT")
