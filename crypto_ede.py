from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter
from Crypto.Util import Padding
from Crypto.Cipher.DES3 import adjust_key_parity
import base64

def ajustar_clave_generica(clave, longitud):
    clave = clave.encode()
    if len(clave) < longitud:
        clave += get_random_bytes(longitud - len(clave))
    elif len(clave) > longitud:
        clave = clave[:longitud]
    return clave

def ajustar_clave_3des(clave, longitud):
    clave = clave.encode()
    if len(clave) < longitud:
        clave += get_random_bytes(longitud - len(clave))
    elif len(clave) > longitud:
        clave = clave[:longitud]
    return adjust_key_parity(clave)

def ajustar_iv(iv, longitud):
    iv = iv.encode()
    if len(iv) < longitud:
        iv += get_random_bytes(longitud - len(iv))
    elif len(iv) > longitud:
        iv = iv[:longitud]
    return iv

def cifrar_y_descifrar(algoritmo, clave, iv, texto):
    if algoritmo == 'DES-EDE':
        clave = ajustar_clave_3des(clave, 16)
        iv = ajustar_iv(iv, 8)
        cipher = DES3.new(clave, DES3.MODE_CBC, iv)
        block_size = DES3.block_size
    elif algoritmo == '3DES':
        clave = ajustar_clave_3des(clave, 24)
        iv = ajustar_iv(iv, 8)
        cipher = DES3.new(clave, DES3.MODE_CBC, iv)
        block_size = DES3.block_size
    elif algoritmo == 'AES':
        clave = ajustar_clave_generica(clave, 32)
        iv = ajustar_iv(iv, 16)
        cipher = AES.new(clave, AES.MODE_CBC, iv)
        block_size = AES.block_size
    else:
        raise ValueError("Algoritmo no soportado")

    # Cifrado
    texto_cifrado = cipher.encrypt(pad(texto.encode(), block_size))
    print(f"\n[{algoritmo}] Clave ajustada: {clave}")
    print(f"[{algoritmo}] IV ajustado: {iv}")
    print(f"[{algoritmo}] Texto cifrado (base64): {base64.b64encode(texto_cifrado).decode()}")

    # Descifrado
    if algoritmo in ['DES-EDE', '3DES']:
        cipher_descifrar = DES3.new(clave, DES3.MODE_CBC, iv)
    elif algoritmo == 'AES':
        cipher_descifrar = AES.new(clave, AES.MODE_CBC, iv)

    texto_descifrado = unpad(cipher_descifrar.decrypt(texto_cifrado), block_size)
    print(f"[{algoritmo}] Texto descifrado: {texto_descifrado.decode()}\n")

# === PROGRAMA PRINCIPAL ===
print("== Cifrado Simétrico CBC ==")
print("Algoritmos disponibles: DES-EDE, 3DES, AES")
algoritmo = input("Ingrese algoritmo: ").strip().upper()
clave = input("Ingrese la clave: ")
iv = input("Ingrese el IV: ")
texto = input("Ingrese el texto a cifrar: ")

try:
    cifrar_y_descifrar(algoritmo, clave, iv, texto)
except Exception as e:
    print("Error:", e)
