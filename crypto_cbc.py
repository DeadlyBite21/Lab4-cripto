from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

def ajustar_clave(clave, longitud_requerida):
    clave = clave.encode()
    if len(clave) < longitud_requerida:
        clave += get_random_bytes(longitud_requerida - len(clave))
    elif len(clave) > longitud_requerida:
        clave = clave[:longitud_requerida]
    return clave

def ajustar_iv(iv, longitud_requerida):
    iv = iv.encode()
    if len(iv) < longitud_requerida:
        iv += get_random_bytes(longitud_requerida - len(iv))
    elif len(iv) > longitud_requerida:
        iv = iv[:longitud_requerida]
    return iv

def cifrar_y_descifrar(algoritmo, clave, iv, texto):
    if algoritmo == 'DES':
        clave = ajustar_clave(clave, 8)
        iv = ajustar_iv(iv, 8)
        cipher = DES.new(clave, DES.MODE_CBC, iv)
        block_size = DES.block_size
    elif algoritmo == '3DES':
        clave = ajustar_clave(clave, 24)
        iv = ajustar_iv(iv, 8)
        cipher = DES3.new(clave, DES3.MODE_CBC, iv)
        block_size = DES3.block_size
    elif algoritmo == 'AES':
        clave = ajustar_clave(clave, 32)
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

    # Descifrado con nuevo objeto
    if algoritmo == 'DES':
        cipher_descifrar = DES.new(clave, DES.MODE_CBC, iv)
    elif algoritmo == '3DES':
        cipher_descifrar = DES3.new(clave, DES3.MODE_CBC, iv)
    elif algoritmo == 'AES':
        cipher_descifrar = AES.new(clave, AES.MODE_CBC, iv)

    texto_descifrado = unpad(cipher_descifrar.decrypt(texto_cifrado), block_size)
    print(f"[{algoritmo}] Texto descifrado: {texto_descifrado.decode()}\n")

# === PROGRAMA PRINCIPAL ===
print("== Laboratorio de Cifrado Simétrico (DES / 3DES / AES-256) ==")
algoritmo = input("Ingrese algoritmo (DES, 3DES, AES): ").strip().upper()
clave = input("Ingrese la clave: ")
iv = input("Ingrese el IV: ")
texto = input("Ingrese el texto a cifrar: ")

try:
    cifrar_y_descifrar(algoritmo, clave, iv, texto)
except Exception as e:
    print("Error:", e)
