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

def cifrar_y_descifrar_ecb(algoritmo, clave, texto):
    if algoritmo == 'DES':
        clave = ajustar_clave(clave, 8)
        cipher = DES.new(clave, DES.MODE_ECB)
        block_size = DES.block_size
    elif algoritmo == '3DES':
        clave = ajustar_clave(clave, 24)
        cipher = DES3.new(clave, DES3.MODE_ECB)
        block_size = DES3.block_size
    elif algoritmo == 'AES':
        clave = ajustar_clave(clave, 32)
        cipher = AES.new(clave, AES.MODE_ECB)
        block_size = AES.block_size
    else:
        raise ValueError("Algoritmo no soportado")

    # Cifrado
    texto_cifrado = cipher.encrypt(pad(texto.encode(), block_size))
    print(f"\n[{algoritmo} - ECB] Clave ajustada: {clave}")
    print(f"[{algoritmo} - ECB] Texto cifrado (base64): {base64.b64encode(texto_cifrado).decode()}")

    # Descifrado (recrear el objeto correctamente)
    if algoritmo == 'DES':
        cipher_descifrar = DES.new(clave, DES.MODE_ECB)
    elif algoritmo == '3DES':
        cipher_descifrar = DES3.new(clave, DES3.MODE_ECB)
    elif algoritmo == 'AES':
        cipher_descifrar = AES.new(clave, AES.MODE_ECB)

    texto_descifrado = unpad(cipher_descifrar.decrypt(texto_cifrado), block_size)
    print(f"[{algoritmo} - ECB] Texto descifrado: {texto_descifrado.decode()}\n")

# === PROGRAMA PRINCIPAL ===
print("== Cifrado Simétrico en Modo ECB (DES / 3DES / AES) ==")
algoritmo = input("Ingrese algoritmo (DES, 3DES, AES): ").strip().upper()
clave = input("Ingrese la clave: ")
texto = input("Ingrese el texto a cifrar: ")

try:
    cifrar_y_descifrar_ecb(algoritmo, clave, texto)
except Exception as e:
    print("Error:", e)
