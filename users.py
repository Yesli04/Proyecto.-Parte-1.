# Estos son los paquetes que se deben instalar
# pip install pycryptodome
# pip install pyqrcode
# pip install pypng
# pip install pyzbar
# pip install pillow

# No modificar estos módulos que se importan
from pyzbar.pyzbar import decode
from PIL import Image
from json import dumps, loads
from hashlib import sha256
from Crypto.Cipher import AES
import base64
import pyqrcode
from os import urandom
import io
from datetime import datetime
import cv2
import numpy as np
import os

# Nombre del archivo con la base de datos de usuarios
usersFileName = "users.txt"
if not os.path.exists(usersFileName):
    with open(usersFileName, "w") as f:
        pass  # Crear el archivo si no existe

# Fecha actual y clave AES
date = None
key = None

# Función para encriptar (no modificar)
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

# Función para desencriptar (no modificar)
def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

# Función que genera un código QR (no modificar)
def generateQR(id, program, role, buffer):
    global key, date
    data = {'id': id, 'program': program, 'role': role}
    datas = dumps(data).encode("utf-8")

    if key is None:
        key = urandom(32)
        date = datetime.today().strftime('%Y-%m-%d')

    if date != datetime.today().strftime('%Y-%m-%d'):
        key = urandom(32)
        date = datetime.today().strftime('%Y-%m-%d')

    encrypted = list(encrypt_AES_GCM(datas, key))

    qr_text = dumps({
        'qr_text0': base64.b64encode(encrypted[0]).decode('ascii'),
        'qr_text1': base64.b64encode(encrypted[1]).decode('ascii'),
        'qr_text2': base64.b64encode(encrypted[2]).decode('ascii')
    })

    qrcode = pyqrcode.create(qr_text)
    qrcode.png(buffer, scale=8)

# Función para registrar usuarios
def registerUser(id, password, program, role):
    try:
        with open(usersFileName, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    usuario = loads(line)
                except:
                    continue
                if usuario["id"] == int(id):
                    return "User already registered"
    except FileNotFoundError:
        pass

    with open(usersFileName, "a") as f:
        newUser = {
            "id": int(id),
            "password": sha256(password.encode()).hexdigest(),
            "program": program,
            "role": role
        }
        f.write(dumps(newUser) + "\n")

    return "User succesfully registered"

# Función para obtener el QR si las credenciales son válidas
def getQR(id, password):
    try:
        with open(usersFileName, "r") as f:
            usuarios = f.readlines()
    except:
        return None

    for line in usuarios:
        line = line.strip()
        if not line:
            continue
        try:
            datos = loads(line)
        except:
            continue

        if datos["id"] == int(id) and datos["password"] == sha256(password.encode()).hexdigest():
            buffer = io.BytesIO()
            generateQR(id, datos["program"], datos["role"], buffer)
            return buffer

    return None

# Función para procesar un QR y asignar un puesto
def sendQR(png):
    from pyzbar.pyzbar import decode
    from PIL import Image
    from json import loads, dumps
    from Crypto.Cipher import AES
    import base64
    import io
    import cv2
    import numpy as np
    import os

    global key  # Clave AES global

    # === 1. Leer y decodificar QR ===
    try:
        decoded = decode(Image.open(io.BytesIO(png)))[0].data.decode('ascii')
        data = loads(decoded)
        encrypted = (
            base64.b64decode(data["qr_text0"]),
            base64.b64decode(data["qr_text1"]),
            base64.b64decode(data["qr_text2"]),
        )
        decrypted = decrypt_AES_GCM(encrypted, key)
        info = loads(decrypted.decode('utf-8'))
    except Exception as e:
        return dumps(f"QR inválido o no se pudo desencriptar: {e}")

    # === 2. Verificar si el usuario está registrado ===
    user_found = False
    with open(usersFileName, "r") as archivo:
        for linea in archivo:
            try:
                usuario = loads(linea.strip())
                if usuario["id"] == int(info["id"]):
                    user_found = True
                    break
            except:
                continue

    if not user_found:
        return dumps("Usuario no registrado")

    rol_usuario = info["role"]

    # === 3. Definir plazas según el rol ===
    if rol_usuario == "Student":
        plazas_rol = [1, 2, 3, 4]
    elif rol_usuario == "Administrative":
        plazas_rol = [5, 6, 7]
    elif rol_usuario == "Teacher":
        plazas_rol = [8, 9, 10]
    else:
        return dumps("Rol no válido")

    # === 4. Capturar imágenes de hasta 10 plazas ===
    cam = cv2.VideoCapture("http://100.85.93.45:8080/video")
    carpeta = "capturas_plazas"
    if not os.path.exists(carpeta):
        os.makedirs(carpeta)

    capturas = []

    def identifySpot(frame):
        escala = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        borde = cv2.Canny(escala, 50, 100)
        pixeles = np.count_nonzero(borde == 255)
        return pixeles >= 12500  # True si ocupada

    print("Presiona [ESPACIO] para capturar una plaza. [ESC] para finalizar.")

    while len(capturas) < 10:
        ret, frame = cam.read()
        if not ret:
            print("Error al capturar desde la cámara.")
            continue

        cv2.imshow('Vista en Vivo', cv2.flip(frame, 1))
        tecla = cv2.waitKey(1)

        if tecla == 27:  # ESC
            break
        elif tecla == 32:  # ESPACIO
            plaza_num = len(capturas) + 1
            ruta = os.path.join(carpeta, f"plaza_{plaza_num}.jpg")
            cv2.imwrite(ruta, frame)
            capturas.append((plaza_num, ruta))
            print(f"Captura guardada: plaza {plaza_num}")

    cam.release()
    cv2.destroyAllWindows()

    # === 5. Validar y asignar ===
    print("\nRESULTADOS DE VALIDACIÓN Y ASIGNACIÓN:\n")
    puesto_asignado = None

    for plaza, path in capturas:
        img = cv2.imread(path)
        ocupada = identifySpot(img)
        estado = "ocupada" if ocupada else "desocupada"

        if plaza in [1, 2, 3, 4]:
            rol_plaza = "Estudiante"
        elif plaza in [5, 6, 7]:
            rol_plaza = "Administrativo"
        elif plaza in [8, 9, 10]:
            rol_plaza = "Profesor"
        else:
            rol_plaza = "Desconocido"

        print(f"Plaza {plaza} ({rol_plaza}): {estado}")

        if not ocupada and not puesto_asignado and plaza in plazas_rol:
            puesto_asignado = plaza

    if puesto_asignado:
        return dumps(f"Se le asignó la plaza {puesto_asignado} ({rol_usuario})")
    else:
        return dumps(f"No hay plazas disponibles para el rol {rol_usuario}")

# === PRUEBA ===
print(registerUser(11111111, "00000", "Electronics Engineering", "Student"))
qr = getQR(11111111, "00000")
if qr:
     with open("qr.png", "wb") as f:
         f.write(qr.getvalue())
     print("QR guardado como qr.png")
else:
     print("Usua2rio no válido")
