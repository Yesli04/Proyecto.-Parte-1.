from users import registerUser, getQR, sendQR, usersFileName
from json import dumps
from hashlib import sha256
import io
from PIL import Image
import base64
import pyqrcode


def test_register_usuario_ya_registrado():
    with open(usersFileName, "w") as f:
        f.write(dumps({
            "id": 11111111,
            "password": sha256("00000".encode()).hexdigest(),
            "program": "Electronics Engineering",
            "role": "Student"
        }) + "\n")

    resultado = registerUser(11111111, "00000", "Electronics Engineering", "Student")
    assert resultado == "User already registered"

def test_register_nuevo_usuario():
    with open(usersFileName, "w") as f:
        f.write("")

    resultado = registerUser(11111111, "00000", "Electronics Engineering", "Student")
    assert resultado == "User succesfully registered"

def test_getQR_usuario_valido():
    # Registrar usuario
    registerUser(11111111, "00000", "Electronics Engineering", "Student")
    buffer = getQR(11111111, "00000")
    assert isinstance(buffer, io.BytesIO)
    buffer.seek(0)
    img = Image.open(buffer)
    assert img.format == "PNG"

def test_getQR_usuario_invalido():
    resultado = getQR(99999999, "wrongpassword")
    assert resultado is None

#def test_sendQR_usuario_valido(monkeypatch):
    # Registrar y generar QR
    #registerUser(11111112, "12345", "Computer Science", "Student")
    #buffer = getQR(11111112, "12345")
    #png_bytes = buffer.getvalue()

    # Monkeypatch para simular ocupación
    #def fake_identifySpot(img):
        #return False  # Simula plaza desocupada

    # Parchear funciones si las tienes separadas, aquí asumimos que funciona
    #resultado = sendQR(png_bytes)
    #assert "puesto disponible asignado" in resultado or "plazas están ocupadas" in resultado

#def test_sendQR_usuario_no_registrado():
    # Simula QR de usuario no existente
    #data = {
        #"id": 99999999,
        #"program": "Fake",
        #"role": "Student"
    #}
    #import users
    #encrypted = list(users.encrypt_AES_GCM(dumps(data).encode(), users.key or users.urandom(32)))
    #qr_text = dumps({
        #'qr_text0': base64.b64encode(encrypted[0]).decode('ascii'),
        #'qr_text1': base64.b64encode(encrypted[1]).decode('ascii'),
        #'qr_text2': base64.b64encode(encrypted[2]).decode('ascii')
    #})
    #qrcode = pyqrcode.create(qr_text)
    #buffer = io.BytesIO()
    #qrcode.png(buffer, scale=8)
    #png_bytes = buffer.getvalue()

    #resultado = sendQR(png_bytes)
    #assert "Usuario no registrado" in resultado