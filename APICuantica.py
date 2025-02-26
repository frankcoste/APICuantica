from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from oqs import KeyEncapsulation
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import base64
import logging
from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator

class IntentosFilter(logging.Filter):
    def filter(self, record):
        return "Intentos realizados" in record.getMessage()

logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
handler.addFilter(IntentosFilter())  # Solo mostrar intentos
logger.handlers = [handler]


app = FastAPI()

# Modelo de solicitud
class EncryptRequest(BaseModel):
    data: str  

class AttackRequest(BaseModel):
    private_key: str  # La clave privada en Base64
    kyber_ciphertext: str  # El texto cifrado con Kyber en Base64
    aes_ciphertext: str  # El texto cifrado con AES en Base64

# Constantes
KYBER_ALGORITHM = "Kyber1024"
AES_KEY_LENGTH = 32

@app.post("/encrypt")
def encrypt(request: EncryptRequest):
    try:
        # Generar un par de claves Kyber1024
        kem = KeyEncapsulation(KYBER_ALGORITHM)
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
        kyber_ciphertext, shared_secret = kem.encap_secret(public_key)

        # Cifrado AES usando la clave compartida
        shared_secret = shared_secret.ljust(AES_KEY_LENGTH, b'\0')[:AES_KEY_LENGTH]
        aesgcm = AESGCM(shared_secret)
        nonce = os.urandom(12)
        aes_ciphertext = aesgcm.encrypt(nonce, request.data.encode(), None)

        # Retorna los resultados en formato base64
        return {
            "kyber_ciphertext": base64.b64encode(kyber_ciphertext).decode(),
            "aes_ciphertext": base64.b64encode(nonce + aes_ciphertext).decode(),
            "private_key": base64.b64encode(private_key).decode(),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al cifrar: {str(e)}")

# Circuito cuánticopara buscar la clave privada
def QuanticAttack(private_key: bytes):
    n = len(private_key) * 8  # Usamos 8 qubits por cada byte de la clave privada
    if n > 30:  # Limitar el número de qubits a 30
        n = 30  # Ajustamos el número de qubits a un valor manejable
    
    # Crear un circuito cuántico con 'n' qubits
    qc = QuantumCircuit(n)

    # Aplicar puertas Hadamard a todos los qubits para crear una superposición
    qc.h(range(n))

    # Medir todos los qubits
    qc.measure_all()

    # Simulador cuántico
    simulator = AerSimulator()

    # Transpile y ejecutar el circuito
    compiled_circuit = transpile(qc, simulator)
    result = simulator.run(compiled_circuit).result()

    # Obtener los resultados y retornar los conteos
    counts = result.get_counts()
    return counts

#Corrige el padding por si tiene cualquier error. 
def correct_base64_padding(base64_string):
    base64_string = base64_string.replace('-', '+').replace('_', '/')
    missing_padding = len(base64_string) % 4
    if missing_padding:
        base64_string += '=' * (4 - missing_padding)
    return base64_string
    
#La base 64 indica el formato 64 de la misma
def safe_base64_decode(base64_string):
    try:
        corrected = correct_base64_padding(base64_string)
        return base64.b64decode(corrected)
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

@app.post("/attack")
def attack(request: AttackRequest):
    try:
        private_key = safe_base64_decode(request.private_key)
        kyber_ciphertext = safe_base64_decode(request.kyber_ciphertext)
        aes_ciphertext = safe_base64_decode(request.aes_ciphertext)
        nonce = aes_ciphertext[:12]
        aes_ciphertext = aes_ciphertext[12:]
        attempts = 0

        while True:
            counts = QuanticAttack(private_key)
            attempts += len(counts)

            
            if attempts % 10 == 0:
                logging.info(f"Intentos realizados: {attempts}")

            for key, _ in counts.items():
                guessed_key = int(key, 2).to_bytes(len(private_key), byteorder='big')
                
                if guessed_key == private_key:
                    # Intentar descifrar el texto cifrado con la clave compartida
                    kem = KeyEncapsulation(KYBER_ALGORITHM)
                    shared_secret = kem.decap_secret(kyber_ciphertext, guessed_key)
                    shared_secret = shared_secret.ljust(AES_KEY_LENGTH, b'\0')[:AES_KEY_LENGTH]
                    aesgcm = AESGCM(shared_secret)
                    try:
                        decrypted_data = aesgcm.decrypt(nonce, aes_ciphertext, None)
                        return {
                            "message": "Clave encontrada y texto descifrado!",
                            "attempts": attempts,
                            "recovered_private_key": base64.b64encode(guessed_key).decode(),
                            "decrypted_data": decrypted_data.decode()
                        }
                    except Exception as e:
                        logging.error(f"Error al descifrar con la clave adivinada: {e}")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al simular el ataque cuántico: {str(e)}")
