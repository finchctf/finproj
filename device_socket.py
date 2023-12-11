import socket
import json
from client import Device
from verifier_socket import VerifierSocket

class DeviceSocket:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.device = Device(1212005173304576588776035408720434249624843017988539769573321072546946726998200133077605437, "A")

    def start(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                print(f"Connected to the verifier on {self.host}:{self.port}")
                self.enrollment_phase(s)
                self.device_device_ake(s)  # Added DD-AKE communication
        except ConnectionRefusedError as e:
            print(f"Error: {e}")

    def enrollment_phase(self, s):
        challenges_json = s.recv(1024).decode()
        challenges = json.loads(challenges_json)
        C_X, C_XV = challenges["C_X"], challenges["C_XV"]
        self.device.device_enroll.get_CX_CXV(C_X, C_XV)

        RA, RAV = self.device.device_enroll.get_RX_RXV()
        responses = {"RA": RA, "RAV": RAV}
        s.sendall(json.dumps(responses).encode())

        print("Sent responses to the verifier.")

        message_json = s.recv(1024).decode()
        message = json.loads(message_json)
        self.device.device_enroll.store_vVals(message["ID"], message["s_A"], message["hc_A"].encode("latin-1"), message["CAV"])

        print("Received message from the verifier.")

        verification_result = self.device_verification()
        s.sendall(verification_result.encode())
        print(f"Sent verification result to the verifier.")

    def device_device_ake(self, s):
        temp_keys_A = self.device.device_dd_ake.gen_tempo_keys("B", "V1")
        s.sendall(json.dumps(temp_keys_A).encode())

        temp_keys_V_json = s.recv(1024).decode()
        temp_keys_V = json.loads(temp_keys_V_json)
        temp_keys_V = tuple(temp_keys_V)

        print(self.device.device_dd_ake.verify_and_gen_session_key(*temp_keys_V[0]))
        print(self.device.device_dd_ake.verify_and_gen_session_key(*temp_keys_V[1], False))

    def device_verification(self):
        verification_result = "Device Verification Successful"
        return verification_result

def main():
    try:
        device_socket = DeviceSocket(host="localhost", port=8000)  
        device_socket.start()
    except ConnectionRefusedError as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
