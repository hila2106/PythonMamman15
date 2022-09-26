import socket
import struct
from uuid import UUID
from consts import *
from Crypto.PublicKey import RSA


class ResponseHeader:
    def __init__(self, version: int, code: int, payload_size: int):
        self.version = version
        self.code = code
        self.payload_size = payload_size

    def __str__(self):
        return f"version: {self.version}, code: {self.code}, payload_size: {self.payload_size}"


class Client:
    def __init__(self, port: int = DEFAULT_PORT, host: str = LOCAL_HOST):
        self.port = port
        self.host = host
        self.key = RSA.generate(KEY_LEN)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            registration_request = self._create_registration_request(DEFAULT_USERNAME,
                                                                  DEFAULT_UUID,
                                                                  SERVER_VERSION,
                                                                  REGISTRATION_CODE)
            s.sendall(registration_request)
            resp_payload = self._get_resp_payload(s)
            print(f"recieved {resp_payload}")

    def _create_registration_request(self, name: str, client_id: UUID, version: int, code: int) -> bytes:
        payload = f"""{name}{NULL_TERMINATED}""".ljust(NAME_FIELD_LEN, '0').encode()
        header = self._create_request_header(client_id, version, code, len(payload))
        return header + payload

    @staticmethod
    def _create_request_header(client_id: UUID, version: int, code: int, payload_size: int) -> bytes:
        header = struct.pack(REQUEST_HDR_FORMAT_NO_UUID, version, code, payload_size)
        return client_id.bytes_le + header

    @staticmethod
    def _get_resp_payload(s: socket.socket) -> ResponseHeader:
        header = s.recv(RESPONSE_HEADER_LENGTH)
        return ResponseHeader(*struct.unpack(RESPONSE_HEADER_FORMAT, header))



def main():
    client = Client()
    client.run()


if __name__ == '__main__':
    main()
