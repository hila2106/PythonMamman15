import datetime
import socket
import sqlite3
import struct
from uuid import UUID, uuid1

from consts import *


class RequestHeader:
    def __init__(self, client_id: UUID, ver: int, code: int, payload_size: int):
        self.client_id = client_id
        self.ver = ver
        self.code = code
        self.payload_size = payload_size

    def __str__(self):
        return f"client_id: {self.client_id}, ver: {self.ver}, code: {self.code}, payload_size: {self.payload_size}"


class DBManager:
    def __init__(self, server_name: str):
        self.conn = sqlite3.connect(server_name)
        self.conn.text_factory = bytes
        self._create_db_tables()
        self.cur = self.conn.cursor()

    def __del__(self):
        self.conn.close()

    def _create_db_tables(self):
        for sql_script in [CREATE_CLIENTS_TABLE_SQL, CREATE_FILES_TABLE_SQL]:
            try:
                self.conn.executescript(sql_script)
                self.conn.commit()
            except sqlite3.OperationalError as error:
                print(f"failed creating tables due to {error}")

    def has_username(self, username: str) -> bool:
        query = f"""select * from clients where Name = '{username}'"""
        self.cur.execute(query)
        return bool(len(self.cur.fetchall()))

    def generate_uuid(self) -> str:
        while True:
            client_uuid = uuid1().__str__()
            if client_uuid not in (self._get_all_uuids()):
                print(client_uuid)
                return client_uuid.__str__()

    def _get_all_uuids(self):
        query = "SELECT id FROM clients;"
        self.cur.execute(query)
        return [row[0] for row in self.cur.fetchall()]

    def insert_client(self, uuid, username: str, last_seen: str):
        print("in insert_client")
        query = """INSERT INTO clients VALUES(?, ?, null, ?, null);"""
        self.cur.execute(query, (uuid, username, last_seen))
        self.conn.commit()


class Server:
    HOSTNAME = "MAMMAN15"
    DEFAULT_PORT = 1234
    REQUEST_CODE_MAPPING = {
        1100: '_handle_registration',
        1101: '_handle_public_key',
        1103: '_handle_file_upload',
        None: '_handle_invalid_code'
    }

    def __init__(self):
        self.port = self._init_port()
        self.dbmanager = DBManager(DB_SERVER)

    def _init_port(self):
        try:
            with open(PORT_FILE_PATH, 'r') as f:
                port = int(f.read())
        except (FileNotFoundError, ValueError) as error:
            print(f"warning! {error}. using {self.DEFAULT_PORT}")
            port = self.DEFAULT_PORT
        return int(port)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', self.port))
            s.listen()
            conn, addr = s.accept()
            print(f"conn from {addr}")
            while True:
                header = self._parse_request_header(conn.recv(REQUEST_HEADER_LENGTH))
                resp = self._handle_request(header, conn)
                print(f"received: {header}")
                conn.send(resp)

    @staticmethod
    def _parse_request_header(header: bytes) -> RequestHeader:
        ver, code, payload_size = struct.unpack_from(REQUEST_HDR_FORMAT_NO_UUID, header, offset=UUID_LEN)
        client_id = UUID(bytes_le=header[:UUID_LEN])
        return RequestHeader(client_id, ver, code, payload_size)

    def _handle_request(self, header, conn):
        func = getattr(self, self.REQUEST_CODE_MAPPING.get(header.code))
        return func(header, conn)

    def _handle_registration(self, request_header: RequestHeader, conn) -> bytes:
        """
        - read payload
        - check if user exists
        - generate UUID
        - insert to db
        - return resp
        """
        payload = conn.recv(min(request_header.payload_size, NAME_FIELD_LEN))
        name = payload.decode('ascii')
        if self.dbmanager.has_username(name):
            resp = self._get_failure_resp()
            return resp
        now = datetime.datetime.now().strftime(DATE_FORMAT)
        client_uuid = self.dbmanager.generate_uuid()
        self.dbmanager.insert_client(client_uuid, name, now)
        resp = self._get_registration_success_resp(client_uuid, SERVER_VERSION)
        return resp

    def _get_failure_resp(self):
        pass

    def _get_registration_success_resp(self, client_uuid: str, server_ver: int):
        response_hdr_bytes = struct.pack(RESPONSE_HEADER_FORMAT,
                                         SERVER_VERSION,
                                         REGISTRATION_SUCCESS_CODE,
                                         UUID_LEN)
        response_payload = UUID('{' + client_uuid + '}').bytes_le
        return response_hdr_bytes + response_payload


def main():
    server = Server()
    server.run()


if __name__ == '__main__':
    main()
