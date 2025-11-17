# chat_server.py - server percakapan dengan DES + distribusi kunci via rsa

import socket
import sys
import threading
import os

from DES import encrypt_text_with_trace, decrypt_text_with_trace
import rsa

# Prefix khusus untuk pesan distribusi kunci
KEYX_PREFIX = "KEYX:"

# Kunci sesi DES (akan terisi setelah key exchange)
SESSION_KEY_HEX = None

# Konfigurasi default host dan port
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000


def generate_des_session_key():
    """Bangkitkan kunci DES 64-bit (8 byte) dan kembalikan dalam bentuk hex 16 karakter."""
    key_bytes = os.urandom(8)  # 8 byte = 64 bit
    return key_bytes.hex().upper()


def send_des_key_via_rsa(conn):
    """Server membangkitkan kunci DES lalu mengirimkannya ke client via rsa.

    Langkah:
      1. Generate session key DES.
      2. Ambil kunci publik client dari "Public Key Authority" (rsa.get_public_key).
      3. Enkripsi session key DES dengan rsa (encrypt_int).
      4. Kemas ciphertext jadi string heksadesimal dan kirim dengan prefix KEYX:.
    """
    global SESSION_KEY_HEX

    # 1) generate kunci sesi DES
    SESSION_KEY_HEX = generate_des_session_key()
    key_bytes = bytes.fromhex(SESSION_KEY_HEX)
    m_int = int.from_bytes(key_bytes, "big")

    # 2) ambil kunci publik client dari PKA
    client_pub = rsa.get_public_key("client")  # (n, e)

    # 3) enkripsi kunci DES memakai rsa
    c_int = rsa.encrypt_int(m_int, client_pub)

    # Ubah ciphertext integer menjadi string hex (tanpa 0x)
    cipher_hex = format(c_int, "X")

    # 4) kirim ke client
    msg = f"{KEYX_PREFIX}{cipher_hex}\n"
    conn.sendall(msg.encode())

    print("\n[Key Exchange] Mengirim session key DES ke client (rsa)")
    print(f"[Key Exchange] DES key (hex)      : {SESSION_KEY_HEX}")
    print(f"[Key Exchange] rsa cipher (hex)   : {cipher_hex}")


def recv_loop(conn):
    """Loop penerima pesan dari client (ciphertext DES)."""
    global SESSION_KEY_HEX
    buffer = b""  # buffer untuk kumpulkan data sampai newline

    while True:
        chunk = conn.recv(4096)
        if not chunk:
            print("\n[Disconnected]")
            break
        buffer += chunk

        # Proses per-baris dipisahkan dengan newline
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            try:
                cipher_hex = line.decode().strip()
                if not cipher_hex:
                    continue

                if SESSION_KEY_HEX is None:
                    print("\n[Warning] Pesan masuk sebelum session key siap.")
                    print(" Raw cipher:", cipher_hex)
                    continue

                # Dekripsi dengan DES
                plaintext, trace = decrypt_text_with_trace(cipher_hex, SESSION_KEY_HEX)

                print("\n--- Decrypt Process (Server) ---")
                print(trace)
                print(f"<peer> {plaintext}")
            except Exception as exc:
                print(f"\n[Decode error] {exc} (raw={line!r})")


def main():
    """Fungsi utama server."""
    global SESSION_KEY_HEX

    # Baca argumen host & port jika ada
    if len(sys.argv) == 1:
        host, port = DEFAULT_HOST, DEFAULT_PORT
    elif len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print("Usage: python chat_server.py [host port]")
        sys.exit(1)

    # Siapkan socket TCP
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(1)

    print(f"[Listening] {host}:{port} ...")

    # Tunggu client terhubung
    conn, addr = srv.accept()
    print(f"[Connected] from {addr}")

    # Lakukan distribusi kunci DES via rsa
    send_des_key_via_rsa(conn)

    # Jalankan thread terpisah untuk menerima pesan
    t = threading.Thread(target=recv_loop, args=(conn,), daemon=True)
    t.start()

    # Loop utama untuk mengirim pesan ke client
    try:
        while True:
            msg = input("> ")
            if not msg:
                continue

            if SESSION_KEY_HEX is None:
                print("[Error] Session key belum siap, tidak bisa enkripsi pesan.")
                continue

            try:
                cipher_hex, trace = encrypt_text_with_trace(msg, SESSION_KEY_HEX)

                print("\n--- Encrypt Process (Server) ---")
                print(trace)

                conn.sendall(cipher_hex.encode() + b"\n")
            except Exception as exc:
                print(f"[Encrypt/Send error] {exc}")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        # Tutup koneksi dan socket
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        conn.close()
        srv.close()
        print("\n[Server closed]")


if __name__ == "__main__":
    main()
