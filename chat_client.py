# chat_client.py - client percakapan dengan DES + distribusi kunci via rsa

import socket
import sys
import threading

from DES import encrypt_text, decrypt_text
import rsa

# Prefix khusus untuk pesan distribusi kunci
KEYX_PREFIX = "KEYX:"

# Kunci sesi DES (akan terisi setelah key exchange)
SESSION_KEY_HEX = None

# Konfigurasi default alamat server
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000


def handle_key_exchange_message(text: str):
    """Memproses pesan KEYX dari server untuk mendapatkan session key DES.

    Format pesan dari server:
        KEYX:<cipher_hex>
    di mana cipher_hex adalah ciphertext rsa dalam heksadesimal.
    """
    global SESSION_KEY_HEX

    cipher_hex = text[len(KEYX_PREFIX):]  # buang prefix "KEYX:"
    if not cipher_hex:
        print("[Key Exchange] Pesan KEYX tanpa isi.")
        return

    try:
        # Ubah ciphertext dari hex -> integer
        c_int = int(cipher_hex, 16)

        # Dekripsi dengan kunci privat milik client
        m_int = rsa.decrypt_int(c_int, rsa.CLIENT_PRIVATE_KEY)

        # Session key DES = 8 byte
        key_bytes = m_int.to_bytes(8, "big")
        SESSION_KEY_HEX = key_bytes.hex().upper()

        print("\n[Key Exchange] Session key DES diterima dari server (rsa)")
        print(f"[Key Exchange] DES key (hex): {SESSION_KEY_HEX}")
    except Exception as exc:
        print(f"[Key Exchange ERROR] {exc}")


def recv_loop(sock):
    """Loop penerima pesan dari server."""
    global SESSION_KEY_HEX
    buffer = b""  # buffer untuk kumpulkan data sampai newline

    while True:
        chunk = sock.recv(4096)
        if not chunk:
            print("\n[Disconnected]")
            break
        buffer += chunk

        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            try:
                text = line.decode().strip()
                if not text:
                    continue

                # Pesan khusus untuk distribusi kunci
                if text.startswith(KEYX_PREFIX):
                    handle_key_exchange_message(text)
                    continue

                # Sisanya dianggap ciphertext DES
                if SESSION_KEY_HEX is None:
                    print("\n[Warning] Cipher diterima tetapi session key belum ada.")
                    print(" Raw cipher:", text)
                    continue

                plaintext = decrypt_text(text, SESSION_KEY_HEX)
                print(f"\n<peer>: {plaintext}")
            except Exception as exc:
                print(f"\n[Decode error] {exc} (raw={line!r})")


def main():
    """Fungsi utama client."""
    global SESSION_KEY_HEX

    # Baca host & port server
    if len(sys.argv) == 1:
        host, port = DEFAULT_HOST, DEFAULT_PORT
    elif len(sys.argv) == 3:
        host = sys.argv[1]
        port = int(sys.argv[2])
    else:
        print("Usage: python chat_client.py [server_host port]")
        sys.exit(1)

    # Koneksi ke server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[Connected] to {host}:{port}")

    # Thread untuk menerima pesan
    t = threading.Thread(target=recv_loop, args=(sock,), daemon=True)
    t.start()

    # Loop utama: kirim pesan ke server
    try:
        while True:
            msg = input("> ")
            if not msg:
                continue

            if SESSION_KEY_HEX is None:
                print("[Info] Session key belum diterima, tunggu pesan [Key Exchange].")
                continue

            try:
                cipher_hex = encrypt_text(msg, SESSION_KEY_HEX)
                sock.sendall(cipher_hex.encode() + b"\n")
            except Exception as exc:
                print(f"[Encrypt/Send error] {exc}")
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        sock.close()
        print("\n[Client closed]")


if __name__ == "__main__":
    main()
