import os
import socket
import threading
import json
import base64
import os
from Crypto.Cipher import AES
from pqcrypto.kem.ml_kem_1024 import encrypt

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 25572

lock = threading.Lock()

DATA_FOLDER = "userdata"  # Your user folder, will also store groups/messages

if not os.path.exists(DATA_FOLDER):
    os.makedirs(DATA_FOLDER)

def save(name, data):
    path = os.path.join(DATA_FOLDER, f"{name}.json")
    with open(path, "w") as f:
        json.dump(data, f)

def load(name):
    path = os.path.join(DATA_FOLDER, f"{name}.json")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

groups = {}
messages = {}

def generate_aes256_key():
    return os.urandom(32)

def handle_client(conn, addr):
    print(f"Client connected: {addr}")
    buffer = ""
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            # Decode bytes to string with error handling
            try:
                buffer += data.decode('utf-8')
            except UnicodeDecodeError as e:
                print(f"UTF-8 decode error from {addr}: {e}")
                # skip this chunk, continue reading more data
                continue

            # Process all full messages separated by newline
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip():
                    continue
                try:
                    req = json.loads(line)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error from {addr}: {e}")
                    continue  # skip this line and continue

                # Now safely handle the parsed JSON command
                cmd = req.get("cmd")

                if cmd == "create_group":
                    group_name = req.get("name")
                    if not group_name:
                        conn.sendall(b"ERR\n")
                        continue

                    with lock:
                        if group_name in groups:
                            conn.sendall(b"ERR:GROUP_EXISTS\n")
                        else:
                            key = generate_aes256_key()
                            groups[group_name] = {"aes_key": base64.b64encode(key).decode()}
                            messages[group_name] = []
                            save("groups", groups)
                            save("messages", messages)
                            conn.sendall(b"OK\n")

                elif cmd == "request_group_key":
                    group_name = req.get("name")
                    client_kyber_pub_b64 = req.get("kyber_pub")
                    if not group_name or not client_kyber_pub_b64:
                        conn.sendall(b"ERR\n")
                        continue

                    with lock:
                        if group_name not in groups:
                            conn.sendall(b"ERR:GROUP_NOT_FOUND\n")
                            continue
                        aes_key_b64 = groups[group_name]["aes_key"]

                    try:
                        client_kyber_pub = base64.b64decode(client_kyber_pub_b64)
                        ciphertext, secret = encrypt(client_kyber_pub)
                        aes_key_bytes = base64.b64decode(aes_key_b64)

                        cipher = AES.new(secret, AES.MODE_GCM)
                        wrapped_ciphertext, tag = cipher.encrypt_and_digest(aes_key_bytes)
                        wrapped = cipher.nonce + tag + wrapped_ciphertext

                        response = {
                            "ciphertext": base64.b64encode(ciphertext).decode(),
                            "wrapped": base64.b64encode(wrapped).decode()
                        }
                        conn.sendall((json.dumps(response) + '\n').encode())
                    except Exception as e:
                        print(f"Kyber encapsulation error: {e}")
                        conn.sendall(b"ERR\n")

                elif cmd == "send":
                    group_name = req.get("name")
                    msg = req.get("message")
                    username = req.get("username", "unknown")
                    if not group_name or msg is None:
                        conn.sendall(b"ERR\n")
                        continue

                    with lock:
                        if group_name not in messages:
                            messages[group_name] = []
                        messages[group_name].append({"username": username, "text": msg})
                        if len(messages[group_name]) > 1000:
                            messages[group_name] = messages[group_name][-1000:]
                        save("messages", messages)
                    conn.sendall(b"OK\n")

                elif cmd == "fetch_messages":
                    group_name = req.get("name")
                    if not group_name:
                        conn.sendall(b"ERR\n")
                        continue

                    with lock:
                        last_msgs = messages.get(group_name, [])
                        last_msgs = last_msgs[-100:]
                    conn.sendall((json.dumps(last_msgs) + '\n').encode())

                else:
                    conn.sendall(b"ERR\n")

    except Exception as e:
        print(f"Client handler error: {e}")
    finally:
        conn.close()
        print(f"Client disconnected: {addr}")


def main():
    global groups, messages
    groups = load("groups")
    messages = load("messages")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen()
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
