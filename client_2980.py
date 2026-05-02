import socket

HOST = "127.0.0.1"
PORT = 50980

def send_framed(sock, payload):
    payload_bytes = payload.encode()
    header = f"LEN:{len(payload_bytes)}\n".encode()
    sock.sendall(header + payload_bytes)

def recv_response(sock):
    data = sock.recv(4096)
    return data.decode()

def main():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect((HOST, PORT))
        print("Connected to server")

        while True:
            user_input = input("Enter command (or quit): ").strip()
            if user_input.lower() == "quit":
                break

            send_framed(client, user_input)
            response = recv_response(client)
            print("Server response:")
            print(response)

    except Exception as e:
        print("Error:", e)

    finally:
        client.close()

if __name__ == "__main__":
    main()
