import re
import socket

HOST = "127.0.0.1"
PORT = 50938

session_token = None

def framed_send(sock, payload: str):
    payload_bytes = payload.encode()
    msg = f"LEN:{len(payload_bytes)}\n".encode() + payload_bytes
    sock.sendall(msg)

def show_help():
    print("============================================================")
    print("IE2102 Secure TCP Client")
    print("Commands you can type:")
    print("  REGISTER <username> <password>")
    print("  LOGIN <username> <password>")
    print("  LOGOUT")
    print("  WHOAMI")
    print("  ECHO <message>")
    print("  HELP")
    print("  EXIT")
    print("============================================================")

def build_payload(user_input: str):
    global session_token

    text = user_input.strip()
    if not text:
        return None

    parts = text.split(maxsplit=1)
    cmd = parts[0].upper()

    if cmd == "LOGOUT":
        if not session_token:
            print("Client: no active token. Please LOGIN first.")
            return None
        return f"LOGOUT {session_token}"

    if cmd == "WHOAMI":
        if not session_token:
            print("Client: no active token. Please LOGIN first.")
            return None
        return f"WHOAMI {session_token}"

    if cmd == "ECHO":
        if not session_token:
            print("Client: no active token. Please LOGIN first.")
            return None
        if len(parts) < 2:
            print("Client: usage -> ECHO <message>")
            return None
        return f"ECHO {session_token} {parts[1]}"

    return text

def display_response(resp: str):
    global session_token
    line = resp.strip()

    token_match = re.search(r"TOKEN:([A-Za-z0-9]+)", line)
    if token_match:
        session_token = token_match.group(1)
        line = re.sub(r"\s*TOKEN:[A-Za-z0-9]+", "", line)
        print(f"Server: {line}")
        print("Client: session token stored.")
        return

    if "LOGOUT_SUCCESS" in line or "Logged out successfully." in line:
        session_token = None

    print(f"Server: {line}")

def main():
    global session_token

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        print(f"Connected to {HOST}:{PORT}")
        show_help()

        while True:
            user_input = input("> ").strip()

            if user_input.lower() == "exit":
                print("Client closed.")
                break

            if user_input.lower() == "help":
                show_help()
                continue

            payload = build_payload(user_input)
            if payload is None:
                continue

            framed_send(client, payload)
            response = client.recv(4096).decode(errors="ignore")
            if not response:
                print("Server disconnected.")
                break

            display_response(response)

if __name__ == "__main__":
    main()
