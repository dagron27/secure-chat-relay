import socket
import threading
import signal
import sys, time
import logging
import queue
import ssl
import re
from user_manager import UserManager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Server setup
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 5555))
server.listen(5)
server.settimeout(1)  # Set a timeout for the accept call

# Set up SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.cert", keyfile="server.key")
context.check_hostname = False #Currently false for development
context.verify_mode = ssl.CERT_NONE

logging.info("Secure server is listening on port 5555...")

clients = []
shutdown_flag = False
# Bounded so a flood of client messages (faster than the operator can type
# replies) can't grow memory without limit.
message_queue = queue.Queue(maxsize=1000)
log_queue = queue.Queue()
user_manager = UserManager()

# --- Simple per-IP failed-login lockout -------------------------------
# Not a production rate-limiter: a small in-memory counter keyed on the
# connecting IP address, meant to blunt naive online password guessing
# against this project's login flow.
FAILED_ATTEMPT_LIMIT = 5
LOCKOUT_SECONDS = 60
_failed_attempts_lock = threading.Lock()
_failed_attempts = {}  # ip -> {"count": int, "locked_until": float}


def _is_locked_out(ip):
    with _failed_attempts_lock:
        entry = _failed_attempts.get(ip)
        if entry and entry["locked_until"] > time.time():
            return True
        return False


def _record_failed_attempt(ip):
    with _failed_attempts_lock:
        entry = _failed_attempts.setdefault(ip, {"count": 0, "locked_until": 0})
        entry["count"] += 1
        if entry["count"] >= FAILED_ATTEMPT_LIMIT:
            entry["locked_until"] = time.time() + LOCKOUT_SECONDS
            entry["count"] = 0


def _record_successful_attempt(ip):
    with _failed_attempts_lock:
        _failed_attempts.pop(ip, None)


_CONTROL_CHARS_RE = re.compile(r'[^\x20-\x7E\t]')
_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def sanitize_for_terminal(text):
    """Strip ANSI escape sequences and other non-printable characters from
    client-supplied text before it is printed to the operator's terminal,
    to prevent terminal/escape-sequence injection."""
    if not isinstance(text, str):
        return text
    text = _ANSI_ESCAPE_RE.sub('', text)
    return _CONTROL_CHARS_RE.sub('', text)


def authenticate(client_socket, client_address):
    ip = client_address[0]

    if _is_locked_out(ip):
        try:
            client_socket.send(
                "Too many failed login attempts. Try again later.\n".encode('utf-8')
            )
        except Exception:
            pass
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()
        return False

    client_socket.send("Username: ".encode('utf-8'))
    username = client_socket.recv(1024).decode('utf-8')
    client_socket.send("Password: ".encode('utf-8'))
    password = client_socket.recv(1024).decode('utf-8')

    if user_manager.authenticate(username, password):
        _record_successful_attempt(ip)
        client_socket.send("Authentication successful\n".encode('utf-8'))
        log_queue.put(f"Authentication successful for user: {sanitize_for_terminal(username)}")
        return True
    else:
        _record_failed_attempt(ip)
        client_socket.send("Authentication failed\n".encode('utf-8'))
        # Remove from clients list before closing
        if client_socket in clients:
            clients.remove(client_socket)
        client_socket.close()
        return False

def handle_client(client_socket, client_address):
    log_queue.put(f"Secure connection from {client_address} has been established.")
    if not authenticate(client_socket, client_address):
        log_queue.put(f"Authentication failed for {client_address}. Connection closed.")
        return

    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if not message:
                break
            if message.lower() == "logoff":
                break
            log_queue.put(f"Client {client_address}: {sanitize_for_terminal(message)}")
            message_queue.put((client_socket, message))
        except (ConnectionResetError, ssl.SSLError):
            break
    client_socket.close()
    clients.remove(client_socket)
    log_queue.put(f"Connection from {client_address} has been closed.")

def handle_responses():
    while not shutdown_flag:
        try:
            if not message_queue.empty():
                print("Enter response: ", end='', flush=True)
                client_socket, message = message_queue.get(timeout=1)
                response = input()
                client_socket.send(response.encode('utf-8'))
            else:
                # No messages to respond to, short sleep to prevent CPU spinning
                time.sleep(0.1)
        except queue.Empty:
            continue

def handle_logging():
    while not shutdown_flag:
        try:
            log_message = log_queue.get(timeout=1)
            print(f"\r{log_message}", flush=True)
        except queue.Empty:
            continue

def signal_handler(sig, frame):
    global shutdown_flag
    log_queue.put("Shutting down secure server...")
    shutdown_flag = True
    for client in clients[:]:  # Create a copy of the list to iterate over
        try:
            client.send("Server is shutting down...".encode('utf-8'))
        except:
            # Skip errors for closed sockets
            pass
        finally:
            try:
                client.close()
            except:
                pass
    server.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

response_thread = threading.Thread(target=handle_responses)
response_thread.start()

logging_thread = threading.Thread(target=handle_logging)
logging_thread.start()

while not shutdown_flag:
    try:
        # Accept connection
        client_socket, client_address = server.accept()
        # Wrap socket with SSL
        secure_socket = context.wrap_socket(client_socket, server_side=True)
        clients.append(secure_socket)
        client_thread = threading.Thread(target=handle_client, args=(secure_socket, client_address))
        client_thread.start()
    except socket.timeout:
        continue
    except ssl.SSLError as e:
        log_queue.put(f"SSL Error: {e}")
    except Exception as e:
        log_queue.put(f"Error: {e}")
        break

server.close()