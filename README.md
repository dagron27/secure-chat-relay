# Secure Chat Relay

![CI](https://github.com/dagron27/secure-chat-relay/actions/workflows/ci.yml/badge.svg)

**Course:** `CSCI 312, Distributed Systems, Spring 2025`

**Assignment:** `csci312_chat_system` — "Secure Multi-Client-Server Chat
Application with Authentication."

The original folder name (`csci312_chat_system`) just describes the course it was written
for. "Secure Chat Relay" is used here instead because it describes what the code actually
does: a TLS-wrapped TCP socket connection where messages are relayed through a human
operator at the server terminal, rather than a real multi-user broadcast chat (see
[Security Findings](#security-findings), Informational note below). If you'd rather keep
the academic origin visible (e.g., for a transcript/portfolio link),
`csci312-secure-chat-relay` is a reasonable alternative. Avoid renaming it to anything
implying group chat or broadcast messaging until that feature actually exists.

## Assignment Intent

The assignment asked students to take an existing basic single-client chat
system and expand it into a secure, authenticated, multi-client one. Its
graded requirements, cross-checked directly against this code:

- **Architecture -- client/server, multiple clients connecting to a central
  server.** Confirmed: `src/server.py` accepts concurrent connections and spawns
  a dedicated `handle_client` thread per connection (line 192), plus separate
  `response_thread` and `logging_thread` threads. Multiple clients can be
  connected at once.
- **Socket programming -- TCP via Python's `socket` library.** Confirmed,
  wrapped in TLS (see Security Findings).
- **Message protocol -- simple text-based exchange.** Confirmed: plain text
  messages, no binary framing beyond a fixed read size.
- **Concurrency -- threading.** Confirmed, per the architecture point above.
- **Error handling.** Confirmed as reasonably robust: `src/server.py` and
  `src/client.py` each have roughly eight to nine `except` blocks, including an
  explicit `(ConnectionResetError, ssl.SSLError)` catch around the per-client
  loop so an unexpected disconnect doesn't take the whole server down.
- **CLI for both client and server.** Confirmed -- both are plain terminal
  programs, no GUI.
- **Logging.** Confirmed: `logging.basicConfig` is configured at INFO level
  with a timestamp format, and a `log_queue` mechanism records connection
  opens, authentication failures, and connection closes to the server's
  console via a dedicated logging thread.
- **Authentication enhancement (the assignment's specific "expand upon" ask)
  and the "secure" framing from its own title.** This is where the codebase
  goes beyond the baseline checklist above, not just meets it: TLS-wrapped
  sockets (with real certificate verification as of this repo's security
  remediation pass -- see Security Findings), salted PBKDF2-HMAC-SHA256
  password hashing rather than plaintext, per-IP rate limiting/lockout after
  repeated failed logins, and a one-time randomly generated bootstrap
  credential instead of hardcoded defaults.
- **Open question, not a clear gap: true multi-client chat (clients talking
  to each other).** The assignment's deliverable list describes "message
  exchange between clients and the server," not explicitly client-to-client
  messaging. What's actually built is closer to the literal reading: each
  connected client exchanges messages one-to-one with the server (here, a
  human operator typing replies), rather than every client seeing every
  other client's messages. Whether the original grading expected true
  broadcast/group chat isn't something the code alone can answer --
  documented here as an open question rather than assumed either way.

One process note: this was built iteratively, but that iteration isn't
visible in this archive -- there's no commit history preserved in this
checkout, so the working copy here is a single snapshot of the final state,
not a record of the development process.

## Overview

- A server (`src/server.py`) listens on `localhost:5555` over a TLS-wrapped TCP socket.
- Each connecting client (`src/client.py`) is prompted for a username and password, checked
  against `src/user_manager.py`'s salted PBKDF2-HMAC-SHA256 store (`users.json`).
- After authenticating, a client can send text messages. Each message is placed on a
  shared queue and printed to the server's terminal; a person sitting at the server types
  a reply by hand, which is sent back to that one client.
- There is no message history, no persistence of chat content, and no relay between two
  clients: the server operator is effectively a single manual "chat partner" for everyone
  connected.

## Dependencies

None outside the Python standard library. `src/server.py`, `src/client.py`, and `src/user_manager.py`
only import `socket`, `threading`, `signal`, `sys`, `time`, `logging`, `queue`, `ssl`, `re`,
`hashlib`, `os`, `json`, and `secrets` — all part of core Python. There is no real
`requirements.txt` to install from; the placeholder file in this repo exists purely to
document that fact for tooling that expects one to be present.

## Environment Setup

**Requirements**

- Python 3.8 or newer (the code uses f-strings and `hashlib.pbkdf2_hmac`; developed/tested
  against Python 3.12).
- OpenSSL (or any tool that can produce a PEM certificate/key pair), used once to generate
  the self-signed TLS certificate the server loads at startup.
- No specific OS requirement; uses only cross-platform standard library APIs.

**Steps**

1. Generate a self-signed certificate and key in the project directory (both are
   gitignored, so this must be done locally before the server will start):

   ```
   openssl req -x509 -newkey rsa:2048 -nodes -out server.cert -keyout server.key -days 365
   ```

2. Start the server:

   ```
   python src/server.py
   ```

   On first run (no `users.json` present yet) the server creates exactly one
   account, username `admin`, with a random password generated via Python's
   `secrets` module. The username and password are printed once to the
   server's console — save them immediately, since the password is not
   stored anywhere in plaintext and will not be shown again. See
   [Security Findings](#security-findings) below, item 2, for why this
   replaced the old fixed demo accounts (`test/test`, `user1/password1`,
   `user2/password2`).

3. In a separate terminal, start one or more clients:

   ```
   python src/client.py
   ```

   Log in with the one-time account printed by the server on first run (or any
   account created since), then type messages. Whoever is running
   `src/server.py` sees each message printed to their terminal and must type a response there
   for it to reach that client. Type `logoff` on the client to disconnect.

## Repository Organization

The original submission had `client.py`, `server.py`, and
`user_manager.py` sitting directly at the repository root, and the
report PDFs at the repository root rather than in `docs/`. Both have
been reorganized for portfolio-wide consistency with sibling
repositories: the three `.py` files moved into `src/`, and the reports
moved into `docs/`. `.github/workflows/ci.yml` and this README were
updated to match; the app is still invoked from the repository root
(`python src/server.py`, not `cd src`), so `server.py`'s
`load_cert_chain("server.cert", "server.key")` calls, relative to the
working directory, keep resolving to the certificate generated in step
1 above.

## Continuous Integration

A GitHub Actions workflow (`.github/workflows/ci.yml`) compile-checks
all three source files, generates a throwaway self-signed certificate,
starts the server, and verifies it stays alive and binds its port (see
Known Issues below for why it stops short of a full authenticated login
round trip). One difference from the certificate command documented in
step 1 above is necessary for CI specifically: CI's `openssl req`
invocation adds `-subj "/CN=localhost"`, which this README's local
command does not. `openssl req` without `-subj` prompts interactively
for certificate subject fields on stdin -- fine for a human running the
command locally, but CI's stdin is closed, so the step failed
immediately until `-subj` was added to skip the prompt. If you want the
exact non-interactive command, use the one in `.github/workflows/ci.yml`
instead of the one in step 1.

## Known Issues

This project ended at the end of the course; nobody is actively working on it. The lists
below are meant as a map for anyone (including a future version of the original author)
who picks it back up. Most of the security items were already called out informally in
code comments by the original author (e.g. notes like "Currently false for development"
next to the TLS settings) — this section makes that existing self-documentation explicit
and complete rather than presenting these as newly discovered problems. A few additional
items not previously called out in-code are marked "(new in this review)" below.

### Dead Code

- **FIXED.** `src/user_manager.py` had two commented-out debug `print()` calls left over from
  development (`authenticate()`, around the salt/hash comparison logic — the lines
  printing "Stored data" and "Calculated hash"/"Stored hash"). These were removed as part
  of the `authenticate()` rewrite described under Security Findings item 5 below, which
  also replaced the active `print()` calls with a single `logging.debug(...)` call.

### Security Findings

Severity labels below are relative to this project's actual purpose (a classroom
networking exercise), not a production chat product.

0. **[Informational, PII] PII exposure in `docs/Report Part 1.pdf`,
   `docs/Report Part 2 Chat System Authentication.pdf`, and
   `docs/Report Part 2 Chat System Security.pdf`. FIXED.** All three PDFs
   contained a PII exposure, found and remediated. True-redacted via
   PyMuPDF (search + black-fill annotation + apply-redactions), verified
   via re-extracted text showing zero remaining hits and an intact page
   count for each file.

1. **[High] TLS verification is disabled. FIXED.** `src/client.py` previously set
   `check_hostname = False` and `verify_mode = ssl.CERT_NONE`, meaning it could not detect
   a machine-in-the-middle during the TLS handshake. It now sets `verify_mode =
   ssl.CERT_REQUIRED` and calls `context.load_verify_locations("server.cert")`, pinning
   trust to the specific self-signed certificate this project generates (see Environment
   Setup) rather than trusting nothing or requiring a public CA (which a self-signed cert
   can never satisfy). If `server.cert` is missing, the client now fails with a clear
   error instead of an unverified connection or a raw traceback. `check_hostname` is
   intentionally left `False`: the cert generated by the README's `openssl` command has no
   guaranteed Subject Alternative Name for "localhost", so turning hostname checking on
   too could break the handshake depending on how the cert was generated locally. `src/server.py`'s
   own `check_hostname = False` / `verify_mode = ssl.CERT_NONE` (used for the server-side
   context with `Purpose.CLIENT_AUTH`) is unchanged — this project does not use client
   certificates, so that setting is inert rather than a real gap.

2. **[High] Hardcoded default credentials. FIXED.** `src/user_manager.py`'s
   `_initialize_default_users()` used to seed `users.json` with three known demo
   passwords (`test/test`, `user1/password1`, `user2/password2`) on first run. It has been
   replaced with `_initialize_first_run_user()`, which runs only when no users exist yet
   and creates exactly one account (username `admin`) with a password generated via
   `secrets.token_urlsafe(12)`. The username and password are printed to the console once,
   with a clear "save this now" message, and are never written anywhere in plaintext. There
   is no separate registration/signup flow in `src/client.py` or `src/server.py` to hook into
   instead — this one-time console credential is the only way to obtain the first login.

3. **[Medium] No rate limiting or lockout on login attempts. FIXED.** `src/server.py`'s
   `authenticate()` now tracks failed login attempts per connecting IP address in an
   in-memory dict guarded by a lock. After 5 failed attempts from the same IP, further
   connection attempts from that IP are rejected outright (with a message back to the
   client) for a 60-second lockout window; a successful login clears the counter for that
   IP. This is intentionally simple (in-memory, per-process, not persisted across
   restarts) — not a production rate-limiter, but enough to blunt naive online
   password guessing against this project's login flow.

4. **[Medium] Unbounded message queue. FIXED.** `src/server.py`'s `message_queue` is now
   created with `queue.Queue(maxsize=1000)` instead of an unbounded queue. Producers
   (client handler threads) will now block on `.put()` once the queue is full, applying
   natural backpressure instead of growing memory without bound if clients send messages
   faster than the operator can reply.

5. **[Low] Login attempts logged in plaintext, aiding username enumeration. FIXED.**
   `src/user_manager.py`'s `authenticate()` no longer uses `print()` for login attempts. It now
   makes a single `logging.debug(...)` call after the outcome is determined, reporting
   only success/failure without a separate "user not found" branch, so server console
   output no longer makes it easy to distinguish an unknown username from a wrong
   password. Debug-level logs are not shown under the server's default `INFO` logging
   configuration.

6. **[Low] Operator terminal is not protected against escape-sequence injection. FIXED.**
   `src/server.py` now has a `sanitize_for_terminal()` helper that strips ANSI escape
   sequences and any other characters outside the printable ASCII range (plus tabs) from
   client-supplied text. It is applied to the username and the message text before either
   is placed on `log_queue` (i.e. before `handle_logging()` prints it), so a client can no
   longer send terminal control sequences that get interpreted by the operator's terminal
   emulator.

7. **[Informational] Session identity is just the raw socket object; no per-message
   identity check.** `src/server.py` tracks connected clients as a bare list of sockets
   (`clients = []`, line 28) and `handle_client()`/`authenticate()` operate directly on
   that socket with no separate session token or identity binding. This is fine today
   because there is no message fan-out between clients (see Overview) — there is nothing
   for a forged identity to impersonate. It is called out here because it would become a
   real spoofing/authorization concern if group chat or any multi-client message routing
   (see item 8) is ever implemented; at that point each outgoing message would need a
   verified sender identity independent of "whichever socket the bytes arrived on."

8. **[Informational] No real group chat.** `handle_responses()` in `src/server.py` routes
   every incoming message to one shared queue, answered one at a time by a human typing
   into the server's own terminal. Clients never see each other. This is a design
   limitation rather than a vulnerability by itself, but it is the reason item 7 above is
   only informational today. **Fix-it plan (if this feature is ever added):** replace the
   queue/`input()` pattern with a fan-out — when a client thread receives a message,
   iterate over the `clients` list and write it to every other connected socket. Add
   per-client nicknames/identities so recipients know who sent what (see item 7), and
   guard `clients` with a lock since it is currently mutated from multiple threads without
   one.

9. **[Informational] Shutdown can hang.** `signal_handler()` calls `sys.exit(0)` on
   Ctrl+C, but `response_thread` is a non-daemon thread blocked on `input()`, so the
   process can sit there until someone presses Enter at the server terminal. **Fix-it
   plan:** either make the worker threads daemon threads, or have `handle_responses` poll
   with a timeout / check `shutdown_flag` instead of blocking indefinitely on `input()`.

10. **[Informational] Fixed 1024-byte reads.** Both `src/server.py` and `src/client.py` call
    `recv(1024)` and treat whatever comes back as one complete message, with no
    length-prefixing or buffering. Longer messages will be silently truncated or split
    across reads. **Fix-it plan:** add simple length-prefixed framing (e.g., send a 4-byte
    length header before each payload) or delimit messages and buffer until a full message
    is seen.

**Confirmed not present.** This review specifically checked for, and did not find: SQL/NoSQL
injection (no database queries anywhere in the codebase), command injection (`subprocess`
is never imported or used), insecure deserialization (no `pickle`, `eval`, or `exec` calls),
and hardcoded API keys or tokens. Password storage uses salted PBKDF2-HMAC-SHA256 with
100,000 iterations (`src/user_manager.py`, `_add_user()`/`authenticate()`) — not plaintext and
not a weak/fast hash.

None of the findings above are "bugs" in the sense of failing the assignment — they're the
kind of simplification that's normal and expected in a first networking project. They're
recorded here so that if this code is ever extended, the extension starts from an accurate
understanding of what it currently does rather than what its name implies.

## Status

**Archived student project, not maintained.**

This repository is a snapshot of a school assignment. It works well enough to demonstrate
the concepts it was built to practice (TCP sockets, threading, TLS, salted password
hashing), but it is not a finished chat application and was never revisited after the
course ended. Treat it as a learning artifact, not a starting point for a real chat
product, without the fixes described in [Known Issues](#known-issues) above.
