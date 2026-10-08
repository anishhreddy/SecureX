# SecureX

A local/LAN academic prototype for one-to-one, real-time encrypted text and image messaging, plus reproducible security and traffic experiments.

## Architecture

- React + Vite frontend, served on `0.0.0.0` for a second LAN device.
- Express, Socket.IO and MongoDB backend.
- Argon2id password hashes; JWT authenticated API/session.
- Each browser generates an RSA-OAEP key pair. Its private key is AES-GCM encrypted with a PBKDF2-derived key locally; only its public key reaches the server.
- Every payload uses a fresh AES-256-GCM key and 96-bit random IV. The payload key is RSA-OAEP wrapped for both participants. MongoDB and Socket.IO only receive encrypted payload data and wrapped symmetric keys.

## Start

1. Copy `.env.example` to `backend/.env` and set a long `JWT_SECRET`.
2. Ensure the installed MongoDB Windows service is running.
3. Install dependencies once: `npm run install:all`.
4. Run both services: `npm run dev`.
5. Open `http://localhost:5173` and register Alice. Use another browser/device to register Bob.

For a second device, run `ipconfig`, find the host's IPv4 address, then open `http://HOST_LAN_IP:5173`. Permit TCP ports 5173 and 5000 through Windows Firewall on the private network. Set `FRONTEND_URL` in `backend/.env` to include the LAN frontend URL if browser CORS blocks it (comma-separated values are accepted).

## Demo checks

- Alice searches Bob, creates a conversation, then sends text/image. Bob receives it without refresh. The message display verifies AES-GCM before decrypting.
- Inspect `securex.messages` in MongoDB: `encrypted.cipher`, IV and wrapped keys—not plaintext—are stored.
- Requesting `/api/conversations/<unrelated-id>/messages` with Alice's bearer token returns 403 and logs `UNAUTHORIZED_CONVERSATION`.
- Tamper with ciphertext or tag/IV in a controlled browser test: decryption returns `INTEGRITY CHECK FAILED`.
- Security Lab measures actual browser AES-GCM timing, throughput, SHA-256 digest/timing, and an isolated analysis-only avalanche comparison. It never reuses production nonces.

## Traffic analysis

Capture the LAN interface in Wireshark while sending content, save a PCAP, then run:

```powershell
pip install pyshark
python analysis/traffic/analyze_pcap.py .\capture.pcap
```

The script reports packet count, addresses/ports, protocol, timing, traffic volume, processing time, and simple explainable packet-rate/traffic-burst flags. Packet metadata and timing remain visible; encrypted application payloads are not claimed to hide them. Use HTTPS/reverse-proxy TLS for a packet-capture demonstration that also protects HTTP/WebSocket transport headers on a LAN.

## Limitations

Academic prototype only: browser private keys are device-bound; losing browser storage prevents historic decryption. The security lab explains bounded demonstrations rather than claiming to prove or break cryptographic properties. Image entropy/NPCR/UACI/PSNR/MSE tooling remains a next extension; AES-GCM ciphertext bytes should not be misrepresented as a custom pixel cipher.
