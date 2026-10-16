<div align="center">

# OSI Stack in C++

**A complete, educational 7-layer OSI network stack in a single C++17 file, built from scratch on Linux.**

![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)
![Language](https://img.shields.io/badge/language-C%2B%2B17-00599C.svg)
![Platform](https://img.shields.io/badge/platform-Linux-informational.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

</div>

---

## Overview

This project implements every layer of the OSI model, from the physical wire up to a chat and file-transfer application, using nothing but the C++ standard library and POSIX sockets. Each layer is its own class and talks only to the layer directly above and below it, exactly like the real thing.

There are **no external libraries**. Even SHA-256, HMAC, CRC-32 and the packet memory pool are written from scratch.

> **Educational project.** The cryptography is a teaching construction. Do not use it to protect real data. Use TLS in real software.

## Features

| Layer | Name | What it does |
|:-----:|------|--------------|
| **7** | Application | Chat, file transfer, random-blob transfer with SHA-256 verification, ping |
| **6** | Presentation | Binary serialization, RLE compression, encryption + authentication tag |
| **5** | Session | Handshake, mutual authentication (HMAC-SHA256), session IDs, checkpoints, keepalive, clean shutdown |
| **4** | Transport | TCP-like reliable stream (3-way handshake, sequence numbers, sliding window, retransmission, fast retransmit, FIN close) and UDP-like datagrams |
| **3** | Network | IPv4-like addressing, header checksum, TTL, fragmentation and reassembly, ICMP echo (ping) |
| **2** | Data Link | MAC addressing, framing, CRC-32, ARP with cache |
| **1** | Physical | The "wire": a UDP socket carrying raw frames, with optional simulated packet loss and bit corruption |

**Also included**

- Fixed-size **buffer pool** with RAII packet buffers, zero-copy header push/pull, double-free detection and a leak report at exit.
- A built-in **automated test mode** that verifies pings, UDP, chat, a 256 KiB blob and a 100 KiB file end to end.
- **Network fault simulation** (`--loss`, `--corrupt`, `--mtu`) to watch retransmission, CRC checks and IP fragmentation work.
- Defensive parsing: bounds-checked readers, size limits, decompression caps, UTF-8 sanitizing and path-traversal protection.

## How it works

```
 Sender                                                     Receiver
 ┌────────────────────┐                             ┌────────────────────┐
 │ L7  Application    │  chat / file / blob / ping  │ L7  Application    │
 │ L6  Presentation   │  serialize → compress → enc │ L6  Presentation   │
 │ L5  Session        │  handshake, auth, keepalive │ L5  Session        │
 │ L4  Transport      │  reliable stream (TCP-like) │ L4  Transport      │
 │ L3  Network        │  IP, fragmentation, ICMP    │ L3  Network        │
 │ L2  Data Link      │  MAC, CRC-32, ARP           │ L2  Data Link      │
 │ L1  Physical       │  UDP socket as the "wire"   │ L1  Physical       │
 └─────────┬──────────┘                             └──────────┬─────────┘
           └──────────────── real network (UDP) ───────────────┘
```

Every layer adds its own header on the way down and removes it on the way up (encapsulation).

## Requirements

- **Linux** (any modern distribution)
- `g++` with C++17 support (GCC 7+ or Clang 5+)

Install a compiler if you don't have one:

```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install -y build-essential

# Fedora
sudo dnf install -y gcc-c++

# Arch
sudo pacman -S --needed base-devel
```

## Build

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
g++ -std=c++17 -O2 -Wall -Wextra osi.cpp -o osi
```

## Quick start (one machine)

Open two terminals in the project folder.

**Terminal 1: server**
```bash
./osi server --listen 9000
```

**Terminal 2: client**
```bash
./osi client --peer 127.0.0.1:9000
```

Type a message in either terminal and press Enter. Try `/ping`, `/blob 512` or `/stats`.

## Connecting two computers

You need the **real IP address of the server machine**. The stack also has its own *virtual* IPs (`10.0.0.1` and `10.0.0.2`) used inside the simulation, but those are **not** what you pass to `--peer`.

### Step 1: Find the server's IP address (on the server machine)

```bash
hostname -I
```

This prints one or more addresses. Use the first one that looks like `192.168.x.x`, `10.x.x.x` or `172.16-31.x.x`.

Other ways to get it:

```bash
# Show only IPv4 addresses with their interface names
ip -4 -brief addr

# The address your machine uses to reach the internet
ip route get 1.1.1.1 | awk '{print $7; exit}'
```

### Step 2: Allow the port through the firewall (on the server)

The "wire" uses **UDP port 9000** (or whatever you pass to `--listen`).

```bash
# Ubuntu / Debian with ufw
sudo ufw allow 9000/udp

# Fedora / RHEL with firewalld
sudo firewall-cmd --add-port=9000/udp --permanent && sudo firewall-cmd --reload
```

### Step 3: Start the server

```bash
./osi server --listen 9000 --key "my-shared-secret"
```

### Step 4: Connect from the client machine

Replace `192.168.1.20` with the server's IP from Step 1:

```bash
./osi client --peer 192.168.1.20:9000 --key "my-shared-secret"
```

When both sides print `session ... established - authenticated`, you are connected.

### Same network or over the internet?

| Situation | What to do |
|-----------|------------|
| Same Wi-Fi / LAN | Use the server's local IP from `hostname -I`. This is the easy path. |
| Different networks | Either forward **UDP 9000** on the server's router to the server machine and use your public IP (`curl ifconfig.me`), or put both machines on a private VPN such as WireGuard or Tailscale and use the VPN addresses. |

## Usage

```
usage: osi server|client [options]

  --listen PORT      UDP port of the physical "wire" (server default 9000, client default: any)
  --peer HOST:PORT   other machine's wire address (required for client; server learns it)
  --ip A.B.C.D       virtual IP of this node        (server 10.0.0.1, client 10.0.0.2)
  --peer-ip A.B.C.D  virtual IP of the other node
  --app-port N       application port (default 7000)
  --key SECRET       shared secret (must match on both sides)
  --loss PCT         simulate frame loss on transmit
  --corrupt PCT      simulate bit flips on transmit
  --mtu N            network MTU 100..1500 (small values force IP fragmentation)
  --no-compress      disable compression (must match on both sides)
  --no-encrypt       disable encryption (must match on both sides)
  --test             client: run the automated test suite
  --once             server exits after the first session
  -v                 verbose per-layer log (stderr)
```

### In-session commands

| Command | Description |
|---------|-------------|
| `<text>` | Send a chat message (the peer echoes it back and it is verified) |
| `/ping` | Send an ICMP echo and print the round-trip time |
| `/udp TEXT` | Send a UDP datagram (echoed back) |
| `/file PATH` | Send a file (max 8 MiB). The receiver saves it in `received/` and verifies its SHA-256 |
| `/blob KB` | Send KB kilobytes of random data and verify the checksum |
| `/stats` | Print statistics for every layer |
| `/quit` | Close the session cleanly |

## Testing the stack

Run the automated test on a perfect connection:

```bash
./osi server --listen 9000 --once
./osi client --peer 127.0.0.1:9000 --test
```

Now make the network terrible and watch it recover:

```bash
./osi server --listen 9000 --once
./osi client --peer 127.0.0.1:9000 --test --loss 15 --corrupt 5 --mtu 300 -v
```

- `--loss 15` drops 15% of frames, so Layer 4 retransmits.
- `--corrupt 5` flips bits in 5% of frames, so Layer 2's CRC-32 rejects them.
- `--mtu 300` forces Layer 3 to fragment and reassemble packets.
- `-v` prints what each layer is doing.

A passing run ends with `ALL PASSED`, and the memory report prints `NO LEAKS`. Use `/stats` (or the end-of-test dump) to see retransmissions, bad CRCs and fragment counts.

## Troubleshooting

| Problem | Likely cause and fix |
|---------|----------------------|
| `bind: Address already in use` | Another program uses that UDP port. Pick another with `--listen`. |
| Client hangs at `connecting...` | Wrong IP or port, a firewall blocking UDP, or the server isn't running. Check Step 1 and Step 2. |
| `authentication denied by peer (wrong --key?)` | The `--key` values differ. They must match exactly. |
| Messages are dropped with presentation errors | `--no-encrypt` or `--no-compress` is set on one side only. Both sides must match. |
| `cannot resolve ...` | The `--peer` value must be `HOST:PORT`. |

## Known limitations

This is a learning tool, so some things are deliberately simple:

- No congestion control or flow control (fixed window of 8 segments).
- Go-Back-N receiver (out-of-order segments are discarded, not buffered).
- No routing or forwarding: it is a point-to-point link between two end hosts.
- IPv4-like only, with a simplified header.
- One session at a time.
- Cryptography is educational and has not been audited. Random values come from `mt19937`, which is not cryptographically secure.

## Contributing

Contributions are welcome. Fork the repository, create a branch, make your change and open a pull request. By contributing, you agree that your contribution is licensed under the same license as this project (GPL-3.0).

## License and copyright

Copyright (C) 2026 **Yamen Ehab Mohamed (ymcs)**. All rights reserved except as granted below.

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version**.

This program is distributed in the hope that it will be useful, but **WITHOUT ANY WARRANTY**; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.html) for more details.

**In plain English:**

- The original author remains the copyright holder of this code.
- You may use, study, modify and share it, including commercially.
- If you distribute your modified version, you must also release it under the **same GPL license**, keep the original copyright notices, and make your source code available.
- You may not remove the author's copyright or relicense this code as closed source.

See the [`LICENSE`](LICENSE) file for the full legal text.
