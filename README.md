# TCP Handshake Client using Raw Sockets

This project implements the client-side of a TCP three-way handshake using raw sockets in C++. The server code is provided separately.

## Files Included
- `client.cpp` — Raw socket implementation of the TCP handshake client
- `README.md` — This file

## How It Works

This client sends:
1. A SYN packet with a user-provided sequence number
2. Waits for the SYN-ACK from the server
3. Sends the final ACK to complete the three-way handshake

The server validates that:
- The client's SYN sequence number is exactly `200`
- The final ACK follows the expected sequence

## Compilation Instructions

Use the provided Makefile to compile:
```bash
make
```
This will generate the `client` and `server` executables.

Note: You must run the binaries as root since raw sockets require elevated privileges.

## Execution Instructions

1. Run the server (in one terminal):
```bash
sudo ./server
```

2. Run the client (in another terminal):
```bash
sudo ./client
```
You will be prompted:
```
Enter the initial sequence number to send with SYN:
```
Enter a number (e.g., `200`) to test correct handshake behavior.

## Test Cases

### Handshake Succeeds
Input:
```
200
```
Expected Output:
```
[+] Sent packet: SEQ=200, ACK=0, SYN=1, ACK_FLAG=0
[+] Received SYN-ACK: SEQ=400, ACK=201
[+] Sent packet: SEQ=600, ACK=401, SYN=0, ACK_FLAG=1
[+] Handshake completed.
```

### Handshake Fails
Input:
```
201
```
Expected Output:
```
[+] Sent packet: SEQ=201, ACK=0, SYN=1, ACK_FLAG=0
[-] No response received. Handshake failed or timed out.
```

## Notes
- This program is tested only on Linux.
- Uses raw sockets to manually construct IP and TCP headers.
- Checksums are manually computed.

## References
- Kurose, J. F., & Ross, K. W. (2020). Computer Networking: A Top-Down Approach (8th ed.). Pearson.
- https://www.binarytides.com/raw-sockets-c-linux/
- https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment
- https://www.geeksforgeeks.org/tcp-ip-model/
