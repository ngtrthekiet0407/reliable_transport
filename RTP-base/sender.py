import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

START = 0
END = 1
DATA = 2
ACK = 3

MAX_PACKET_SIZE = 1472
HEADER_SIZE = 16
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5


def make_packet(packet_type, seq_num, payload=b""):
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0,
    )
    header.checksum = compute_checksum(header / payload)
    return bytes(header / payload)


def parse_packet(raw):
    if len(raw) < HEADER_SIZE or len(raw) > MAX_PACKET_SIZE:
        return None

    try:
        header = PacketHeader(raw[:HEADER_SIZE])
        payload = raw[HEADER_SIZE:]

        if header.length != len(payload):
            return None

        received_checksum = header.checksum
        header.checksum = 0

        if compute_checksum(header / payload) != received_checksum:
            return None

        if header.type not in (START, END, DATA, ACK):
            return None

        if header.type in (START, END, ACK) and payload:
            return None

        return header, payload
    except Exception:
        return None


def wait_for_ack(sock, destination, expected_seq, packet):
    """Retransmit START until its ACK is received."""
    while True:
        sock.sendto(packet, destination)
        deadline = time.monotonic() + TIMEOUT

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            readable, _, _ = select.select(
                [sock], [], [], remaining
            )
            if not readable:
                break

            raw, address = sock.recvfrom(MAX_PACKET_SIZE + 1)

            if address != destination:
                continue

            parsed = parse_packet(raw)
            if parsed is None:
                continue

            header, _ = parsed

            if header.type == ACK and header.seq_num >= expected_seq:
                return


def sender(receiver_ip, receiver_port, window_size):
    if window_size < 1:
        raise ValueError("window_size must be positive")

    receiver = (
        socket.gethostbyname(receiver_ip),
        receiver_port,
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    try:
        message = sys.stdin.buffer.read()
        chunks = [
            message[i:i + MAX_PAYLOAD_SIZE]
            for i in range(0, len(message), MAX_PAYLOAD_SIZE)
        ]

        # START has sequence number 0; its ACK has sequence number 1.
        wait_for_ack(
            sock,
            receiver,
            1,
            make_packet(START, 0),
        )

        total = len(chunks)

        # base is the first DATA sequence number not cumulatively ACKed.
        base = 1
        next_seq = 1

        # Store packets sent but not yet cumulatively acknowledged.
        outstanding = {}
        deadline = None

        while base <= total:
            # Fill the sending window.
            while (
                next_seq <= total
                and next_seq < base + window_size
            ):
                packet = make_packet(
                    DATA,
                    next_seq,
                    chunks[next_seq - 1],
                )
                sock.sendto(packet, receiver)
                outstanding[next_seq] = packet
                next_seq += 1

                if deadline is None:
                    deadline = time.monotonic() + TIMEOUT

            if not outstanding:
                deadline = None
                continue

            remaining = max(0.0, deadline - time.monotonic())
            readable, _, _ = select.select(
                [sock], [], [], remaining
            )

            if not readable:
                # No cumulative progress: retransmit all outstanding
                # packets in the current window.
                for seq in sorted(outstanding):
                    sock.sendto(outstanding[seq], receiver)

                deadline = time.monotonic() + TIMEOUT
                continue

            raw, address = sock.recvfrom(MAX_PACKET_SIZE + 1)

            if address != receiver:
                continue

            parsed = parse_packet(raw)
            if parsed is None:
                continue

            header, _ = parsed

            if header.type != ACK:
                continue

            ack_seq = header.seq_num

            # ACK N confirms all DATA packets with sequence numbers < N.
            # Ignore duplicate, stale, or impossible ACKs.
            if base < ack_seq <= next_seq:
                base = ack_seq

                for seq in list(outstanding):
                    if seq < base:
                        del outstanding[seq]

                # Restart the timer when cumulative progress occurs.
                deadline = (
                    time.monotonic() + TIMEOUT
                    if outstanding
                    else None
                )

        # All DATA packets have been cumulatively acknowledged.
        end_seq = total + 1
        end_packet = make_packet(END, end_seq)

        # The specification allows the sender to exit 500 ms after END
        # if the END ACK is lost because the receiver has already exited.
        sock.sendto(end_packet, receiver)
        deadline = time.monotonic() + TIMEOUT

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            readable, _, _ = select.select(
                [sock], [], [], remaining
            )
            if not readable:
                break

            raw, address = sock.recvfrom(MAX_PACKET_SIZE + 1)

            if address != receiver:
                continue

            parsed = parse_packet(raw)
            if parsed is None:
                continue

            header, _ = parsed

            if (
                header.type == ACK
                and header.seq_num >= end_seq + 1
            ):
                break

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()

    sender(
        args.receiver_ip,
        args.receiver_port,
        args.window_size,
    )


if __name__ == "__main__":
    main()