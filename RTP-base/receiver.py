
import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

START = 0
END = 1
DATA = 2
ACK = 3

MAX_PACKET_SIZE = 1472
HEADER_SIZE = 16


def make_packet(packet_type, seq_num):
    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=0,
        checksum=0,
    )
    header.checksum = compute_checksum(header)
    return bytes(header)


def parse_packet(raw):
    if len(raw) < HEADER_SIZE or len(raw) > MAX_PACKET_SIZE:
        return None

    try:
        header = PacketHeader(raw[:HEADER_SIZE])
        payload = raw[HEADER_SIZE:]

        if header.type not in (START, END, DATA, ACK):
            return None

        if header.length != len(payload):
            return None

        # START, END và ACK không được mang payload.
        if header.type in (START, END, ACK) and payload:
            return None

        received_checksum = header.checksum
        header.checksum = 0

        if compute_checksum(header / payload) != received_checksum:
            return None

        return header, payload
    except Exception:
        return None


def receiver(receiver_ip, receiver_port, window_size):
    if window_size < 1:
        raise ValueError("window_size must be positive")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    active = False
    sender_address = None
    expected_seq = 1
    buffer = {}

    try:
        while True:
            # Nhận thêm 1 byte để phát hiện datagram vượt giới hạn.
            raw, address = sock.recvfrom(MAX_PACKET_SIZE + 1)
            parsed = parse_packet(raw)

            # Invalid or corrupted packets are discarded without ACK.
            if parsed is None:
                continue

            header, payload = parsed
            packet_type = header.type
            seq_num = header.seq_num

            if packet_type == START:
                # Ignore START messages during an active connection.
                if active:
                    continue

                if seq_num != 0 or payload:
                    continue

                active = True
                sender_address = address
                expected_seq = 1
                buffer.clear()

                sock.sendto(make_packet(ACK, 1), sender_address)
                continue

            # Only accept packets from the sender that initiated
            # the current connection.
            if not active or address != sender_address:
                continue

            if packet_type == DATA:
                # Duplicate DATA: repeat the cumulative ACK.
                if seq_num < expected_seq:
                    sock.sendto(
                        make_packet(ACK, expected_seq),
                        sender_address,
                    )
                    continue

                # Packets outside the receive window are discarded.
                if seq_num >= expected_seq + window_size:
                    continue

                # Buffer out-of-order packets.
                if seq_num not in buffer:
                    buffer[seq_num] = payload

                # Deliver all consecutive packets starting at expected_seq.
                while expected_seq in buffer:
                    chunk = buffer.pop(expected_seq)
                    sys.stdout.buffer.write(chunk)
                    expected_seq += 1

                sys.stdout.buffer.flush()

                # Cumulative ACK reports the next sequence number expected.
                sock.sendto(
                    make_packet(ACK, expected_seq),
                    sender_address,
                )
                continue

            if packet_type == END:
                # END is valid only after all preceding DATA has arrived.
                if seq_num != expected_seq or payload:
                    continue

                sock.sendto(
                    make_packet(ACK, seq_num + 1),
                    sender_address,
                )
                break

    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip")
    parser.add_argument("receiver_port", type=int)
    parser.add_argument("window_size", type=int)
    args = parser.parse_args()

    receiver(
        args.receiver_ip,
        args.receiver_port,
        args.window_size,
    )


if __name__ == "__main__":
    main()
