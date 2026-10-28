
import argparse
import random
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5

START = 0
END = 1
DATA = 2
ACK = 3


def make_packet(packet_type, seq_num, payload=b""):
    if isinstance(payload, str):
        payload = payload.encode()

    header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0,
    )
    header.checksum = compute_checksum(header / payload)
    return bytes(header / payload)


def parse_packet(raw):
    if len(raw) < HEADER_SIZE:
        return None, None

    header = PacketHeader(raw[:HEADER_SIZE])

    if header.length < 0 or len(raw) != HEADER_SIZE + header.length:
        return None, None

    payload = raw[HEADER_SIZE:]

    received_checksum = header.checksum
    header.checksum = 0

    if compute_checksum(header / payload) != received_checksum:
        return None, None

    return header, payload


class Sender:
    def __init__(self, receiver_ip, receiver_port, window_size):
        self.destination = (receiver_ip, receiver_port)
        self.window_size = window_size
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.base_seq = 1
        self.next_seq = 1
        self.outstanding = {}
        self.acknowledged = set()
        self.timer_started = None

    def send_raw(self, raw):
        self.sock.sendto(raw, self.destination)

    def receive_ack(self, timeout):
        self.sock.settimeout(max(0.001, timeout))
        expected_ip = socket.gethostbyname(self.destination[0])

        while True:
            try:
                raw, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                return None

            if (
                addr[0] != expected_ip
                or addr[1] != self.destination[1]
            ):
                continue

            header, payload = parse_packet(raw)

            if header is None:
                continue

            if header.type != ACK or header.length != 0:
                continue

            return header.seq_num

    def send_start(self):
        # START luôn có seq_num = 0; ACK START có seq_num = 1.
        packet = make_packet(START, 0)

        self.send_raw(packet)
        ack = self.receive_ack(TIMEOUT)

        # Theo README, không bắt buộc xử lý START ACK bị trễ hoặc bị mất.
        if ack != 1:
            pass

    def fill_window(self):
        while self.next_seq < self.base_seq + self.window_size:
            payload = sys.stdin.buffer.read(MAX_PAYLOAD_SIZE)

            if not payload:
                return False

            seq = self.next_seq
            packet = make_packet(DATA, seq, payload)

            self.outstanding[seq] = packet
            self.send_raw(packet)
            self.next_seq += 1

            if self.timer_started is None:
                self.timer_started = time.monotonic()

        return True

    def process_ack(self, ack_seq):
        # Chỉ ghi nhận ACK cho gói đang nằm trong cửa sổ.
        if ack_seq not in self.outstanding:
            return

        self.acknowledged.add(ack_seq)

        old_base = self.base_seq

        # Trượt cửa sổ qua những gói đã được ACK liên tục từ đầu cửa sổ.
        while self.base_seq in self.acknowledged:
            self.acknowledged.remove(self.base_seq)
            del self.outstanding[self.base_seq]
            self.base_seq += 1

        if self.base_seq != old_base:
            self.timer_started = (
                time.monotonic() if self.outstanding else None
            )

    def retransmit_unacknowledged(self):
        # Chỉ truyền lại những gói chưa nhận được ACK riêng.
        for seq, packet in list(self.outstanding.items()):
            if seq not in self.acknowledged:
                self.send_raw(packet)

        self.timer_started = (
            time.monotonic() if self.outstanding else None
        )

    def send_data(self):
        input_finished = False

        while not input_finished or self.outstanding:
            if not input_finished:
                input_finished = not self.fill_window()

            if not self.outstanding:
                continue

            if self.timer_started is None:
                self.timer_started = time.monotonic()

            remaining = TIMEOUT - (
                time.monotonic() - self.timer_started
            )

            if remaining <= 0:
                self.retransmit_unacknowledged()
                continue

            ack_seq = self.receive_ack(remaining)

            if ack_seq is not None:
                self.process_ack(ack_seq)

            if (
                self.outstanding
                and self.timer_started is not None
                and time.monotonic() - self.timer_started >= TIMEOUT
            ):
                self.retransmit_unacknowledged()

    def send_end(self):
        # END dùng số thứ tự kế tiếp sau DATA cuối cùng.
        packet = make_packet(END, self.next_seq)
        deadline = time.monotonic() + TIMEOUT

        while time.monotonic() < deadline:
            self.send_raw(packet)
            remaining = deadline - time.monotonic()

            if remaining <= 0:
                break

            ack_seq = self.receive_ack(remaining)

            if ack_seq == self.next_seq:
                break

    def run(self):
        try:
            self.send_start()
            self.send_data()
            self.send_end()
        finally:
            self.sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip",
        help="The IP address of the host that receiver is running on",
    )
    parser.add_argument(
        "receiver_port",
        type=int,
        help="The port number on which receiver is listening",
    )
    parser.add_argument(
        "window_size",
        type=int,
        help="Maximum number of outstanding packets",
    )
    args = parser.parse_args()

    if not 1 <= args.receiver_port <= 65535:
        parser.error("receiver_port must be between 1 and 65535")

    if args.window_size <= 0:
        parser.error("window_size must be positive")

    Sender(
        args.receiver_ip,
        args.receiver_port,
        args.window_size,
    ).run()


if __name__ == "__main__":
    main()
