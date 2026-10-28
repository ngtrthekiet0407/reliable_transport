
import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472

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
    if len(raw) < HEADER_SIZE or len(raw) > MAX_PACKET_SIZE:
        return None, None

    header = PacketHeader(raw[:HEADER_SIZE])

    if header.type not in (START, END, DATA, ACK):
        return None, None

    if header.length < 0 or len(raw) != HEADER_SIZE + header.length:
        return None, None

    payload = raw[HEADER_SIZE:]

    # Các gói điều khiển không được mang payload.
    if header.type in (START, END, ACK) and header.length != 0:
        return None, None

    received_checksum = header.checksum
    header.checksum = 0

    if compute_checksum(header / payload) != received_checksum:
        return None, None

    return header, payload


class Receiver:
    def __init__(self, receiver_ip, receiver_port, window_size):
        self.window_size = window_size
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((receiver_ip, receiver_port))

        self.active = False
        self.sender_address = None
        self.expected_seq = 1
        self.buffer = {}

    def send_ack(self, seq_num):
        if self.sender_address is None:
            return

        packet = make_packet(ACK, seq_num)
        self.sock.sendto(packet, self.sender_address)

    def handle_start(self, header, address):
        # Chỉ nhận START khi chưa có kết nối đang hoạt động.
        if self.active:
            return

        if header.seq_num != 0 or header.length != 0:
            return

        self.active = True
        self.sender_address = address
        self.expected_seq = 1
        self.buffer.clear()

        # Quy ước trong README: ACK của START có seq_num = 1.
        self.send_ack(1)

    def handle_data(self, header, payload, address):
        if not self.active or address != self.sender_address:
            return

        seq = header.seq_num

        # Gói cũ có thể được gửi lại do ACK trước đó bị mất.
        if seq < self.expected_seq:
            self.send_ack(seq)
            return

        # Không nhận gói nằm ngoài cửa sổ nhận.
        if seq >= self.expected_seq + self.window_size:
            return

        # Part 3: ACK riêng bằng seq_num của chính gói DATA.
        self.send_ack(seq)

        # Lưu gói đến sai thứ tự; không ghi đè dữ liệu đã có.
        if seq not in self.buffer:
            self.buffer[seq] = payload

        # Chỉ xuất dữ liệu theo thứ tự liên tục.
        while self.expected_seq in self.buffer:
            data = self.buffer.pop(self.expected_seq)
            sys.stdout.buffer.write(data)
            self.expected_seq += 1

        sys.stdout.flush()

    def handle_end(self, header, address):
        if not self.active or address != self.sender_address:
            return

        if header.length != 0:
            return

        # Chỉ kết thúc khi mọi gói DATA trước END đã được nhận theo thứ tự.
        if header.seq_num != self.expected_seq:
            return

        self.send_ack(header.seq_num)

        self.active = False
        self.sender_address = None
        self.buffer.clear()
        self.expected_seq = 1

    def run(self):
        try:
            while True:
                raw, address = self.sock.recvfrom(2048)
                header, payload = parse_packet(raw)

                # Bỏ gói hỏng hoặc gói có cấu trúc không hợp lệ.
                if header is None:
                    continue

                if header.type == START:
                    self.handle_start(header, address)
                elif header.type == DATA:
                    self.handle_data(header, payload, address)
                elif header.type == END:
                    self.handle_end(header, address)
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

    Receiver(
        args.receiver_ip,
        args.receiver_port,
        args.window_size,
    ).run()


if __name__ == "__main__":
    main()
