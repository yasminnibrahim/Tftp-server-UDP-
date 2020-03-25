import sys
import os
import enum
import socket
import struct

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ("127.0.0.1", 69)


class TftpProcessor(object):
    class TftpPacketType(enum.Enum):
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    error_msg = {
        0: "Not defined, see error message (if any).",
        1: "File not found.",  #
        # 2: "Access violation.",
        # 3: "Disk full or allocation exceeded.",
        4: "Illegal TFTP operation.",  #
        # 5: "Unknown transfer ID.",
        6: "File already exists.",  #
        # 7: "No such user."
    }

    def __init__(self):
        self.packet_buffer = []
        self.blocks_buffer = []
        self.size = 0
        self.filename = []
        self.block_number = 0

    def process_udp_packet(self, packet_data, packet_source):

        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)
        # This shouldn't change.
        self.packet_buffer.append(out_packet)
        print(f" PACKET BUFFER {self.packet_buffer}")

    def _parse_udp_packet(self, packet_bytes):

        read = bytearray()
        write = bytearray()
        blockN = bytearray()
        ackblockN = bytearray()
        data = bytearray()
        errorcode = bytearray()

        i = 2
        j = 2

        (opcode,) = struct.unpack("!H", packet_bytes[0:2])
        if opcode == TftpProcessor.TftpPacketType.RRQ.value:  # read

            while packet_bytes[i] != 0:
                read.append(packet_bytes[i])
                i += 1

            self.filename = read.decode('ascii')
            format_str = "!H{}sB{}sB".format(len(read), len('octet'))
            packet_data = struct.pack(format_str, opcode, read, 0, 'octet'.encode('ascii'), 0)
            return packet_data

        elif opcode == TftpProcessor.TftpPacketType.WRQ.value:  # write
            while packet_bytes[i] != 0:
                write.append(packet_bytes[i])
                i += 1
            self.filename = write.decode('ascii')
            format_str = "!H{}sB{}sB".format(len(write), len('octet'))
            packet_data = struct.pack(format_str, opcode, write, 0, 'octet'.encode('ascii'), 0)

            return packet_data

        elif opcode == TftpProcessor.TftpPacketType.DATA.value:  # data

            blockN = int(str(packet_bytes[2]) + str(packet_bytes[3]))
            data = packet_bytes[4:]
            format_str = "!HH{}s".format(len(data))
            packet_data = struct.pack(format_str, opcode, blockN, data)



            return packet_data

        elif opcode == TftpProcessor.TftpPacketType.ACK.value:  # ACK
            blockN = int(str(packet_bytes[2]) + str(packet_bytes[3]))

            format_str = ("!HH")
            packet_data = struct.pack(format_str, opcode, blockN)


            return packet_data

        elif opcode == TftpProcessor.TftpPacketType.ERROR.value:  # error
            while j < 4:
                errorcode.append(packet_bytes[j])
                j += 1



            packet_data = packet_bytes[2:len(packet_bytes) - 9].split(bytearray([0]))
            packet_data.insert(0, 'ERROR'.encode('ascii'))
            packet_data.insert(1, packet_bytes[2:3])
            packet_data.insert(2, packet_bytes[4:len(packet_bytes)].split())

            return packet_data

        else:  # opcode doesn't exist
            msg = "Illegal TFTP operation"
            format_str = "!HH{}sB".format(len(msg))
            opcode = 5
            errorn = 4
            error_packet = struct.pack(format_str, opcode, errorn, msg.encode("ascii"), 0)
            return error_packet

    def _do_some_logic(self, input_packet ):

        block = 0

        opcode = input_packet[1]


        if opcode == 1:
            self.block_number=0
            packet_to_buffer = self.read_request()
            return packet_to_buffer

        elif opcode == 2:  # write case
            if os.path.isfile(self.filename):
                msg = "File already exists."
                format_str = "!HH{}sB".format(len(msg))
                opcode = 5
                errorn = 6
                error_packet = struct.pack(format_str, opcode, errorn, msg.encode("ascii"), 0)
                return error_packet

            else:
                opcode = 4
                format_str = "!HH"
                ack_Packet = struct.pack(format_str, opcode, block)
                return ack_Packet

        elif opcode == 3:
            Block_Data = struct.unpack("!H", input_packet[2:4])
            Data = struct.unpack("!{}s".format(len(input_packet[4:])), input_packet[4:])

            print('Data sent',Data)
            packet_to_buffer = self.write_request(Block_Data,  Data)
            return packet_to_buffer

        elif opcode == 4:
            packet_to_buffer = self.read_request()
            return packet_to_buffer

        else:
            msg = "Not defined, see error message (if any)."
            format_str = "!HH{}sB".format(len(msg))
            opcode = 5
            errorn = 0
            error_packet = struct.pack(format_str, opcode, errorn, msg.encode("ascii"), 0)
            return error_packet


    def read_request(self):
        chunk_size = 512

        if os.path.exists(self.filename):

            with open(self.filename, 'r') as f:

                while True:
                    read_data = f.read(chunk_size)
                    print(len(read_data))
                    opcode = 3

                    self.blocks_buffer.append(read_data)
                    if len(read_data) < 512:
                        self.blocks_buffer.append(read_data)
                        break

                f.close()
                print("opcode", opcode, "block", self.block_number)
                self.block_number+=1
                format_str = "!HH{}s".format(len(self.blocks_buffer[0]))
                packet_data = struct.pack(format_str, opcode, self.block_number, self.blocks_buffer.pop(0).encode("latin-1"))
            return packet_data
        else:
            msg = "File doesn't exist."
            format_str = "!HH{}sB".format(len(msg))
            opcode = 5
            errorn = 1
            error_packet = struct.pack(format_str, opcode, errorn, msg.encode("ascii"), 0)
            return error_packet

    def write_request(self, block, data):

        print(self.filename)
        print(data[0])
        f = open(self.filename, 'a')
        f.write(data[0].decode("latin-1"))
            # block += 1
        opcode = 4

        format_str = "!HH"
        ack_Packet = struct.pack(format_str, opcode, block[0])
        f.close()

        return ack_Packet

    def get_next_output_packet(self):

        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):

        return len(self.packet_buffer) != 0


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)

    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")


def setup_sockets(address):
    print("[SERVER] Socket info:", server_socket)
    print("[SERVER] Waiting...")
    packet = server_socket.recvfrom(516)

    data, client_address = packet

    print("[SERVER] IN", data)
    print("[SERVER] Socket info:", server_socket)
    print("[SERVER] Waiting...")
    print(f"TFTP server started on on [{address}]...")

    return data, client_address


def get_arg(param_index, default=None):
    try:

        return sys.argv[param_index]

    except IndexError as e:

        if default:

            return default

        else:

            print(e)

            print(

                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")

            exit(-1)  # Program execution failed.


def main():
    obj = TftpProcessor()

    print("*" * 50)

    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))

    check_file_name()

    print("*" * 50)

    ip_address = get_arg(1, "127.0.0.1")
    server_socket.bind(server_address)
    data, client_address = setup_sockets(ip_address)


    while True:
        TftpProcessor.process_udp_packet(obj, data, client_address)
        if TftpProcessor.has_pending_packets_to_be_sent(obj):

            server_socket.sendto(TftpProcessor.get_next_output_packet(obj), client_address)

        else:
            break
        data, client_address = setup_sockets(ip_address)


if __name__ == "__main__":
    main()
