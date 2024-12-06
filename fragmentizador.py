import os
import random
import socket
import threading
import struct
import time
import queue
import sys
import io
import typing

INTERNET_PROTOCOL = 0
CONTROL_PROTOCOL = 1

HEADER_FIELDS = 7
HEADER_LEN = 4 * HEADER_FIELDS

RECIEVER_TIMEOUT = 0.5
BUFFSIZE = 2 ** 15

MSG_DEFRAG_TIMEOUT = 1
SEEN_CTRL_MSG_TIMEOUT = 1
COMPLETE_TABLE_TIMEOUT = 2


class Header:
    def __init__(self, protocol: int,
                 ip: int, port: int,
                 size: int, offset: int,
                 id: int, ttl: int) -> None:

        self.protocol: int = protocol

        self.ip: int = ip
        self.port: int = port

        self.size: int = size
        self.offset: int = offset

        self.id: int = id
        self.ttl: int = ttl


def pack_header(header: Header) -> bytes:
    return struct.pack(f"{HEADER_FIELDS}I", header.protocol,
                                            header.ip, header.port, 
                                            header.size, header.offset,
                                            header.id, header.ttl)

def unpack_header(header: bytes) -> Header:
    return Header(*typing.cast(tuple[int, int, int, int, int, int, int], 
                               struct.unpack(f"{HEADER_FIELDS}I", header)))

def ip_to_int(ip: str) -> int:
    return int.from_bytes(socket.inet_aton(socket.gethostbyname(ip)))

def int_to_ip(ip: int) -> str:
    return socket.inet_ntoa(ip.to_bytes(4))


class FragmentedMessage:
    def __init__(self, len: int) -> None:
        self.len: int = len
        self.next: int = 0
        self.msg: dict[int, bytes] = dict()
        self.offsets: set[int] = set()

    def is_complete(self) -> bool:
        return self.len == self.next

    def add(self, fragment: bytes, offset: int) -> None:
        if offset < self.next \
            or offset + len(fragment) > self.len \
            or len(fragment) <= 0 \
            or offset in self.offsets:
            return

        self.msg[offset] = fragment
        self.offsets.add(offset)

        while self.next in self.offsets:
            self.next += len(self.msg[self.next])

    def reconstruct(self) -> bytes:
        ret = b''
        while len(ret) < self.next:
            ret += self.msg[len(ret)]
        return ret
        

class Defragmenter:
    def __init__(self) -> None:
        self.messages: dict[int, FragmentedMessage] = dict()
        self.timeouts: dict[int, float] = dict()

    def check_timeouts(self) -> None:
        current_time = time.time()
        timedout_keys = [key for key, timeout in self.timeouts.items() \
                            if current_time - timeout > MSG_DEFRAG_TIMEOUT]

        for key in timedout_keys:
            del self.timeouts[key]
            del self.messages[key]

    def add_segment(self, header: Header, data: bytes) -> bytes | None:
        self.check_timeouts()

        if header.id not in self.messages.keys():
            self.messages[header.id] = FragmentedMessage(header.size)
            self.timeouts[header.id] = time.time()
        
        msg = self.messages[header.id]
        msg.add(data, header.offset)
        self.timeouts[header.id] = time.time()

        if msg.is_complete():
            ret = msg.reconstruct()
            del self.messages[header.id]
            del self.timeouts[header.id]
            return ret
    

address_t: typing.TypeAlias = tuple[str, int]

class RoutingTable:
    def __init__(self, this_addr: address_t, linked_addrs: list[str]) -> None:
        self.this_addr: address_t = this_addr
        self.mtus: dict[address_t, int] = dict()

        for link in linked_addrs:
            try: 
                parts = link.split(':', maxsplit=2)
                ip = socket.gethostbyname(parts[0])
                port = int(parts[1])
                mtu = int(parts[2])

                if mtu <= HEADER_LEN:
                    print((f"Error en el argumento '{link}', todos los MTUs deben "
                           f"ser mayores al tamaño del header ({HEADER_LEN} bytes)"),
                          file=sys.stderr)
                    exit(1)

                self.mtus[(ip,port)] = mtu

            except:
                print(f"Error de formato en el argumento '{link}'", file=sys.stderr)
                exit(1)

        self.argument_links: set[address_t] = set(self.mtus.keys())
        self.direct_links: set[address_t] = set(self.mtus.keys())
        self.max_mtu: int = max(self.mtus.values()) if len(self.mtus) > 0 else 0

        self.routing_table: dict[address_t, list[address_t]] \
                            = {addr: [addr] for addr in self.mtus.keys()}

        self.distances: dict[address_t, int] = {addr: 1 for addr in self.mtus.keys()}
        self.reachable_addrs: set[address_t] = set(self.mtus.keys())


    def get_mtu(self, addr: address_t) -> int:
        return self.mtus[addr]
    
    def to_str(self) -> str:
        result = ""
        for addr, dist in self.distances.items():
            result += f"destino: {addr[0]}:{addr[1]}\n"
            result += f"    distancia: {dist}\n"
            offset = f"    enrutar por: "
            for ip, port in self.routing_table[addr]:
                result += offset + f"- {ip}:{port}\n"
                offset = f"                 "

        return result

    def reachable(self, addr: address_t) -> bool:
        return addr in self.reachable_addrs
        
    def add_path(self, dst_addr: address_t, next_addr:address_t,
                 distance: int) -> None:
        if dst_addr == self.this_addr:
            return

        if dst_addr in self.reachable_addrs:
            prev_distance = self.distances[dst_addr]

            if distance < prev_distance:
                self.routing_table[dst_addr] = [next_addr]
                self.distances[dst_addr] = distance

            elif prev_distance == distance \
                and next_addr not in self.routing_table[dst_addr]:
                self.routing_table[dst_addr].append(next_addr)

        else:
            self.reachable_addrs.add(dst_addr)
            self.routing_table[dst_addr] = [next_addr]
            self.distances[dst_addr] = distance
    
    def get_directions(self, dst_addr: address_t, data_size: int) -> list[tuple[address_t, int]]:
        paths = self.routing_table[dst_addr]
        ideal_path_index = -1

        for index, addr in enumerate(paths):
            if self.mtus[addr] - HEADER_LEN >= data_size:
                ideal_path_index = index
                break

        if ideal_path_index != -1:
            ideal_path = paths.pop(ideal_path_index)
            paths.append(ideal_path)
            return [(ideal_path, self.mtus[ideal_path])]

        else:
            distributed_bytes = 0
            directions: list[tuple[address_t, int]] = list()

            while distributed_bytes < data_size:
                addr = paths.pop(0)
                paths.append(addr)
                mtu = self.mtus[addr]
                directions.append((addr, mtu))
                distributed_bytes += mtu - HEADER_LEN

            return directions


    def add_direct_link(self, addr: address_t, mtu:int) -> None:
        if addr not in self.direct_links:
            self.mtus[addr] = mtu
            self.direct_links.add(addr)
            if mtu > self.max_mtu:
                self.max_mtu = mtu

            self.add_path(addr, addr, 1)

        elif addr in self.argument_links:
            self.argument_links.remove(addr)

    def is_complete(self) -> bool:
        return len(self.argument_links) == 0

    def get_direct_links(self) -> list[tuple[address_t, int]]:
        return list(self.mtus.items())

    def pack(self) -> bytes:
        packed_table: bytes = b''
        for (ip, port), dist in self.distances.items():
            packed_table += socket.inet_aton(ip) + port.to_bytes(4) + dist.to_bytes(4)

        return packed_table

    def update(self, header: Header, data: bytes) -> None:
        sender_addr: address_t = (int_to_ip(header.ip), header.port)
        self.add_direct_link(sender_addr, header.ttl)

        for entry in [data[i: i+12] for i in range(0, len(data), 12)]:
            ip = socket.inet_ntoa(entry[0:4])
            port = int.from_bytes(entry[4:8])
            dist = int.from_bytes(entry[8:12])

            self.add_path((ip, port), sender_addr, dist + 1)


def recieve_messages(address: address_t,
                     message_queue: queue.Queue[bytes], 
                     continue_event: threading.Event) -> None:
    reciever_soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reciever_soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    reciever_soc.settimeout(RECIEVER_TIMEOUT)
    reciever_soc.bind(address)

    while continue_event.is_set():
        try:
            msg = reciever_soc.recv(BUFFSIZE)
            message_queue.put(msg)
        except TimeoutError:
            pass

    reciever_soc.close()


# esta funcion añade un retardo pequeño cada 10 mensajes para 
# no sobrecargar la cola de mensajes del kernel
wait_before_send = 0
def send_message(soc: socket.socket, msg: bytes, addr: address_t) -> None:
    global wait_before_send

    if wait_before_send >= 10:
        time.sleep(0.01)
        wait_before_send = 0

    wait_before_send += 1
    _ = soc.sendto(msg, addr)


def start_as_sender(filename: str, arg_src: str, arg_dst: str, arg_ttl: str) -> None:
    try:
        file = open(filename, "rb")
        size = file.seek(0, io.SEEK_END)
        _ = file.seek(0, io.SEEK_SET)
    except:
        print(f"Error al abrir archivo: \"{filename}\"", file=sys.stderr)
        exit(1)

    try:
        src_addr = arg_src.split(':', maxsplit=1)
        src_addr = (socket.gethostbyname(src_addr[0]), int(src_addr[1]))
    except:
        print(f"Error de formato en la dirección de origen '{arg_src}'", file=sys.stderr)
        exit(1)

    try:
        dst_addr = arg_dst.split(':', maxsplit=1)
        dst_ip = ip_to_int(dst_addr[0])
        dst_port = int(dst_addr[1])
    except:
        print(f"Error de formato en la dirección de destino '{arg_dst}'", file=sys.stderr)
        exit(1)

    try:
        ttl = int(arg_ttl)
    except:
        print(f"Error de formato en ttl '{arg_ttl}'", file=sys.stderr)
        exit(1)


    id = random.randint(0, 2 ** 32 - 1)

    header = Header(protocol=INTERNET_PROTOCOL, 
                    ip=dst_ip, port=dst_port, 
                    size=size, offset=0,
                    id=id, ttl=ttl)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as soc:
        while file.tell() != size:
            data = file.read(BUFFSIZE - HEADER_LEN)
            _ = send_message(soc, pack_header(header) + data, src_addr)
            header.offset += len(data)

    print("Mensaje enviado", file=sys.stderr)


def start_as_router(router_addr: str, linked_addrs: list[str]):
    try: 
        router_ip, router_port = router_addr.split(':', maxsplit=1)
        my_addr = (socket.gethostbyname(router_ip), int(router_port))

    except:
        print(f"Error de format en la dirección '{router_addr}'", file=sys.stderr)
        exit(1)

    sender_soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    segments = Defragmenter()

    # Un thread separado se encarga de recibir los mensajes para
    # evitar sobrecargar la cola del kernel
    msg_queue: queue.Queue[bytes] = queue.Queue()
    reciever_continue = threading.Event()
    reciever_continue.set()
    reciever_thread = threading.Thread(target=recieve_messages, 
                                       args=(my_addr, msg_queue, reciever_continue),
                                       daemon=True)
    reciever_thread.start()

    routing_table = RoutingTable(my_addr, linked_addrs)
    print(f"Tabla de rutas:\n{routing_table.to_str()}", file=sys.stderr)

    def routing_table_sendall(id: int) -> None:
        routing_data = routing_table.pack()

        ctrl_header = Header(protocol=CONTROL_PROTOCOL, 
                        ip=ip_to_int(my_addr[0]), port=my_addr[1], 
                        size=HEADER_LEN + len(routing_data), offset=0,
                        id=id, ttl=0)

        for addr, mtu in routing_table.get_direct_links():
            ctrl_header.ttl = mtu
            send_message(sender_soc, pack_header(ctrl_header) + routing_data, addr)

    routing_table_sendall(random.randint(0, (1 << 32) - 1))

    seen_ctrl_msgs: dict[int, float] = dict()

    def getfunc() -> bytes:
        if routing_table.is_complete():
            return msg_queue.get()
        else:
            while True:
                try:
                    return msg_queue.get(timeout=COMPLETE_TABLE_TIMEOUT)
                except queue.Empty:
                    routing_table_sendall(random.randint(0, (1 << 32) - 1))

    try:
        while True:
            msg = getfunc()

            if len(msg) <= HEADER_LEN:
                continue

            header = unpack_header(msg[:HEADER_LEN])
            data = msg[HEADER_LEN:]
            dst_addr = (int_to_ip(header.ip), header.port)

            header.ttl -= 1

            if header.protocol == CONTROL_PROTOCOL:
                if header.id in seen_ctrl_msgs.keys() \
                    and time.time() - seen_ctrl_msgs[header.id] <= SEEN_CTRL_MSG_TIMEOUT:
                    continue

                seen_ctrl_msgs[header.id] = time.time()

                routing_table.update(header, data)
                print(f"Tabla de rutas actualizada:\n{routing_table.to_str()}", file=sys.stderr)
                
                routing_table_sendall(header.id)


            elif dst_addr == my_addr:
                full_msg = segments.add_segment(header, data)
                if full_msg != None:
                    _ = os.write(sys.stdout.fileno(), full_msg)

            elif header.ttl > 0 and routing_table.reachable(dst_addr):
                next_addrs = routing_table.get_directions(dst_addr, len(data))
                sent_data = 0

                for addr, mtu in next_addrs:
                    data_size = mtu - HEADER_LEN

                    datagram = pack_header(header) + data[sent_data: sent_data + data_size]
                    send_message(sender_soc, datagram, addr)

                    header.offset += data_size
                    sent_data += data_size


    except KeyboardInterrupt:
        sender_soc.close()
        reciever_continue.clear()
        reciever_thread.join()
        print("conección cerrada", file=sys.stderr)
        exit()


flag = "--enviar"
help_string = f"""\
USOS: {sys.orig_argv[0]} {sys.argv[0]} mi_ip:mi_puerto ip:puerto:mtu ...
      {sys.orig_argv[0]} {sys.argv[0]} {flag} archivo ip_origen:puerto_origen ip_destino:puerto_destino ttl"""

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print(help_string, file=sys.stderr)
        exit(1)

    if sys.argv[1] == flag:
        if len(sys.argv) < 6:
            print(help_string, file=sys.stderr)
            exit(1)
        start_as_sender(*sys.argv[2:6])

    else:
        start_as_router(sys.argv[1], sys.argv[2:])

