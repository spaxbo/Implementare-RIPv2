import io
import json
import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pprint import pprint
from typing import Optional

logger = logging.getLogger("RIP")
logging.basicConfig(level=logging.INFO)


@dataclass(frozen=True)
class IPAddress:
    ip: str

    def __bytes__(self):
        return socket.inet_aton(self.ip)

    def __repr__(self):
        return f"IPAddress({self.ip})"

    @classmethod
    def from_bytestream(cls, b: io.BytesIO):
        ip = socket.inet_ntoa(b.read(4))
        return cls(ip)

    def __and__(self, other: "IPAddress"):
        a = socket.inet_aton(self.ip)
        b = socket.inet_aton(other.ip)
        p = bytes([aa & bb for aa, bb in zip(a, b)])
        return IPAddress.from_bytestream(io.BytesIO(p))


class RIPPacketCommand(IntEnum):
    REQUEST = 1
    RESPONSE = 2


@dataclass
class RIPRouteTableEntry:
    ip_address: IPAddress
    next_hop: IPAddress
    metric: int
    af_identifier: socket.AddressFamily = field(default=socket.AF_INET, repr=False)
    subnet_mask: IPAddress = field(default=IPAddress("255.255.255.0"), repr=False)
    route_tag: int = field(default=0, repr=False)
    age_timer: float = field(default=180, compare=False, repr=False)
    gc_timer: float = field(default=120, compare=False, repr=False)

    @classmethod
    def from_bytestream(cls, b: io.BytesIO):
        af_identifier = socket.AddressFamily(int.from_bytes(b.read(1)))
        route_tag = int.from_bytes(b.read(2))
        ip_address = IPAddress.from_bytestream(b)
        subnet_mask = IPAddress.from_bytestream(b)
        next_hop = IPAddress.from_bytestream(b)
        metric = int.from_bytes(b.read(4))
        return cls(
            af_identifier=af_identifier,
            route_tag=route_tag,
            ip_address=ip_address,
            subnet_mask=subnet_mask,
            next_hop=next_hop,
            metric=metric,
        )

    def __bytes__(self):
        return (
                self.af_identifier.to_bytes(1, byteorder="big")
                + self.route_tag.to_bytes(2, byteorder="big")
                + bytes(self.ip_address)
                + bytes(self.subnet_mask)
                + bytes(self.next_hop)
                + self.metric.to_bytes(4, byteorder="big")
        )


@dataclass
class RIPPacket:
    command: RIPPacketCommand
    version: int = 2
    reserved: int = 0
    route_table_entries: list[RIPRouteTableEntry] = field(default_factory=list)

    @classmethod
    def from_bytes(cls, b: bytes):
        br = io.BytesIO(b)
        command = RIPPacketCommand(int.from_bytes(br.read(1)))
        version = int.from_bytes(br.read(1))
        reserved = int.from_bytes(br.read(2))
        route_table_entries = []
        while br.tell() < len(b):
            route_table_entries.append(RIPRouteTableEntry.from_bytestream(br))
        return cls(
            command=command,
            version=version,
            reserved=reserved,
            route_table_entries=route_table_entries,
        )

    def __bytes__(self):
        return (
                self.command.to_bytes(1, byteorder="big")
                + self.version.to_bytes(1, byteorder="big")
                + self.reserved.to_bytes(2, byteorder="big")
                + b"".join(bytes(entry) for entry in self.route_table_entries)
        )


class Router:
    interfaces: dict[IPAddress, socket.socket]
    recv_socket: socket.socket
    routing_table: list[RIPRouteTableEntry]

    def __init__(self) -> None:
        self.interfaces = {}
        self.routing_table = []

        self.recv_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.recv_socket.bind(("", 520))

        with open("config.json", "r") as f:
            data: list[str] = json.load(f)
        for address in data:
            new_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            new_socket.bind((address, 520))

            self.interfaces[IPAddress(address)] = new_socket

            self.routing_table.append(
                RIPRouteTableEntry(
                    ip_address=IPAddress(address) & IPAddress("255.255.255.0"),
                    next_hop=IPAddress(address),
                    metric=0,
                )
            )

            logger.info(f"Interface {address} is up")
            threading.Thread(
                target=self.unicast_response_handler, args=(IPAddress(address),)
            ).start()

    def handle_packet(self, address: IPAddress, packet: RIPPacket):
        if packet.command == RIPPacketCommand.REQUEST:
            logger.info(f"Request received from {address.ip}")
            self.send_update(address)
            return
        # response received
        logger.info(f"Response received from {address.ip}")
        for route in packet.route_table_entries:
            # go through all our routes, refreshing all routes coming from this peer and checking if the route we got is new or better
            found = False
            should_send_update = False  # triggered update
            for saved_route in self.routing_table:
                if saved_route.ip_address == route.ip_address:
                    found = True
                    if (
                            saved_route.next_hop == address and saved_route.metric == 16
                    ):  # we got an update for a route that was being gc'd, we save it
                        logger.info(f"was gc update for {saved_route}, recv was {route}")
                        saved_route.metric = route.metric
                        should_send_update = True
                    elif (
                            route.metric + 1 < saved_route.metric
                    ):  # we've found a route that goes to the same place as an already existing route with a better metric
                        logger.info(
                            f"is better path to {saved_route.ip_address.ip}, recv was {route}, old was {saved_route}")
                        saved_route.metric = route.metric + 1
                        saved_route.next_hop = address
                        should_send_update = True
                if saved_route.next_hop == address:
                    # we've found a route which goes through this neighbor, update it
                    logger.info(f"is from neightbor {address.ip}, refreshing route {saved_route}")
                    saved_route.age_timer = 180.0
                if saved_route == route:
                    logger.info(f"{route} is existing {saved_route}")
            # if not found, this route is a new route, we add it
            if not found:
                logger.info(f"{route} is new")
                self.add_new_route(route, address)
                should_send_update = True

            if should_send_update:
                self.send_update(address)

    def unicast_response_handler(self, address: IPAddress):
        s = self.interfaces[address]
        logger.info(f"Response handler for {address.ip} is up")
        while True:
            data, (ip, _) = s.recvfrom(1024)
            if IPAddress(ip) in self.interfaces:
                continue
            self.handle_packet(IPAddress(ip), RIPPacket.from_bytes(data))

    def add_new_route(self, route: RIPRouteTableEntry, address: IPAddress):
        route.metric += 1
        route.next_hop = address
        self.routing_table.append(route)
        threading.Thread(target=self.age_timer, args=(route,)).start()

    def broadcast_response_handler(self):
        logger.info("Broadcast response handler is up")
        while True:
            data, (ip, _) = self.recv_socket.recvfrom(1024)
            if IPAddress(ip) in self.interfaces:
                continue
            self.handle_packet(IPAddress(ip), RIPPacket.from_bytes(data))

    def find_interface_for_address(self, address: IPAddress):
        for interface in self.interfaces:
            if interface & address == interface & IPAddress("255.255.255.0"):
                return interface

    def send_update(self, address: Optional[IPAddress] = None):
        packet = RIPPacket(
            command=RIPPacketCommand.RESPONSE,
            route_table_entries=self.routing_table,
        )
        if not address:
            for address in self.interfaces:
                self.interfaces[address].sendto(bytes(packet), ("<broadcast>", 520))
        else:
            self.interfaces[self.find_interface_for_address(address)].sendto(bytes(packet), (address.ip, 520))

    def send_request(self):
        packet = RIPPacket(command=RIPPacketCommand.REQUEST)
        for address in self.interfaces:
            self.interfaces[address].sendto(bytes(packet), (address.ip, 520))

    def update_timer(self):
        while True:
            self.send_update()
            time.sleep(30)

    def age_timer(self, route: RIPRouteTableEntry):
        while route.age_timer > 0:
            time.sleep(1)
            route.age_timer -= 1
        route.metric = 16
        logger.info(f"Age timer for route {route} expired, starting gc")
        threading.Thread(target=self.garbage_collect_timer, args=(route,)).start()

    def garbage_collect_timer(self, route: RIPRouteTableEntry):
        while route.gc_timer > 0:
            time.sleep(1)
            route.gc_timer -= 1
            if route.metric < 16:
                logger.info(f"Route {route} was refreshed, starting age timer")
                # cancel the gc timer, restart the age timer
                threading.Thread(target=self.age_timer, args=(route,)).start()
                return
        logger.info(f"Route {route} gc timer expired, removing route")
        # gc timer expired with no update
        self.routing_table.remove(route)

    def run(self):
        threading.Thread(target=self.broadcast_response_handler).start()
        threading.Thread(target=self.update_timer).start()
        while True:
            print("====================================================================")
            for route in self.routing_table:
                print(route)
            print("====================================================================")
            time.sleep(5)


a = Router()
a.run()
