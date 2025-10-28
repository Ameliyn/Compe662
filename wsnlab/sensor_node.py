import random
from enum import Enum
import sys
sys.path.insert(1, '.')
from source import wsnlab_vis as wsn
import math
from source import config
from collections import Counter


import csv  # <— add this near your other imports

# Track where each node is placed
NODE_POS = {}  # {node_id: (x, y)}

# --- tracking containers ---
ALL_NODES = []              # node objects
CLUSTER_HEADS = []
ROLE_COUNTS = Counter()     # live tally per Roles enum

def _addr_str(a): return "" if a is None else str(a)
def _role_name(r): return r.name if hasattr(r, "name") else str(r)

Roles = Enum('Roles', 'ROOT CLUSTER_HEAD ROUTER REGISTERED UNREGISTERED UNDISCOVERED')
"""Enumeration of roles"""

class NodeInformation():
    """A dataclass to store information about other nodes."""
    def __init__(self,
                 gui: int,
                 addr: wsn.Addr,
                 role: Roles,
                 hop_count: int,
                 arrival_time: float,
                 distance: float,
                 networks: set[int]):
        self.gui = gui
        """Globally Unique ID"""
        self.addr = addr
        """Dynamic Address"""
        self.role = role
        """Role"""
        self.hop_count = hop_count
        """Hops to Root"""
        self.arrival_time = arrival_time
        """Arrival Time."""
        self.distance = distance
        """Distance from Self"""
        self.networks = networks
        """Networks Reachable"""

    def __str__(self):
        return ("{"f'gui: {self.gui}, addr: {self.addr}, role: {self.role}, '
                f'hop_count: {self.hop_count}, arrival_time: {self.arrival_time}, '
                f'distance: {self.distance}, networks: {self.networks}'"}")
    
    def __repr__(self):
        return self.__str__()


###########################################################
class SensorNode(wsn.Node):
    """SensorNode class is inherited from Node class in wsnlab.py.
    It will run data collection tree construction algorithms.

    Attributes:
        role (Roles): role of node
        is_root_eligible (bool): keeps eligibility to be root
        c_probe (int): probe message counter
        th_probe (int): probe message threshold
        neighbors_table (Dict): keeps the neighbor information with received heart beat messages
    """
    ###################
    def init(self, ROOT_ELIGABLE = False):
        """Initialization of node. Setting all attributes of node.
        At the beginning node needs to be sleeping and its role should be UNDISCOVERED.

        Args:

        Returns:

        """
        self.scene.nodecolor(self.id, 1, 1, 1) # sets self color to white
        self.sleep()
        self.addr: wsn.Addr = None
        self.parent_gui: int = None
        self.root_addr: wsn.Addr = None
        self.set_role(Roles.UNDISCOVERED)
        self.c_probe = 0  # c means counter and probe is the name of counter
        self.th_probe = 10  # th means threshold and probe is the name of threshold
        self.hop_count = 99999
        self.neighbors_table: dict[int, NodeInformation] = {} # keeps neighbor information with received HB messages
        self.candidate_parents_table: list[int] = []
        self.networking_table: dict[int, NodeInformation] = {}
        self.members_table: list[int] = []
        self.received_JR_guis: list[int] = []  # keeps received Join Request global unique ids

    ###################
    def run(self):
        """Setting the arrival timer to wake up after firing.

        Args:

        Returns:

        """
        self.set_timer('TIMER_ARRIVAL', self.arrival)

    ###################

    def set_role(self, new_role: Roles, *, recolor=True):
        """Central place to switch roles, keep tallies, and (optionally) recolor."""
        old_role = getattr(self, "role", None)
        if old_role is not None:
            ROLE_COUNTS[old_role] -= 1
            if ROLE_COUNTS[old_role] <= 0:
                ROLE_COUNTS.pop(old_role, None)
        ROLE_COUNTS[new_role] += 1
        self.role = new_role

        if recolor:
            if new_role == Roles.UNDISCOVERED:
                self.scene.nodecolor(self.id, 1, 1, 1)
            elif new_role == Roles.UNREGISTERED:
                self.scene.nodecolor(self.id, 1, 1, 0)
            elif new_role == Roles.REGISTERED:
                self.scene.nodecolor(self.id, 0, 1, 0)
            elif new_role == Roles.ROUTER:
                self.scene.nodecolor(self.id, 0, 0.75, 0.5)
            elif new_role == Roles.CLUSTER_HEAD:
                self.scene.nodecolor(self.id, 0, 0, 1)
                self.draw_tx_range()
            elif new_role == Roles.ROOT:
                self.scene.nodecolor(self.id, 0, 0, 0)
                self.set_timer('TIMER_EXPORT_CH_CSV', config.EXPORT_CH_CSV_INTERVAL)
                self.set_timer('TIMER_EXPORT_NEIGHBOR_CSV', config.EXPORT_NEIGHBOR_CSV_INTERVAL)

    def become_unregistered(self):
        if self.role != Roles.UNDISCOVERED:
            self.kill_all_timers()
            self.log('I became UNREGISTERED')
        self.scene.nodecolor(self.id, 1, 1, 0)
        self.erase_parent()
        self.addr: wsn.Addr = None
        self.parent_gui: int = None
        self.root_addr: wsn.Addr = None
        self.set_role(Roles.UNREGISTERED)
        self.c_probe = 0
        self.th_probe = 10
        self.hop_count = 99999
        self.neighbors_table: dict[int, NodeInformation] = {}
        self.candidate_parents_table: list[int] = []
        self.networking_table: dict[int, NodeInformation] = {}
        self.members_table: list[int] = []
        self.received_JR_guis: list[int] = []  # keeps received Join Request global unique ids
        self.send_probe()
        self.set_timer('TIMER_JOIN_REQUEST', 20)

    ###################
    def update_neighbor(self, pck: dict):
        pck['arrival_time'] = self.now
        # compute Euclidean distance between self and neighbor
        if pck['gui'] in NODE_POS and self.id in NODE_POS:
            x1, y1 = NODE_POS[self.id]
            x2, y2 = NODE_POS[pck['gui']]
            pck['distance'] = math.hypot(x1 - x2, y1 - y2)
        # self.neighbors_table[pck['gui']] = pck
        self.neighbors_table[pck['gui']] = NodeInformation(
            gui=pck['gui'], 
            addr=pck['source'], 
            hop_count=pck['hop_count'], 
            distance=pck['distance'] if 'distance' in pck.keys() else -1,
            arrival_time=pck['arrival_time'],
            role=pck['role'],
            networks=pck['networks'] if 'networks' in pck.keys() else [pck['source'].net_addr])
        self.networking_table[pck['gui']] = NodeInformation(
            gui=pck['gui'], 
            addr=pck['source'], 
            hop_count=pck['hop_count'], 
            distance=pck['distance'] if 'distance' in pck.keys() else -1,
            arrival_time=pck['arrival_time'],
            role=pck['role'],
            networks=pck['networks'] if 'networks' in pck.keys() else [pck['source'].net_addr])

        if pck['gui'] not in self.networking_table.keys() or pck['gui'] not in self.members_table:
            if pck['gui'] not in self.candidate_parents_table:
                self.candidate_parents_table.append(pck['gui'])

    ###################
    def select_and_join(self):
        min_hop = 99999
        min_hop_gui = 99999
        for gui in self.candidate_parents_table:
            if self.neighbors_table[gui].hop_count < min_hop or (self.neighbors_table[gui].hop_count == min_hop and gui < min_hop_gui):
                min_hop = self.neighbors_table[gui].hop_count
                min_hop_gui = gui
        selected_addr = self.neighbors_table[min_hop_gui].addr
        self.send_join_request(selected_addr)
        self.set_timer('TIMER_JOIN_REQUEST', 5)

    ###################
    def send_probe(self):
        """Sending probe message to be discovered and registered.

        Args:

        Returns:

        """
        self.send({'dest': wsn.BROADCAST_ADDR, 'type': 'PROBE', 'ttl': config.PACKET_TTL})

    ###################
    def send_heart_beat(self):
        """Sending heart beat message

        Args:

        Returns:

        """
        child_networks = set()
        child_networks.add(self.addr.net_addr)
        for gui, nodes in self.neighbors_table.items():
            # child_networks.append(nodes.addr.net_addr)
            child_networks.update(nodes.networks)

        self.send({'dest': wsn.BROADCAST_ADDR,
                   'type': 'HEART_BEAT',
                   'source': self.addr,
                   'gui': self.id,
                   'role': self.role,
                   'addr': self.addr,
                   'hop_count': self.hop_count,
                   'networks': set(child_networks), 
                   'ttl': config.PACKET_TTL})

    ###################
    def send_join_request(self, dest: wsn.Addr):
        """Sending join request message to given destination address to join destination network

        Args:
            dest (Addr): Address of destination node
        Returns:

        """
        self.send({'dest': dest, 'type': 'JOIN_REQUEST', 'gui': self.id, 'ttl': config.PACKET_TTL})

    ###################
    def send_join_reply(self, gui: int, addr: wsn.Addr):
        """Sending join reply message to register the node requested to join.
        The message includes a gui to determine which node will take this reply, an addr to be assigned to the node
        and a root_addr.

        Args:
            gui (int): Global unique ID
            addr (Addr): Address that will be assigned to new registered node
        Returns:

        """
        self.send({'dest': wsn.BROADCAST_ADDR, 'type': 'JOIN_REPLY', 'source': self.addr,
                   'gui': self.id, 'dest_gui': gui, 'addr': addr, 'root_addr': self.root_addr,
                   'hop_count': self.hop_count+1, 'ttl': config.PACKET_TTL})

    ###################
    def send_join_ack(self, dest: wsn.Addr):
        """Sending join acknowledgement message to given destination address.

        Args:
            dest (Addr): Address of destination node
        Returns:

        """
        self.route_and_forward_package({'dest': dest, 'type': 'JOIN_ACK', 'source': self.addr,
                   'gui': self.id})

    ###################
    def send_network_request(self):
        """Sending network request message to root address to be cluster head

        Args:

        Returns:

        """
        self.route_and_forward_package({'dest': self.root_addr, 'type': 'NETWORK_REQUEST', 'source': self.addr})

    ###################
    def send_network_reply(self, dest: wsn.Addr, addr: wsn.Addr):
        """Sending network reply message to dest address to be cluster head with a new adress

        Args:
            dest (Addr): destination address
            addr (Addr): cluster head address of new network

        Returns:

        """
        self.route_and_forward_package({'dest': dest, 'type': 'NETWORK_REPLY', 'source': self.addr, 'addr': addr})

    ###################
    def send_network_update(self):
        """Sending network update message to parent

        Args:

        Returns:

        """
        child_networks = set()
        child_networks.add(self.addr.net_addr)
        for gui, nodes in self.neighbors_table.items():
            # child_networks.append(nodes.addr.net_addr)
            child_networks.update(nodes.networks)

        self.route_and_forward_package({'dest': self.root_addr, 'type': 'NETWORK_UPDATE', 'source': self.addr,
                   'gui': self.id, 'child_networks': child_networks})

    ###################
    def route_and_forward_package(self, pck: dict):
        """Routing and forwarding given package

        Args:
            pck (Dict): package to route and forward it should contain dest, source and type.
        Returns:

        """
        try:
            assert(isinstance(pck['dest'], wsn.Addr))
        except Exception as e:
            print(f'ERROR PACKET: {pck}')
            raise e

        if 'next_hop' not in pck.keys():
            pck['next_hop'] = self.addr

        # If the destination is in our neighbor table, next_hop = dest
        for gui, node in self.neighbors_table.items():
            if pck['dest'] == node.addr:
                pck['next_hop'] = node.addr
                break

        # If the destination's network is in our neighbor table, next_hop = dest_net
        if pck['next_hop'] == self.addr:
            for gui, node in self.neighbors_table.items():
                if pck['dest'].net_addr == node.addr.net_addr:
                    pck['next_hop'] = node.addr
                    break

        # If the destination's network is in our networking table, next_hop = dest_net
        if pck['next_hop'] == self.addr:
            # Check networking table
            for gui, node in self.networking_table.items():
                if pck['dest'].net_addr in node.networks or pck['dest'].net_addr == node.addr.net_addr:
                    pck['next_hop'] = self.neighbors_table[gui].addr
                    break
        
        # Finally if all else fails, send the packet towards ROOT
        if pck['next_hop'] == self.addr:
            if self.role == Roles.ROOT:
                print(f'ERROR: {self.parent_gui} not in NEIGHBOR TABLE (self: {self.addr})')
                print(f'Networking Table {self.networking_table}')
                print(f'Neighbor Table: {self.neighbors_table}')
                print(f'{pck}')
                raise Exception(f"ERROR: ROOT HAS NO PATH TO: {pck['dest']}")
            for gui, networks in self.networking_table.items():
                if self.root_addr.net_addr in networks.networks:
                    pck['next_hop'] = self.neighbors_table[gui].addr
                    break

        if pck['next_hop'] == self.addr:
            raise Exception(f'UNROUTABLE PACKET FROM ({self.id}): {pck}\nNet Table: {self.networking_table}\nNeigh Table: {self.neighbors_table}')
        if 'ttl' not in pck.keys():
            pck['ttl'] = config.PACKET_TTL
        else:
            pck['ttl'] -= 1
        self.send(pck)

    ###################
    def on_receive(self, pck: dict):
        """Executes when a package received.

        Args:
            pck (Dict): received package
        Returns:

        """
        try:
            if pck['dest'] == wsn.BROADCAST_ADDR or pck['dest'] == self.addr or pck['type'] == 'NETWORK_UPDATE':
                # Process Packet
                self.process_packet(pck)
                pass
            elif 'next_hop' in pck.keys() and pck['next_hop'] == self.addr:
                # Route Packet
                if pck['ttl'] <= 0:
                    return
                self.route_and_forward_package(pck)
            else:
                # Packet is not for us
                pass
        except AttributeError as e:
            print(f'{pck}')
            raise e

    def process_packet(self, pck: dict):
        """Process an incoming packet that is assigned to us.

        Args:
            pck (Dict): received package
        Returns:        
        """
        # assert(pck['dest'] == self.addr or pck['dest'] == wsn.BROADCAST_ADDR)

        if self.role == Roles.ROOT or self.role == Roles.CLUSTER_HEAD or self.role == Roles.ROUTER:  # if the node is root or cluster head
            if pck['type'] == 'HEART_BEAT':
                self.update_neighbor(pck)
            if pck['type'] == 'PROBE':  # it waits and sends heart beat message once received probe message
                # yield self.timeout(.5)
                self.send_heart_beat()
            if pck['type'] == 'JOIN_REQUEST':  # it waits and sends join reply message once received join request
                # yield self.timeout(.5)
                self.send_join_reply(pck['gui'], wsn.Addr(self.addr.net_addr, pck['gui']))
            if pck['type'] == 'NETWORK_REQUEST':  # it sends a network reply to requested node
                # yield self.timeout(.5)
                if self.role == Roles.ROOT:
                    new_addr = wsn.Addr(pck['source'].node_addr,254)
                    self.send_network_reply(pck['source'],new_addr)
            if pck['type'] == 'JOIN_ACK':
                self.members_table.append(pck['gui'])
            if pck['type'] == 'NETWORK_UPDATE':
                try:
                    self.networking_table[pck['gui']].networks = pck['child_networks']
                    self.neighbors_table[pck['gui']].networks = pck['child_networks']
                    if self.role != Roles.ROOT:
                        self.send_network_update()
                except Exception as e:
                    print(f'SELF {self.id}\nNET: {self.networking_table}\nNEIGH: {self.neighbors_table}\npck: {pck}')
                    raise e
            if pck['type'] == 'SENSOR':
                pass
                # self.log(str(pck['source'])+'--'+str(pck['sensor_value']))

        elif self.role == Roles.REGISTERED:  # if the node is registered
            if pck['type'] == 'HEART_BEAT':
                self.update_neighbor(pck)
            if pck['type'] == 'PROBE':
                # yield self.timeout(.5)
                self.send_heart_beat()
            if pck['type'] == 'JOIN_REQUEST':  # it sends a network request to the root
                self.received_JR_guis.append(pck['gui'])
                # yield self.timeout(.5)
                self.send_network_request()
            if pck['type'] == 'NETWORK_REPLY':  # it becomes cluster head and send join reply to the candidates
                self.set_role(Roles.CLUSTER_HEAD)
                # try:
                    # write_clusterhead_distances_csv("clusterhead_distances.csv")
                # except Exception as e:
                    # self.log(f"CH CSV export error: {e}")
                self.scene.nodecolor(self.id, 0, 0, 1)
                self.addr = pck['addr']

                self.send_heart_beat()
                self.send_network_update()
                # yield self.timeout(.5)
                self.set_timer('ROUTER_CHECK', config.ROUTER_CHECK_INTERVAL)
                for gui in self.received_JR_guis:
                    # yield self.timeout(random.uniform(.1,.5))
                    self.send_join_reply(gui, wsn.Addr(self.addr.net_addr,gui))

            if pck['type'] == 'NETWORK_UPDATE':
                if pck['gui'] in self.networking_table:
                    self.networking_table[pck['gui']].networks = pck['child_networks']
                    self.neighbors_table[pck['gui']].networks = pck['child_networks']

        elif self.role == Roles.UNDISCOVERED:  # if the node is undiscovered
            if pck['type'] == 'HEART_BEAT':  # it kills probe timer, becomes unregistered and sets join request timer once received heart beat
                self.update_neighbor(pck)
                self.kill_timer('TIMER_PROBE')
                self.become_unregistered()

        if self.role == Roles.UNREGISTERED:  # if the node is unregistered
            if pck['type'] == 'HEART_BEAT':
                self.update_neighbor(pck)
            if pck['type'] == 'JOIN_REPLY':  # it becomes registered and sends join ack if the message is sent to itself once received join reply
                if pck['dest_gui'] == self.id:
                    self.addr = pck['addr']
                    self.parent_gui = pck['gui']
                    self.root_addr = pck['root_addr']
                    self.hop_count = pck['hop_count']
                    self.draw_parent()
                    self.kill_timer('TIMER_JOIN_REQUEST')
                    self.send_heart_beat()
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                    self.send_join_ack(pck['source'])
                    self.set_role(Roles.REGISTERED)
                    # self.send_network_update()
                    # # sensor implementation
                    # timer_duration =  self.id % 20
                    # if timer_duration == 0: timer_duration = 1
                    # self.set_timer('TIMER_SENSOR', timer_duration)

    ###################
    def on_timer_fired(self, name: str, *args, **kwargs):
        """Executes when a timer fired.

        Args:
            name (string): Name of timer.
            *args (string): Additional args.
            **kwargs (string): Additional key word args.
        Returns:

        """
        if name == 'TIMER_ARRIVAL':  # it wakes up and set timer probe once time arrival timer fired
            self.scene.nodecolor(self.id, 1, 0, 0)  # sets self color to red
            self.wake_up()
            self.set_timer('TIMER_PROBE', 1)
            try:
                self.is_root_eligible = getattr(self, 'is_root_eligible')
            except:
                self.is_root_eligible = False

        elif name == 'TIMER_PROBE':  # it sends probe if counter didn't reach the threshold once timer probe fired.
            if self.c_probe < self.th_probe:
                self.send_probe()
                self.c_probe += 1
                self.set_timer('TIMER_PROBE', 1)
            else:  # if the counter reached the threshold
                if self.is_root_eligible:  # if the node is root eligible, it becomes root
                    self.set_role(Roles.ROOT)
                    self.scene.nodecolor(self.id, 0, 0, 0)
                    self.addr = wsn.Addr(self.id, 254)
                    self.root_addr = self.addr
                    self.hop_count = 0
                    self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
                else:  # otherwise it keeps trying to sending probe after a long time
                    self.c_probe = 0
                    self.set_timer('TIMER_PROBE', 30)

        elif name == 'TIMER_HEART_BEAT':  # it sends heart beat message once heart beat timer fired
            self.send_heart_beat()
            self.set_timer('TIMER_HEART_BEAT', config.HEARTH_BEAT_TIME_INTERVAL)
            #print(self.id)

        elif name == 'TIMER_JOIN_REQUEST':  # if it has not received heart beat messages before, it sets timer again and wait heart beat messages once join request timer fired.
            if len(self.candidate_parents_table) == 0:
                self.become_unregistered()
            else:  # otherwise it chose one of them and sends join request
                self.select_and_join()

        elif name == 'TIMER_SENSOR':
            self.route_and_forward_package({'dest': self.root_addr, 'type': 'SENSOR', 'source': self.addr, 'sensor_value': random.uniform(10,50)})
            timer_duration =  self.id % 20
            if timer_duration == 0: timer_duration = 1
            # self.set_timer('TIMER_SENSOR', timer_duration)
        elif name == 'TIMER_EXPORT_CH_CSV':
            # Only root should drive exports (cheap guard)
            if self.role == Roles.ROOT:
                # write_clusterhead_distances_csv("clusterhead_distances.csv")
                # reschedule
                self.set_timer('TIMER_EXPORT_CH_CSV', config.EXPORT_CH_CSV_INTERVAL)
        elif name == 'TIMER_EXPORT_NEIGHBOR_CSV':
            if self.role == Roles.ROOT:
                # write_neighbor_distances_csv("neighbor_distances.csv")
                self.set_timer('TIMER_EXPORT_NEIGHBOR_CSV', config.EXPORT_NEIGHBOR_CSV_INTERVAL)
        elif name == 'ROUTER_CHECK':
            if self.role == Roles.CLUSTER_HEAD:
                other_networks = 0
                for node in self.members_table:
                    if self.neighbors_table[node].addr.net_addr != self.addr.net_addr:
                        other_networks += 1
                if other_networks > 1:
                    print(f'{self.addr} could become router.')
                else:
                    self.set_timer('ROUTER_CHECK', config.ROUTER_CHECK_INTERVAL)
                    # self.become_router()