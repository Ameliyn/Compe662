from dataclasses import dataclass
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

Roles = wsn.Roles

@dataclass
class NodeInformation():
    """A dataclass to store information about other nodes."""
    def __init__(self,
                 gui: int,
                 addr: wsn.Addr,
                 role: Roles,
                 hop_count: int,
                 arrival_time: float,
                 distance: float,
                 networks: set[int],
                 neigbors: list[wsn.Addr]):
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
        self.neighbor_nodes = neigbors

    def update(self, pck: dict):
        for key, value in pck.items():
            if key == 'gui':
                self.gui = value
            elif key == 'addr':
                self.addr = value
            elif key == 'role':
                self.role = value
            elif key == 'hop_count':
                self.hop_count = value
            elif key == 'arrival_time':
                self.arrival_time = value
            elif key == 'distance':
                self.distance = value
            elif key == 'networks':
                self.networks = value
            elif key == 'neighbor_nodes':
                self.neighbor_nodes = value
            else:
                pass
                # raise Exception (f'Key: {key} not found in Node Information Object')
            
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
    def init(self):
        """Initialization of node. Setting all attributes of node.
        At the beginning node needs to be sleeping and its role should be UNDISCOVERED.

        Args:

        Returns:

        """
        self.scene.nodecolor(self.id, 1, 1, 1) # sets self color to white
        self.sleep()
        self.addr: wsn.Addr
        """Our Address [NetworkAddr, DynamicAddr]"""
        self.parent_gui: int
        """Our Parent's ID"""
        self.root_addr: wsn.Addr
        """Root's ID"""
        self.set_role(Roles.UNDISCOVERED)
        self.c_probe: int = 0
        """Probe Counter"""
        self.th_probe: int = 10
        """Probe Threshold"""
        self.hop_count: int = 99999
        """Our Hops to Root"""
        self.neighbors_table: dict[int, NodeInformation] = {}
        """Dictionary of neighbors and Information about them."""
        self.candidate_parents_table: list[int] = []
        """Nearby nodes that are not in our cluster."""
        self.networking_table: dict[int, int] = {}
        """Routing Table"""
        self.members_table: list[int] = []
        """Our cluster members."""
        self.received_JR_guis: list[int] = []
        """List of Join Requests."""
        self.child_networks: set[int] = set()
        """Networks downstream from us"""
        self.arrival: float
        """Arrival time of current node."""
        self.is_faulty: float
        self.processing_packet = False
        self.node_addresses = dict()


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
        self.sim.log_role_change(self.id, self.role)

        if recolor:
            if new_role == Roles.UNDISCOVERED:
                self.scene.nodecolor(self.id, 1, 1, 1)
            elif new_role == Roles.UNREGISTERED:
                self.scene.nodecolor(self.id, 1, 1, 0)
            elif new_role == Roles.REGISTERED:
                self.scene.nodecolor(self.id, 0, 1, 0)
                try:
                    self.is_faulty = getattr(self, 'is_faulty')
                except:
                    self.is_faulty = False
                if self.is_faulty:
                    self.set_timer('FAULTY_NODE', random.randrange(config.FAULTY_NODE_PERIOD[0], config.FAULTY_NODE_PERIOD[1]))
            elif new_role == Roles.ROUTER:
                self.scene.nodecolor(self.id, 0, 1, 1)
            elif new_role == Roles.CLUSTER_HEAD:
                self.scene.nodecolor(self.id, 0, 0, 1)
                self.draw_tx_range()
                self.set_timer('TIMER_NETWORK_UPDATE', config.TIMER_NETWORK_UPDATE_INTERVAL)
                self.assigned_node_ids: dict[int,int] = {254: self.id}
            elif new_role == Roles.ROOT:
                self.scene.nodecolor(self.id, 0, 0, 0)
                self.set_timer('TIMER_EXPORT_CH_CSV', config.EXPORT_CH_CSV_INTERVAL)
                self.set_timer('TIMER_EXPORT_NEIGHBOR_CSV', config.EXPORT_NEIGHBOR_CSV_INTERVAL)
                self.assigned_network_ids: dict[int,int] = {1: self.id}
                self.assigned_node_ids: dict[int,int] = {254: self.id}

    def become_unregistered(self):
        """Reset many variables and become unregistered."""
        if self.role != Roles.UNDISCOVERED:
            self.kill_all_timers()
            if self.addr is not None and self.addr == wsn.Addr(-1,-1):
                pass
            else:
                old_addr = self.addr
                self.addr = wsn.Addr(-1,-1)
                self.send_address_renew(old_addr=old_addr)
            self.log('I became UNREGISTERED')
        
        self.scene.nodecolor(self.id, 1, 1, 0)
        self.erase_parent()
        self.erase_tx_range()


        # Reset Variables
        self.addr: wsn.Addr
        self.parent_gui: int
        self.root_addr: wsn.Addr
        self.c_probe = 0
        self.th_probe = 10
        self.hop_count = 99999
        self.neighbors_table: dict[int, NodeInformation] = {}
        self.candidate_parents_table: list[int] = []
        self.networking_table: dict[int, int] = {}
        self.members_table: list[int] = []
        self.received_JR_guis: list[int] = []  # keeps received Join Request global unique ids
        self.child_networks = set()
        self.processing_packet = False
        self.set_role(Roles.UNREGISTERED)
        self.send_probe()
        self.set_timer('TIMER_JOIN_REQUEST', 20)

    ###################
    def update_neighbor(self, pck: dict):
        if getattr(self, 'root_addr',None) is None and 'root_addr' in pck:
            self.root_addr = pck['root_addr']
        pck['arrival_time'] = self.now
        # compute Euclidean distance between self and neighbor
        if 'pos' in pck.keys() and getattr(self, "pos", None) is not None:
            x1, y1 = self.pos
            x2, y2 = pck['pos']
            pck['distance'] = math.hypot(x1 - x2, y1 - y2)

        # Add source to neighbor Table
        if pck['gui'] in self.neighbors_table:
            # if pck['source'] != self.neighbors_table[pck['gui']].addr:
                # self.log('ADDRESS HAS CHANGED!')
            pck['addr'] = pck['source']
            self.neighbors_table[pck['gui']].update(pck)
            if pck['type'] == 'HEART_BEAT' and pck['parent'] != self.id and pck['gui'] in self.members_table:
                self.log(f'Node has left my children.')
                self.members_table.remove(pck['gui'])
        elif pck['type'] == 'NEIGHBOR_UPDATE':
            self.log('Ignoring neighbor update for someone not in our neighbor table.')
        else:
            self.neighbors_table[pck['gui']] = NodeInformation(
                gui=pck['gui'], 
                addr=pck['source'], 
                hop_count=pck['hop_count'] if 'hop_count' in pck.keys() else -1, 
                distance=pck['distance'] if 'distance' in pck.keys() else -1,
                arrival_time=pck['arrival_time'],
                role=pck['role'],
                networks=pck['networks'] if 'networks' in pck.keys() else set(),
                neigbors=pck['neighbors'] if 'neighbors' in pck.keys() else [])
        
        # Add network to networking table
        self.networking_table[pck['source'].net_addr] = pck['gui']

        # If the neighbor is not in our members table (not our child), add them as a candidate parent
        #TODO: Use for network recovery
        if pck['gui'] not in self.members_table:
            if pck['gui'] not in self.candidate_parents_table:
                self.candidate_parents_table.append(pck['gui'])

    ###################
    def select_and_join(self):
        """Select a node to join based on number of hops to root (minimum distance is tiebreaker).
        
        Args:
        
        Returns:
        
        """
        min_hop = 99999
        min_hop_gui = 99999
        for gui in self.candidate_parents_table:
            if gui not in self.neighbors_table:
                continue
            elif (self.neighbors_table[gui].hop_count < min_hop and self.neighbors_table[gui].addr != wsn.Addr(-1,-1,) and self.neighbors_table[gui].role != Roles.ROUTER or 
                (min_hop_gui != 99999 and self.neighbors_table[gui].hop_count == min_hop and self.neighbors_table[gui].distance < self.neighbors_table[min_hop_gui].distance)):
                min_hop = self.neighbors_table[gui].hop_count
                min_hop_gui = gui
        if min_hop_gui == 99999:
            for gui in self.candidate_parents_table:
                if gui not in self.neighbors_table:
                    continue
                elif (self.neighbors_table[gui].hop_count < min_hop and self.neighbors_table[gui].addr != wsn.Addr(-1,-1,) or 
                    (min_hop_gui != 99999 and self.neighbors_table[gui].hop_count == min_hop and self.neighbors_table[gui].distance < self.neighbors_table[min_hop_gui].distance)):
                    min_hop = self.neighbors_table[gui].hop_count
                    min_hop_gui = gui
            if min_hop_gui == 99999:
                self.log('No Available Addresses')
                self.become_unregistered()
                return
        selected_addr = self.neighbors_table[min_hop_gui].addr
        self.candidate_parents_table.remove(min_hop_gui)
        self.log(f'Sent Join Request to {selected_addr}')
        self.send_join_request(selected_addr)
        self.set_timer('TIMER_JOIN_REQUEST', 5)

    ###################
    def send_probe(self):
        """Sending probe message to be discovered and registered.

        Args:

        Returns:

        """
        self.send({'dest': wsn.BROADCAST_ADDR, 'type': 'PROBE', 'ttl': 1})

    ###################
    def send_heart_beat(self, with_root = False):
        """Sending heart beat message

        Args:

        Returns:

        """
        pck = {'dest': wsn.BROADCAST_ADDR,
                   'type': 'HEART_BEAT',
                   'source': self.addr,
                   'gui': self.id,
                   'role': self.role,
                   'addr': self.addr,
                   'hop_count': self.hop_count,
                   'pos': self.pos,
                   'networks': self.child_networks, 
                   'ttl': config.PACKET_TTL,
                   'parent': self.parent_gui}
        if with_root:
            pck['root_addr'] = self.root_addr
        self.send(pck)

    ###################
    def send_join_request(self, dest: wsn.Addr):
        """Sending join request message to given destination address to join destination network

        Args:
            dest (Addr): Address of destination node
        Returns:

        """
        # TTL = 1 because it should not be routed
        self.send({'dest': dest, 'type': 'JOIN_REQUEST', 'gui': self.id, 'ttl': 1})

    def send_router_request(self, dest: wsn.Addr):
        """Send a request to become a router for the node."""
        self.send({'dest': dest, 'source': self.addr, 'type': 'ROUTER_REQUEST', 'gui': self.id, 'ttl': 1})

    def send_router_reply(self, dest: wsn.Addr, gui: int):
        """Send a router reply to a given node."""
        new_node_id = -1
        for i in range(1,config.CLUSTER_SIZE+1):
            if i not in self.assigned_node_ids.keys():
                new_node_id = i
                break
        pck = {}
        if new_node_id == -1 or self.parent_gui is None or self.neighbors_table[self.parent_gui].role == Roles.ROUTER:
            self.log('Router Requet denied: No children to allocate.')
            pck = {'dest': dest, 'type': 'ROUTER_REPLY', 'source': self.addr,
                    'gui': self.id, 'ttl': 1}
            pck['accepted'] = False
        else:
            self.assigned_node_ids[new_node_id] = gui
            
            pck = {'dest': dest, 'type': 'ROUTER_REPLY', 'source': self.addr,
                    'gui': self.id, 'addr': wsn.Addr(self.addr.net_addr, new_node_id)}
            pck['accepted'] = True

        self.send(pck)
            
    ###################
    def send_join_reply(self, gui: int):
        """Sending join reply message to register the node requested to join.
        The message includes a gui to determine which node will take this reply, an addr to be assigned to the node
        and a root_addr.

        Args:
            gui (int): Global unique ID
            addr (Addr): Address that will be assigned to new registered node
        Returns:

        """
        new_node_id = -1
        for i in range(1,config.CLUSTER_SIZE+1):
            if i not in self.assigned_node_ids.keys():
                new_node_id = i
                break
        if new_node_id == -1:
            self.log('Negative Join Reply: No children to allocate.')
            self.send_negative_join_reply(gui)
        else:
            self.assigned_node_ids[new_node_id] = gui
            self.set_timer('JOIN_ACK_TIMEOUT', 200) #TODO: THIS DOES NOTHING
            self.log(f'Sent Join Reply to: {gui}')
            self.send({'dest': wsn.BROADCAST_ADDR, 'type': 'JOIN_REPLY', 'source': self.addr,
                    'gui': self.id, 'dest_gui': gui, 'addr': wsn.Addr(self.addr.net_addr, new_node_id), 'root_addr': self.root_addr,
                    'hop_count': self.hop_count+1, 'ttl': 1})

    def send_negative_join_reply(self, gui: int):
        """Sending join reply message to register the node requested to join.
        The message includes a gui to determine which node will take this reply, an addr to be assigned to the node
        and a root_addr.

        Args:
            gui (int): Global unique ID
            addr (Addr): Address that will be assigned to new registered node
        Returns:

        """
        # TTL = 1 because it should not be routed
        self.log(f'Sent negative Join Reply to: {gui}')
        self.send({'dest': wsn.BROADCAST_ADDR, 'type': 'NEG_JOIN_REPLY', 'source': self.addr,
                   'gui': self.id, 'dest_gui': gui,'ttl': 1})
    ###################
    def send_join_ack(self, dest: wsn.Addr):
        """Sending join acknowledgement message to given destination address.

        Args:
            dest (Addr): Address of destination node
        Returns:

        """
        # TTL = 1 because it should not be routed
        self.route_and_forward_package({'dest': dest, 'type': 'JOIN_ACK', 'source': self.addr,
                   'gui': self.id, 'ttl': 1})

    ###################
    def send_network_request(self):
        """Sending network request message to root address to be cluster head

        Args:

        Returns:

        """
        if 'NETWORK_REQUEST_TIMEOUT' in self.active_timer_list:
            pass
            # self.log('Not sending new network request because one was already sent and we have not timed out.')
        else:
            self.set_timer('NETWORK_REQUEST_TIMEOUT', config.NETWORK_REQUEST_TIMEOUT)
            self.route_and_forward_package({'dest': self.root_addr, 'type': 'NETWORK_REQUEST', 
                                            'source': self.addr, 'gui': self.id, 'ttl': config.PACKET_TTL})

    ###################
    def send_network_reply(self, pck: dict):
        """Sending network reply message to dest address to be cluster head with a new adress

        Args:
            dest (Addr): destination address
            addr (Addr): cluster head address of new network

        Returns:

        """
        new_net_id = -1
        for net_id, gui in self.assigned_network_ids.items():

            if pck['gui'] == gui:
                self.log('Duplicate Network Request detected... Sending duplicate network reply')
                new_net_id = net_id
                break
        if new_net_id == -1:
            for i in range(1,config.CLUSTER_LIMIT+1):
                if i not in self.assigned_network_ids.keys():
                    new_net_id = i
                    break
            if new_net_id == -1:
                self.log(f'No Networks to Allocate: {self.assigned_network_ids}')
                return
        new_addr = wsn.Addr(new_net_id,254)
        self.assigned_network_ids[new_net_id] = pck['gui']
        self.log(f'Sent network reply to {pck["source"]}')
        pck = {'dest': pck['source'], 'type': 'NETWORK_REPLY', 'source': self.addr, 'addr': new_addr, 'ttl': config.PACKET_TTL}
        # self.log(f'{pck}')
        self.route_and_forward_package(pck)

    ###################
    def send_network_update(self, old_addr: wsn.Addr = wsn.Addr(-1,-1)):
        """Sending network update message to parent

        Args:

        Returns:

        """
        pck = {'dest': self.root_addr, 'type': 'NETWORK_UPDATE', 'source': self.addr,
                   'gui': self.id, 'child_networks': self.child_networks, 'ttl': 1}
        if old_addr != wsn.Addr(-1,-1):
            pck['old_addr'] = old_addr
        self.route_and_forward_package(pck)

    def send_address_renew(self, old_addr: wsn.Addr):
        """Sending network update message to parent

        Args:

        Returns:

        """
        if old_addr == wsn.Addr(-1,-1):
            raise Exception('Bad Address Renew')
        pck = {'dest': wsn.BROADCAST_ADDR, 'type': 'ADDRESS_RENEW', 'source': self.addr,
                   'gui': self.id, 'role': self.role, 'ttl': 1, 'parent': self.parent_gui}
        pck['old_addr'] = old_addr
        pck['new_addr'] = self.addr
        self.send(pck)

    def send_neighbor_table(self):
        """Sending network update message to parent

        Args:

        Returns:

        """
        neighbors = []
        for gui, node in self.neighbors_table.items():
            neighbors.append(node.addr)
        pck = {'dest': wsn.BROADCAST_ADDR, 'type': 'NEIGHBOR_UPDATE', 'source': self.addr,
                   'gui': self.id, 'ttl': 1, 'neighbors': neighbors}
        self.send(pck)

    def send_promote_reply(self, pck: dict):
        """Response to a PROMOTE_REQUEST
        """
        promote_reply_pck = {'type': 'PROMOTE_REPLY','assigned_addr': pck['source'], 'source': self.addr, 'gui': self.id, 
                             'dest': pck['source'], 'next_hop': pck['source'], 'role': Roles.ROUTER}
        if pck['gui'] == self.parent_gui:
            promote_reply_pck['role'] = Roles.ROUTER
        else:
            promote_reply_pck['role'] = Roles.UNREGISTERED
        self.send(promote_reply_pck)

    def send_promote_request(self, addr: wsn.Addr):
        """Request to transfer cluster head ownership."""
        promote_req_pck = {'type': 'PROMOTE_REQUEST', 'source': self.addr, 'dest': addr, 'next_hop': addr, 'gui': self.id, 'assigned_addr': self.addr, 'role': Roles.CLUSTER_HEAD}
        self.send(promote_req_pck)

    ###################
    def route_and_forward_package(self, pck: dict, avoid_nodes: list = []):
        """Routing and forwarding given package

        Args:
            pck (Dict): package to route and forward it should contain dest, source and type.
        Returns:

        """
        if 'hop_trace' in pck.keys():
            for (id, time) in pck['hop_trace']:
                if id == self.addr:
                    self.log(f'Circular Routing Detected: {pck}')
                    return


        temp_neighbor_list: dict[int, NodeInformation] = {}
        for gui, node in self.neighbors_table.items():
            if gui not in avoid_nodes:
                temp_neighbor_list[gui] = node

        try:
            assert(isinstance(pck['dest'], wsn.Addr))
            assert(pck['dest'] != self.addr)
        except Exception as e:
            print(f'ERROR PACKET: {pck}')
            raise e
        # If the Time to Live is <= 0, don't route the packet
        if pck['ttl'] <= 0:
            if config.LOG_LEVEL == 'DEBUG':
                print(f'Current: {self.id} Packet Died: {pck}')
            return

        next_gui = self.id

        if 'next_hop' not in pck.keys():
            pck['next_hop'] = self.addr

        # If the destination is in our neighbor table, next_hop = dest
        for gui, node in temp_neighbor_list.items():
            if pck['dest'] == node.addr:
                next_gui = gui
                pck['next_hop'] = node.addr
                pck['routed_type'] = 'Neighbors Table'
                break

        for gui, node in temp_neighbor_list.items():
            if pck['dest'] in node.neighbor_nodes:
                next_gui = gui
                pck['next_hop'] = node.addr
                pck['routed_type'] = 'Neighbors Table (MultiHop)'
                break

        # If the destination's network is in our neighbor table, next_hop = dest_net
        if pck['next_hop'] == self.addr:
            for gui, node in temp_neighbor_list.items():
                # if pck['dest'].net_addr == node.addr.net_addr or (pck['dest'].net_addr in node.networks and node.hop_count > self.hop_count):
                if pck['dest'].net_addr == node.addr.net_addr:
                    next_gui = gui
                    pck['next_hop'] = node.addr
                    pck['routed_type'] = 'Neighbor Network'
                    break

        # If the destination's network is in our networking table, next_hop = dest_net
        if pck['next_hop'] == self.addr:
            # Check networking table
            for network, hop in self.networking_table.items():
                if hop != self.parent_gui and pck['dest'].net_addr == network and hop in temp_neighbor_list:
                    pck['next_hop'] = temp_neighbor_list[hop].addr
                    next_gui = hop
                    pck['routed_type'] = 'Networking Table'
                    break
        
        # Finally if all else fails, send the packet towards ROOT
        if pck['next_hop'] == self.addr:
            if self.role == Roles.ROOT:
                # if config.LOG_LEVEL == "DEBUG":
                self.log(f'ROOT UNABLE TO FIND ROUTE TO: {pck["dest"]}')
                self.log(f'Networking Table {self.networking_table}')
                self.log(f'Neighbor Table: {self.neighbors_table}')
                self.log(f'{pck}')
                return
            pck['routed_type'] = 'Parent'
            pck['next_hop'] = temp_neighbor_list[self.parent_gui].addr
            next_gui = self.parent_gui

        if pck['next_hop'] == self.addr:
            self.log('CANNOT ROUTE PACKET')
            return #TODO: Send NACK
        elif pck['next_hop'] == wsn.Addr(-1,-1):
            self.log('Attempted to route to dead node. retrying')
            pck['next_hop'] = self.addr
            avoid_nodes.append(next_gui)
            self.route_and_forward_package(pck, avoid_nodes=avoid_nodes)

        if 'ttl' not in pck.keys():
            pck['ttl'] = config.PACKET_TTL
        else:
            pck['ttl'] -= 1
        
        if 'hop_trace' not in pck.keys():
            pck['hop_trace'] = [(self.addr, self.now)]
        else:
            pck['hop_trace'].append((self.addr, self.now))
        
        self.log(f'{self.id}.{self.addr} Sending {pck["type"]} to {pck["dest"]} through {next_gui}.{pck["next_hop"]}'
                 f' (selected by {pck["routed_type"]})')
        self.send(pck)
        
    ###################
    def on_receive(self, pck: dict):
        """Executes when a package received.

        Args:
            pck (Dict): received package
        Returns:

        """
        try:
            if config.USE_BATTERY_POWER and self.charge < 0 and self.role != Roles.ROOT and 'CHARGE_TIMER' not in self.active_timer_list and self.addr != wsn.Addr(-1,-1):
                self.kill_all_timers()
                old_addr = self.addr
                self.addr = wsn.Addr(-1,-1)
                self.send_address_renew(old_addr=old_addr)
                self.set_timer('CHARGE_TIMER', config.NODE_CHARGE_TIME)
                self.log('I ran out of power.')
                self.sleep()
                return
            
            elif (pck['type'] == 'NETWORK_UPDATE' and pck['child_networks'] is not None) or pck['type'] == 'ADDRESS_RENEW':
                self.process_packet(pck.copy())

            # If we are the destination, process the packet
            elif pck['dest'] == wsn.BROADCAST_ADDR or pck['dest'] == self.addr:
                self.process_packet(pck.copy())
                pass
            
            # If we are the next hop, route the packet
            elif 'next_hop' in pck.keys() and pck['next_hop'] == self.addr:
                self.route_and_forward_package(pck.copy())
            
            # Packet is not for us            
            else:
                pass

        except Exception as e:
            print(f'{e}')
            print(f'{pck}')

    def process_packet(self, pck: dict):
        """Process an incoming packet that is assigned to us.

        Args:
            pck (Dict): received package
        Returns:        
        """
        pck['receive_time'] = self.now
        self.sim.log_packet(pck, 'receive', self.id)
        while self.processing_packet:
            self.log('Trying to process multiple packets at once...')
            # yield self.timeout(0.5)
            return

        self.processing_packet = True
        if pck['type'] == 'NETWORK_UPDATE' and pck['child_networks'] is not None and pck['gui'] in self.neighbors_table:
            
            self.neighbors_table[pck['gui']].networks = pck['child_networks']
            
            for entry in pck['child_networks']:
                if entry != self.addr.net_addr:
                    self.networking_table[entry] = pck['gui']
                    
                    # raise Exception("Our network marked as their child network.")
                        
            if self.role != Roles.ROOT:                    
                if pck['gui'] != self.parent_gui:
                    self.child_networks.update(pck['child_networks'])
                    self.child_networks.add(pck['source'].net_addr)
                if pck['next_hop'] == self.addr:   
                   self.send_network_update()
            self.processing_packet = False
            return
    
        elif pck['type'] == 'ADDRESS_RENEW':
            self.log(f'ADDRESS RENEW: {pck["old_addr"]} -> {pck["new_addr"]}')

            # Node is leaving!
            if pck['new_addr'] == wsn.Addr(-1,-1):
                if pck['gui'] == self.parent_gui:
                    self.log('Parent is leaving!')
                    self.become_unregistered()
                    self.processing_packet = False
                    return
                elif self.role == Roles.ROOT:
                    if pck['old_addr'].net_addr in self.assigned_network_ids.keys() and self.assigned_network_ids[pck['old_addr'].net_addr] == pck['gui']:
                        self.log(f'Cluster: {pck["old_addr"].net_addr} removed.')
                        self.assigned_network_ids.pop(pck['old_addr'].net_addr)
            
            # Update neighbors table
            if pck['gui'] in self.neighbors_table:
                self.update_neighbor(pck)
                # self.neighbors_table[pck['gui']].addr = pck['new_addr']
            else:
                if pck['gui'] in self.node_addresses and self.node_addresses[pck['gui']] != pck['new_addr']:
                    self.node_addresses[pck['gui']] = pck['new_addr']
                    self.send(pck)
                else:
                    self.node_addresses[pck['gui']] = pck['new_addr']
                    # self.send(pck)

            if ((self.role == Roles.CLUSTER_HEAD or self.role == Roles.ROOT)
                and pck['gui'] in self.members_table 
                and pck['new_addr'].net_addr != self.addr.net_addr
                and pck['old_addr'].node_addr in self.assigned_node_ids.keys()):
                self.log(f'Removing {self.assigned_node_ids.pop(pck["old_addr"].node_addr)} from my assigned node ids.')

            if pck['gui'] == self.parent_gui and pck['role'] not in [Roles.CLUSTER_HEAD, Roles.ROOT]:
                self.become_unregistered()
                return
            
        elif pck['type'] == 'NEIGHBOR_UPDATE':
            self.update_neighbor(pck)
        
        
        elif self.role == Roles.ROOT or self.role == Roles.CLUSTER_HEAD:  # if the node is root or cluster head
            if pck['type'] == 'HEART_BEAT':
                self.update_neighbor(pck)
            if pck['type'] == 'PROBE':  # it waits and sends heart beat message once received probe message
                self.send_heart_beat(with_root = True)
            if pck['type'] == 'JOIN_REQUEST':  # it waits and sends join reply message once received join request
                self.send_join_reply(pck['gui'])
            if pck['type'] == 'NETWORK_REQUEST':  # it sends a network reply to requested node
                if self.role == Roles.ROOT:
                    self.send_network_reply(pck)
            if pck['type'] == 'JOIN_ACK':
                self.members_table.append(pck['gui'])
                # if len(self.members_table) == 1:
                    # self.send_promote_request(pck['source'])
            if pck['type'] == 'SENSOR':
                pass
            if pck['type'] == 'ROUTER_REQUEST':
                self.log(f'Heard ROUTER_REQUEST from: {pck["source"]}')
                self.send_router_reply(pck['source'], pck['gui'])
            if pck['type'] == 'ROUTER_REPLY' and pck['accepted']:
                self.log(f'Heard ROUTER_REPLY from: {pck["source"]}')
                old_addr = self.addr
                self.addr = pck['addr']
                self.send_address_renew(old_addr=old_addr)

                self.send_heart_beat()
                self.erase_tx_range()
                self.set_role(Roles.ROUTER)

                self.set_timer('ROUTER_NECESSITY_CHECK', config.ROUTER_CHECK_INTERVAL)
            elif pck['type'] == 'PROMOTE_REPLY' and self.role != Roles.ROOT:
                if pck['role'] == Roles.UNREGISTERED:
                    self.become_unregistered()
                else:
                    if pck['role'] == Roles.ROUTER:
                        self.set_timer('ROUTER_NECESSITY_CHECK', config.ROUTER_CHECK_INTERVAL)
                        
                    old_addr = self.addr
                    self.addr = pck['assigned_addr']
                    self.send_address_renew(old_addr=old_addr)
                    self.erase_tx_range()

                    self.set_role(pck['role'])
            elif pck['type'] == 'PROMOTE_REQUEST' and self.role != Roles.ROOT:
                self.send_promote_reply(pck)
        
        elif self.role == Roles.ROUTER:
            if pck['type'] == 'HEART_BEAT':
                self.update_neighbor(pck)
            if pck['type'] == 'JOIN_REQUEST':
                self.become_unregistered()
        elif self.role == Roles.REGISTERED:  # if the node is registered
            if pck['type'] == 'HEART_BEAT':
                self.update_neighbor(pck)
            if pck['type'] == 'PROBE':
                # yield self.timeout(.5)
                self.send_heart_beat()
            if pck['type'] == 'JOIN_REQUEST':  # it sends a network request to the root
                self.log(f'Heard Join Request from {pck["gui"]}')
                self.received_JR_guis.append(pck['gui'])
                # yield self.timeout(.5)
                self.send_network_request()
            if pck['type'] == 'NETWORK_REPLY':  # it becomes cluster head and send join reply to the candidates
                self.set_role(Roles.CLUSTER_HEAD)
                self.kill_timer('NETWORK_REQUEST_TIMEOUT')
                self.scene.nodecolor(self.id, 0, 0, 1)
                old_addr = self.addr
                self.addr = pck['addr']
                self.send_address_renew(old_addr=old_addr)
                self.send_heart_beat()
                self.send_network_update(old_addr)
                
                for gui in self.received_JR_guis:
                    self.send_join_reply(gui)
                if self.role != Roles.ROOT:
                    self.set_timer('ROUTER_CHECK', config.ROUTER_CHECK_INTERVAL)
            if pck['type'] == 'KICK':
                self.become_unregistered()
            if pck['type'] == 'PROMOTE':
                self.send_network_request()
            if pck['type'] == 'PROMOTE_REQUEST':
                if self.addr is None or self.addr == wsn.Addr(-1,-1) or pck['assigned_addr'].net_addr == self.addr.net_addr:
                    if self.role == Roles.UNREGISTERED: 
                        self.parent_gui = pck['gui']
                    self.send_promote_reply(pck)
                    self.set_role(Roles.CLUSTER_HEAD)
                    self.scene.nodecolor(self.id, 0, 0, 1)
                    old_addr = self.addr
                    self.addr = pck['assigned_addr']
                    self.send_address_renew(old_addr=old_addr)
                    self.send_heart_beat()
                    self.send_network_update(old_addr)                
                    self.set_timer('ROUTER_CHECK', config.ROUTER_CHECK_INTERVAL)

        elif self.role == Roles.UNDISCOVERED:  # if the node is undiscovered
            if pck['type'] == 'HEART_BEAT':  # it kills probe timer, becomes unregistered and sets join request timer once received heart beat
                self.update_neighbor(pck)
                self.kill_timer('TIMER_PROBE')
                self.become_unregistered()

        elif self.role == Roles.UNREGISTERED:  # if the node is unregistered
            if pck['type'] == 'HEART_BEAT':
                self.update_neighbor(pck)
            if pck['type'] == 'JOIN_REPLY':  # it becomes registered and sends join ack if the message is sent to itself once received join reply
                if pck['dest_gui'] == self.id:
                    self.log(f'Heard Join Reply from: {pck["source"]}')
                    self.addr = pck['addr']
                    if self.parent_gui is not None:
                        self.erase_parent()
                    self.parent_gui = pck['gui']
                    self.root_addr = pck['root_addr']
                    self.hop_count = pck['hop_count']
                    self.neighbors_table[pck['gui']].addr = pck['source']
                    self.neighbors_table[pck['gui']].role = Roles.CLUSTER_HEAD
                    self.draw_parent()
                    self.kill_timer('TIMER_JOIN_REQUEST')
                    self.send_heart_beat()
                    self.set_timer('TIMER_HEART_BEAT', config.HEART_BEAT_TIME_INTERVAL)
                    self.set_timer('TIMER_NEIGHBOR_PUBLISH', config.NEIGHBOR_PUBLISH_INTERVAL)
                    self.send_join_ack(pck['source'])
                    self.set_role(Roles.REGISTERED)
                    # self.send_network_update()
                    # # sensor implementation
                    if config.DO_SENSOR_MESSAGES:
                        timer_duration =  self.id % 20
                        if timer_duration == 0: timer_duration = 1
                        self.set_timer('TIMER_SENSOR', timer_duration)
        if pck['type'] == 'NEG_JOIN_REPLY' and pck['dest_gui']:
            try:
                self.candidate_parents_table.remove(pck['gui'])
            except:
                pass

        self.processing_packet = False
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
                self.hop_count = 0
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
                    self.addr = wsn.Addr(1, 254)
                    self.root_addr = self.addr
                    self.hop_count = 0
                    self.draw_tx_range()
                    self.set_timer('TIMER_HEART_BEAT', config.HEART_BEAT_TIME_INTERVAL)
                else:  # otherwise it keeps trying to sending probe after a long time
                    self.c_probe = 0
                    self.set_timer('TIMER_PROBE', 30)

        elif name == 'TIMER_HEART_BEAT':  # it sends heart beat message once heart beat timer fired
            self.send_heart_beat()
            self.set_timer('TIMER_HEART_BEAT', config.HEART_BEAT_TIME_INTERVAL)
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
        elif name == 'TIMER_NETWORK_UPDATE_INTERVAL':
            self.send_network_update()
            self.set_timer('TIMER_NETWORK_UPDATE_INTERVAL', config.TIMER_NETWORK_UPDATE_INTERVAL)
        elif name == 'ROUTER_CHECK':
            try:
                if self.role != Roles.CLUSTER_HEAD:
                    return
                elif len(self.members_table) == 0 and self.neighbors_table[self.parent_gui].role != Roles.ROUTER:
                    self.become_unregistered()
                elif len(self.members_table) == 1 and self.neighbors_table[self.members_table[0]].role == Roles.REGISTERED:
                    self.send_promote_request(self.neighbors_table[self.members_table[0]].addr)
                
                elif config.ALLOW_ROUTERS and self.role == Roles.CLUSTER_HEAD and len(self.members_table) > 0 and self.neighbors_table[self.parent_gui].role != Roles.ROUTER:
                    # become_router = False
                    # child = None
                    # if self.neighbors_table[self.parent_gui].role == Roles.CLUSTER_HEAD:
                    #     for gui, node in self.neighbors_table.items():
                    #         if node.role == Roles.CLUSTER_HEAD and gui != self.parent_gui:
                    #             become_router = True
                    #             child = self.neighbors_table[gui].addr
                    #             break
                    # if become_router and child is not None:
                    #     self.send_router_request(child)
                    other_networks = 0
                    # best_child = [self.members_table[0], -1]
                    best_child = None
                    for gui, node in self.neighbors_table.items():
                        if best_child is None and gui in self.members_table:
                            best_child = node
                        if node.role == Roles.CLUSTER_HEAD:
                            other_networks += 1
                            if best_child is not None and len(node.networks) > len(best_child.networks) and node.role != Roles.ROUTER:
                                best_child = node
                        elif node.gui in self.members_table and node.role == Roles.ROUTER:
                            self.log('Unable to become a router because I have a router child.')
                            self.set_timer('ROUTER_CHECK', config.ROUTER_CHECK_INTERVAL)
                            return
                    if other_networks > 0 and best_child is not None:
                        self.send_router_request(best_child.addr)
                    elif other_networks > 2 and best_child is not None:
                        self.send_promote_request(best_child.addr)
                    elif other_networks > 1:
                        self.become_unregistered()
                self.set_timer('ROUTER_CHECK', config.ROUTER_CHECK_INTERVAL)
            except:
                pass
        elif name == 'ROUTER_NECESSITY_CHECK':
            if self.role != Roles.ROUTER:
                return
            elif self.role == Roles.ROUTER and self.neighbors_table[self.parent_gui].role == Roles.ROUTER:
                self.log('Router should not be because parent is router.')
                self.become_unregistered()
            elif len(self.members_table) > 0 or (len(self.members_table) == 1 and self.neighbors_table[self.members_table[0]].gui != self.parent_gui):
                for node in self.members_table:
                    if self.neighbors_table[node].role != Roles.CLUSTER_HEAD:
                        self.become_unregistered()
                        return
                self.log(f'Router deemed necessary: {self.members_table}')
                self.set_timer('ROUTER_NECESSITY_CHECK', config.ROUTER_CHECK_INTERVAL)
            else:
                self.log('Router status deemed unnecessary')
                self.become_unregistered()

        elif name == 'NETWORK_REQUEST_TIMEOUT':
            # raise RuntimeError("Network Request Timeout.")
            pass
        elif name == 'TIMER_NEIGHBOR_PUBLISH':
            self.send_neighbor_table()
            self.set_timer('TIMER_NEIGHBOR_PUBLISH', config.NEIGHBOR_PUBLISH_INTERVAL)
        elif name == 'FAULTY_NODE':
            self.become_unregistered()
        elif name == 'CHARGE_TIMER':
            self.charge = config.NODE_CHARGE_AMOUNT
            self.log(f'Recharged!')
            self.init()
            self.set_timer('TIMER_ARRIVAL',1)
        else:
            super().on_timer_fired(name)