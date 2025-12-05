"""Simulator library for self-organizing ad hoc networks.
Based on wsnsimpy library. Timers, Network address and Sleep mode are included by Mustafa Tosun.
"""

import bisect
import inspect
import json
import random
import simpy
from enum import Enum
from simpy import rt
import csv
from simpy.util import start_delayed
from source import config

Roles = Enum('Roles', 'ROOT CLUSTER_HEAD ROUTER REGISTERED UNREGISTERED UNDISCOVERED NETWORK_REQUEST_SENT')
"""Enumeration of roles"""

###########################################################
class Addr:
    """Use for a network address which has two parts

       Attributes:
           f (int): First part of the address.
           l (int): Last part of the address.
    """

    ############################
    def __init__(self, 
                 net_addr: int, 
                 node_addr: int):
        """Constructor for Addr class.

           Args:
               f (int): First part of the address.
               l (int): Last part of the address.

           Returns:
               Addr: Created Addr object.
        """
        self.net_addr = net_addr
        self.node_addr = node_addr

    ############################
    def __repr__(self):
        """Representation method of Addr.

           Args:

           Returns:
               string: represents Addr object as a string.
        """
        return '[%d,%d]' % (self.net_addr, self.node_addr)
    
    def __str__(self) -> str:
        return self.__repr__()
    
    ############################
    def __eq__(self, other):
        """ == operator function for Addr objects.

           Args:
               other (Addr): An Addr object to compare.

           Returns:
               bool: returns True if the objects are equal, otherwise False.
        """
        if self.net_addr == other.net_addr and self.node_addr == other.node_addr:
            return True
        return False

    ############################
    def is_equal(self, other):
        """Comparison function for Addr objects.

           Args:
               other (Addr): An Addr object to compare.

           Returns:
               bool: returns True if the objects are equal, otherwise False.
        """
        if self.net_addr == other.net_addr and self.node_addr == other.node_addr:
            return True
        return False


BROADCAST_ADDR = Addr(config.BROADCAST_NET_ADDR, config.BROADCAST_NODE_ADDR)
"""Addr: Keeps broadcast address."""



###########################################################
def ensure_generator(env, func, *args, **kwargs):
    '''
    Make sure that func is a generator function.  If it is not, return a
    generator wrapper
    '''
    if inspect.isgeneratorfunction(func):
        return func(*args, **kwargs)
    else:
        def _wrapper():
            func(*args, **kwargs)
            yield env.timeout(0)

        return _wrapper()


###########################################################
def distance(pos1: tuple[float, float], 
             pos2: tuple[float, float]):
    """Calculates the distance between two positions.

       Args:
           pos1 (Tuple(float,float)): First position.
           pos2 (Tuple(float,float)): Second position.

       Returns:
           float: returns the distance between two positions.
    """
    return ((pos1[0] - pos2[0]) ** 2 + (pos1[1] - pos2[1]) ** 2) ** 0.5


###########################################################
class Simulator:
    """Class to model a network.

       Attributes:
           timescale (float): Seconds in real time for 1 second in simulation. It arranges speed of simulation
           nodes (List of Node): Nodes in network.
           duration (float): Duration of simulation.
           random (Random): Random object to use.
           timeout (Function): Timeout Function.

    """
    ############################
    def __init__(self, duration: float, timescale: float = 1, seed: float = 0):
        """Constructor for Simulator class.

           Args:
               until (float): Duration of simulation.
               timescale (float): Seconds in real time for 1 second in simulation. It arranges speed of simulation
               seed (float): seed for Random bbject.

           Returns:
               Simulator: Created Simulator object.
        """
        self.env = rt.RealtimeEnvironment(factor=timescale, strict=False)
        self.nodes = []
        self.duration = duration
        self.timescale = timescale
        self.random = random.Random(seed)
        self.timeout = self.env.timeout
        
        self.node_file = 'node_log.csv'
        self.node_logs = []
        with open(self.node_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "node_id", "log_text"])

        self.packet_file = 'node_packets.csv'
        self.packets = []
        with open(self.packet_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "node_id", "send_receive", "create_time", "receive_time", "packet"])

        self.node_role_change_file = 'node_role_change.csv'
        self.role_changes = []
        with open(self.node_role_change_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "node_id", "role"])



    ############################
    @property
    def now(self):
        """Property for time of simulation.

           Args:

           Returns:
               float: Time of simulation.
        """
        return self.env.now

    ############################
    def delayed_exec(self, delay: float, func, *args, **kwargs):
        """Executes a function with given parameters after a given delay.

           Args:
                delay (float): Delay duration.
                func (Function): Function to execute.
                *args (float): Function args.
                delay (float): Function key word args.
           Returns:

        """
        func = ensure_generator(self.env, func, *args, **kwargs)
        start_delayed(self.env, func, delay=delay)

    ############################
    def add_node(self, node_class, pos: tuple[float, float], is_root = False):
        """Adds a new node in to network.

           Args:
                nodeclass (Class): Node class inherited from Node.
                pos (Tuple(float,float)): Position of node.
           Returns:
                nodeclass object: Created nodeclass object
        """
        id = len(self.nodes)
        node = node_class(self, id, pos)
        self.nodes.append(node)
        self.update_neighbor_list(id)
        return node

    ############################
    def update_neighbor_list(self, id: int):
        '''
        Maintain each node's neighbor list by sorted distance after affected
        by addition or relocation of node with ID id

        Args:
            id (int): Global unique id of node
        Returns:

        '''
        me = self.nodes[id]

        # (re)sort other nodes' neighbor lists by distance
        for n in self.nodes:
            # skip this node
            if n is me:
                continue

            nlist = n.neighbor_distance_list

            # remove this node from other nodes' neighbor lists
            for i, (dist, neighbor) in enumerate(nlist):
                if neighbor is me:
                    del nlist[i]
                    break

            # then insert it while maintaining sort order by distance
            bisect.insort(nlist, (distance(n.pos, me.pos), me))

        self.nodes[id].neighbor_distance_list = [
            (distance(n.pos, me.pos), n)
            for n in self.nodes if n is not me
        ]
        self.nodes[id].neighbor_distance_list.sort()

    ############################
    def run(self):
        """Runs the simulation. It initialize every node, then executes each nodes run function.
        Finally calls finish functions of nodes.

           Args:

           Returns:

        """
        for n in self.nodes:
            n.init()
        for n in self.nodes:
            self.env.process(ensure_generator(self.env, n.run))
        self.env.run(until=self.duration)
        for n in self.nodes:
            n.finish()

    def log_message(self, msg: str, id: int):
        if self.node_logs is not None:
            self.node_logs.append({'msg': msg, 'id': id, 'now': f"{self.now:.6f}"})
        
        if len(self.node_logs) > config.NODE_LOG_CACHE_COUNT:
            with open(self.node_file, "a", newline="") as f:
                w = csv.writer(f)
                for log in self.node_logs:
                    w.writerow([log['now'], log['id'], log['msg']])
                self.node_logs = []

    def log_packet(self, input_pck: dict, send_receive: str, id: int):
        pck = input_pck.copy()
        if self.packets is not None and 'ALL' in config.PACKET_LOG_MASK or pck['type'] in config.PACKET_LOG_MASK:
            self.packets.append({'pck': pck, 'send_receive': send_receive, 'id': id, 'now': f"{self.now:.6f}"})
        
        if len(self.packets) > config.PACKET_CACHE_COUNT:
            with open(self.packet_file, "a", newline="") as f:
                w = csv.writer(f)
                for packet in self.packets:
                    w.writerow([packet['now'], packet['id'], packet['send_receive'], 
                                packet['pck']['create_time'] if 'create_time' in packet['pck'] else '-1',
                                packet['pck']['receive_time'] if 'receive_time' in packet['pck'] else '-1', packet['pck']])
                self.packets = []

    def log_role_change(self, id: int, role: Roles):
        if self.role_changes is not None:
            self.role_changes.append({'role': f'{role.value}: {role.name}', 'id': id, 'now': f"{self.now:.6f}"})
        
        if len(self.role_changes) > config.PACKET_CACHE_COUNT:
            with open(self.node_role_change_file, "a", newline="") as f:
                w = csv.writer(f)
                for packet in self.role_changes:
                    w.writerow([packet['now'], packet['id'], packet['role']])
                self.role_changes = []

    def write_packets_and_logs(self):
        with open(self.packet_file, "a", newline="") as f:
            w = csv.writer(f)
            for packet in self.packets:
                w.writerow([packet['now'], packet['id'], packet['send_receive'], 
                            packet['pck']['create_time'] if 'create_time' in packet['pck'] else '-1',
                            packet['pck']['receive_time'] if 'receive_time' in packet['pck'] else '-1', packet['pck']])
            self.packets = []
        with open(self.node_file, "a", newline="") as f:
            w = csv.writer(f)
            for log in self.node_logs:
                w.writerow([log['now'], log['id'], log['msg']])
            self.node_logs = []
        with open(self.node_role_change_file, "a", newline="") as f:
            w = csv.writer(f)
            for packet in self.role_changes:
                w.writerow([packet['now'], packet['id'], packet['role']])
            self.role_changes = []

###########################################################
class Node:
    """Class to model a network node with basic operations. It's base class for more complex node classes.

       Attributes:
           pos (Tuple(float,float)): Position of node.
           tx_range (float): Transmission range of node.
           sim (Simulator): Simulation environment of node.
           id (int): Global unique ID of node.
           addr (Addr): Network address of node.
           is_sleep (bool): If it is True, It means node is sleeping and can not receive messages.
           Otherwise, node is awaken.
           logging (bool): It is a flag for logging. If it is True, nodes outputs can be seen in terminal.
           active_timer_list (List of strings): It keeps the names of active timers.
           neighbor_distance_list (List of Tuple(float,int)): Sorted list of nodes distances to other nodes.
            Each Tuple keeps a distance and a node id.
           timeout (Function): timeout function

    """

    ############################
    def __init__(self, 
                 sim, 
                 id: int, 
                 pos: tuple[float, float]):
        """Constructor for base Node class.

           Args:
               sim (Simulator): Simulation environment of node.
               id (int): Global unique ID of node.
               pos (Tuple(float,float)): Position of node.

           Returns:
               Node: Created node object.
        """
        self.pos = pos
        self.tx_range = 0
        self.sim: Simulator = sim
        self.id = id
        self.addr = Addr(0, id)
        self.parent_gui = None
        self.is_sleep = False
        self.logging = True
        self.active_timer_list = []
        self.neighbor_distance_list: list[tuple[int, Node]] = []
        self.log_history = []
        self.timeout = self.sim.timeout
        self.charge = config.NODE_CHARGE_AMOUNT

    ############################
    def __repr__(self):
        """Representation method of Node.

           Args:

           Returns:
               string: represents Node object as a string.
        """
        return '<Node %d:(%.2f,%.2f)>' % (self.id, self.pos[0], self.pos[1])

    ############################
    @property
    def now(self):
        """Property for time of simulation.

           Args:

           Returns:
               float: Time of simulation.
        """
        return self.sim.env.now

    ############################
    def log(self, msg: str):
        """Writes outputs of node to terminal.

           Args:
                msg (string): Output text
           Returns:

        """

        if self.logging:
            print(f"Node {'#' + str(self.id):4}[{self.now:10.5f}] {msg}")
        self.log_history.append(f"Node {'#' + str(self.id):4}[{self.now:10.5f}] {msg}")
        self.sim.log_message(f"Node {'#' + str(self.id):4}[{self.now:10.5f}] {msg}", self.id)

    def dump_log(self):
        """Returns a string representation of node's log.
        
        Args:

        Returns:
        """
        log_dump = ""
        for entry in self.log_history:
            log_dump += entry + "\n"

        return log_dump

    ############################
    def can_receive(self, pck: dict):
        """Checks if the given package is proper to receive.

           Args:
               pck (Dict): A package to check.

           Returns:
               bool: returns True if the given package is proper to receive .
        """
        # TODO: Check if local nodes are receiving Messages
        dest = pck['next_hop'] if 'next_hop' in pck.keys() else pck['dest']
        if dest.is_equal(BROADCAST_ADDR):  # if destination address is broadcast address
            return True
        if self.addr is not None:  # if node's address is assigned
            if dest.is_equal(self.addr):  # if destination address is node's address
                return True
            elif dest.node_addr == config.BROADCAST_NODE_ADDR and dest.net_addr == self.addr.net_addr:  # if destination address is local broadcast address of node's network
                return True
        return False

    ############################
    def send(self, pck: dict):
        """Sends given package. If dest address in pck is broadcast address, it sends the package to all neighbors.

           Args:
                pck (Dict): Package to be sent. It should contain 'dest' which is destination address.
           Returns:

        """
        if config.PACKET_LOSS_RATE > 0:
            lose_packet = random.randrange(1, int(1/config.PACKET_LOSS_RATE)+1)
            if lose_packet == int(1/config.PACKET_LOSS_RATE):
                self.log('Packet Lost due to Packet Loss Rate.')
        if 'create_time' not in pck.keys():
            pck['create_time'] = self.now
        pck_cost = (len(bytes(f'{pck}', 'UTF-8')) * 1.67 * (self.tx_range / config.TX_RANGE_COST) )/ 1000000
        # (number of bytes in packet * microjules per byte * TX_RANGE) / 1e6 => Joules cost of packet
        for (dist, node) in self.neighbor_distance_list:
            if dist <= self.tx_range:
                if node.can_receive(pck):
                    prop_time = dist / 1000000 - 0.00001 if dist / 1000000 - 0.00001 >0 else 0.00001
                    self.delayed_exec(prop_time, node.on_receive_check, pck)
                    if config.USE_SIMPLE_POWER:
                        self.charge -= config.SEND_COST
                    else:
                        self.charge -= pck_cost
            else:
                break
        self.sim.log_packet(pck, 'send', self.id)
        
    ############################
    def set_timer(self, name: str, time: float, *args, **kwargs):
        """Sets a timer with a given name. It appends name of timer to the active timer list.

           Args:
                name (string): Name of timer.
                time (float): Duration of timer.
                *args (string): Additional args.
                **kwargs (string): Additional key word args.
           Returns:

        """
        if name in self.active_timer_list:
            self.log(f'{name} Timer already exists. Preventing Duplicate...')
            return
        self.active_timer_list.append(name)
        self.delayed_exec(time - 0.00001, self.on_timer_fired_check, name, *args, **kwargs)

    ############################
    def kill_timer(self, name: str):
        """Kills a timer with a given name. It removes name of timer from the active timer list if exists.

           Args:
                name (string): Name of timer.
           Returns:

        """
        if name in self.active_timer_list:
            self.active_timer_list.remove(name)

    ############################
    def kill_all_timers(self):
        """Kills all timers.

           Args:

           Returns:

        """
        self.active_timer_list = []

    ############################
    def delayed_exec(self, delay: float, func, *args, **kwargs):
        """Executes a function with given parameters after a given delay.

           Args:
                delay (float): Delay duration.
                func (Function): Function to execute.
                *args (float): Function args.
                delay (float): Function key word args.
           Returns:

        """
        return self.sim.delayed_exec(delay, func, *args, **kwargs)

    ############################
    def init(self):
        """Initialize a node. It is executed at the beginning of simulation. It should be overridden if needed.

           Args:

           Returns:

        """
        pass

    ############################
    def run(self):
        """Run method of a node. It is executed after init() at the beginning of simulation.
        It should be overridden if needed.

           Args:

           Returns:

        """
        pass

    ###################
    def move(self, x: float, y: float):
        """Moves a node from the current position to given position

           Args:
               x (float): x of position.
               y (float): y of position.
.
           Returns:
         """
        self.pos = (x, y)
        self.sim.update_neighbor_list(self.id)

    ############################
    def on_receive(self, pck: dict):
        """It is executed when node receives a package. It should be overridden if needed.

           Args:
                pck (Dict): Package received
           Returns:

        """
        pass

    ############################
    def on_receive_check(self, pck: dict):
        """Checks if node is sleeping or not for incoming package.
        If sleeping, does not call on_recieve() and does not receive package.

           Args:
                pck (Dict): Incoming package
           Returns:

        """
        if not self.is_sleep:
            self.delayed_exec(0.00001, self.on_receive, pck)

    ############################
    def on_timer_fired(self, name: str, *args, **kwargs):
        """It is executed when a timer fired. It should be overridden if needed.

           Args:
                name (string): Name of timer.
                *args (string): Additional args.
                **kwargs (string): Additional key word args.
           Returns:

        """
        pass

    ############################
    def on_timer_fired_check(self, name: str, *args, **kwargs):
        """Checks if the timer about to fire is in active timer list or not. If not, does not call on_timer_fired().

           Args:
                name (string): Name of timer.
                *args (string): Additional args.
                **kwargs (string): Additional key word args.
           Returns:

        """
        if name in self.active_timer_list:
            self.active_timer_list.remove(name)
            self.delayed_exec(0.00001, self.on_timer_fired, name, *args, **kwargs)

    ############################
    def sleep(self):
        """Make node sleep. In sleeping node can not receive packages.

           Args:

           Returns:

        """
        self.is_sleep = True

    ############################
    def wake_up(self):
        """Wake node up to receive incoming messages.

           Args:

           Returns:

        """
        self.is_sleep = False

    ############################
    def finish(self):
        """It is executed at the end of simulation. It should be overridden if needed.

           Args:

           Returns:

        """
        pass



