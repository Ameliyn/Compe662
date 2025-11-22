import json
import random
from enum import Enum
import sys
sys.path.insert(1, '.')
from source import wsnlab_vis as wsn
import math
from source import config
from collections import Counter
from sensor_node import SensorNode, Roles


import csv  # <— add this near your other imports

# Track where each node is placed
NODE_POS = {}  # {node_id: (x, y)}

# --- tracking containers ---
ALL_NODES = []              # node objects
CLUSTER_HEADS = []
ROLE_COUNTS: Counter[Roles] = Counter()     # live tally per Roles enum

def write_node_distances_csv(path="node_distances.csv"):
    """Write pairwise node-to-node Euclidean distances as an edge list."""
    ids = sorted(NODE_POS.keys())
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source_id", "target_id", "distance"])
        for i, sid in enumerate(ids):
            x1, y1 = NODE_POS[sid]
            for tid in ids[i+1:]:  # i+1 to avoid duplicates and self-pairs
                x2, y2 = NODE_POS[tid]
                dist = math.hypot(x1 - x2, y1 - y2)
                w.writerow([sid, tid, f"{dist:.6f}"])


def write_node_distance_matrix_csv(path="node_distance_matrix.csv"):
    ids = sorted(NODE_POS.keys())
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id"] + ids)
        for sid in ids:
            x1, y1 = NODE_POS[sid]
            row = [sid]
            for tid in ids:
                x2, y2 = NODE_POS[tid]
                dist = math.hypot(x1 - x2, y1 - y2)
                row.append(f"{dist:.6f}")
            w.writerow(row)


def write_clusterhead_distances_csv(path="clusterhead_distances.csv"):
    """Write pairwise distances between current cluster heads."""
    clusterheads = []
    for node in sim.nodes:
        # Only collect nodes that are cluster heads and have recorded positions
        if hasattr(node, "role") and node.role == Roles.CLUSTER_HEAD and node.id in NODE_POS:
            x, y = NODE_POS[node.id]
            clusterheads.append((node.id, x, y))

    if len(clusterheads) < 2:
        # Still write the header so the file exists/is refreshed
        with open(path, "w", newline="") as f:
            csv.writer(f).writerow(["clusterhead_1", "clusterhead_2", "distance"])
        return

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["clusterhead_1", "clusterhead_2", "distance"])
        for i, (id1, x1, y1) in enumerate(clusterheads):
            for id2, x2, y2 in clusterheads[i+1:]:
                dist = math.hypot(x1 - x2, y1 - y2)
                w.writerow([id1, id2, f"{dist:.6f}"])


def write_neighbor_distances_csv(path="neighbor_distances.csv", dedupe_undirected=True):
    """
    Export neighbor distances per node.
    Each row is (node -> neighbor) with distance from NODE_POS.

    Args:
        path (str): output CSV path
        dedupe_undirected (bool): if True, writes each unordered pair once
                                  (min(node_id,neighbor_id), max(...)).
                                  If False, writes one row per direction.
    """
    # Safety: ensure we can compute distances
    if not globals().get("NODE_POS"):
        raise RuntimeError("NODE_POS is missing; record positions during create_network().")

    # Prepare a set to avoid duplicates if dedupe_undirected=True
    seen_pairs = set()

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["node_id", "neighbor_id", "distance",
                    "neighbor_role", "neighbor_hop_count", "arrival_time"])

        for node in sim.nodes:
            # Skip nodes without any neighbor info yet
            if not hasattr(node, "neighbors_table"):
                continue

            x1, y1 = NODE_POS.get(node.id, (None, None))
            if x1 is None:
                continue  # no position → cannot compute distance

            # neighbors_table: key = neighbor GUI, value = heartbeat packet dict
            for n_gui, pck in getattr(node, "neighbors_table", {}).items():
                # Optional dedupe (unordered)
                if dedupe_undirected:
                    key = (min(node.id, n_gui), max(node.id, n_gui))
                    if key in seen_pairs:
                        continue
                    seen_pairs.add(key)

                # Position of neighbor
                x2, y2 = NODE_POS.get(n_gui, (None, None))
                if x2 is None:
                    continue

                # Distance (prefer pck['distance'] if you added it in update_neighbor)
                dist = pck.get("distance")
                if dist is None:
                    dist = math.hypot(x1 - x2, y1 - y2)

                # Extra fields (best-effort; may be missing)
                n_role = getattr(pck.get("role", None), "name", pck.get("role", None))
                hop = pck.get("hop_count", "")
                at  = pck.get("arrival_time", "")

                w.writerow([node.id, n_gui, f"{dist:.6f}", n_role, hop, at])

###########################################################
def create_network(node_class: type[SensorNode], number_of_nodes=100):
    """Creates given number of nodes at random positions with random arrival times.

    Args:
        node_class (Class): Node class to be created.
        number_of_nodes (int): Number of nodes.
    Returns:

    """
    edge = math.ceil(math.sqrt(number_of_nodes))
    ROOT_ID = random.randrange(config.SIM_NODE_COUNT)  # 0..count-1
    
    faulty_node_id = random.randrange(config.SIM_NODE_COUNT)
    while faulty_node_id == ROOT_ID:
        faulty_node_id = random.randrange(config.SIM_NODE_COUNT)

    num_faulty_nodes = config.NUM_FAULTY_NODES
    faulty_node_list = []
    while num_faulty_nodes > 0:
        potential_faulty_node = random.randrange(config.SIM_NODE_COUNT)
        while potential_faulty_node in faulty_node_list or potential_faulty_node == ROOT_ID:
            potential_faulty_node = random.randrange(config.SIM_NODE_COUNT)
        faulty_node_list.append(potential_faulty_node)
        num_faulty_nodes -= 1

    for i in range(number_of_nodes):
        x = i / edge
        y = i % edge
        px = 300 + config.SCALE*x * config.SIM_NODE_PLACING_CELL_SIZE + random.uniform(-1 * config.SIM_NODE_PLACING_CELL_SIZE / 3, config.SIM_NODE_PLACING_CELL_SIZE / 3)
        py = 200 + config.SCALE* y * config.SIM_NODE_PLACING_CELL_SIZE + random.uniform(-1 * config.SIM_NODE_PLACING_CELL_SIZE / 3, config.SIM_NODE_PLACING_CELL_SIZE / 3)
        node = sim.add_node(node_class, (px, py))
        NODE_POS[node.id] = (px, py)   # <— add this line
        node.tx_range = config.NODE_TX_RANGE * config.SCALE
        node.logging = True
        node.arrival = random.uniform(0, config.NODE_ARRIVAL_MAX)

        if node.id == ROOT_ID:
            print(f'Node: {ROOT_ID} is ROOT')
            node.is_root_eligible = True
            node.arrival = 0.1
        elif node.id in faulty_node_list:
            print(f'Node: {node.id} is FAULTY')
            node.is_faulty = True
        


sim = wsn.Simulator(
    duration=config.SIM_DURATION,
    timescale=config.SIM_TIME_SCALE,
    visual=config.SIM_VISUALIZATION,
    terrain_size=config.SIM_TERRAIN_SIZE,
    title=config.SIM_TITLE)

# creating random network
create_network(SensorNode, config.SIM_NODE_COUNT)

write_node_distances_csv("node_distances.csv")
write_node_distance_matrix_csv("node_distance_matrix.csv")
write_clusterhead_distances_csv('clusterhead_distances.csv')
write_neighbor_distances_csv('neighbor_distances.csv')

# start the simulation
try:
    sim.run()
except:
    sim.write_packets_and_logs()
    pass
print("Simulation Finished")

if config.LOG_LEVEL == 'DEBUG':
    for node in sim.nodes:
        assert(isinstance(node, SensorNode))
        # if len(node.child_networks) != 0 or node.role == Roles.ROOT:
        if node.role != Roles.UNDISCOVERED:
            print()
            print(f'ID: {node.id}, PARENT: {node.parent_gui}')
            print('Neighbor Table')
            for gui, entry in node.neighbors_table.items():
                print(f'{gui}: {entry}')
            print('Networking Table')
            for gui, entry in node.networking_table.items():
                print(f'{gui}: {entry}')
            print('Candidate Parents Table')
            print(f'{node.candidate_parents_table}')

if config.GENERATE_AVG_PACKET_DELAY:
    with open('node_packets.csv', 'r') as f:
        r = csv.reader(f)
        header = next(r)
        packet_turnaround_times = []
        for row in r:
            try:
                timestamp = row[0]
                node_id = row[1]
                send_receive = row[2]
                create_time = float(row[3])
                receive_time = float(row[4])
                if send_receive == 'receive' and receive_time != -1:
                    packet_turnaround_times.append(receive_time - create_time)
            except:
                pass
                # print(f'{timestamp}, {node_id} : {} {packet["receive_time"]}')
        print(f'Average Packet Delay: {sum(packet_turnaround_times) / len(packet_turnaround_times)}')

if config.GENERATE_AVG_JOIN_DELAY:
    with open('node_role_change.csv', 'r') as f:
        r = csv.reader(f)
        header = next(r)
        node_join_times = []
        node_roles = dict()
        off_roles = ['5: UNREGISTERED']
        for row in r:
            try:
                timestamp = float(row[0])
                node_id = row[1]
                role = row[2]
                if node_id in node_roles.keys():
                    old_role = node_roles[node_id][0]
                    start_time = node_roles[node_id][1]
                    if old_role in off_roles:
                        # print(f'Node: {node_id} is off')
                        if role not in off_roles:
                            # print(f'Node: {node_id} turned on')
                            node_join_times.append(timestamp-start_time)
                node_roles[node_id] = (role, timestamp)

                
            except:
                pass
                # print(f'{timestamp}, {node_id} : {} {packet["receive_time"]}')
        if len(node_join_times) > 0:
            print(f'Average Join Delay: {sum(node_join_times) / len(node_join_times)}')
        else:
            print(node_roles)

# Created 100 nodes at random locations with random arrival times.
# When nodes are created they appear in white
# Activated nodes becomes red
# Discovered nodes will be yellow
# Registered nodes will be green.
# Root node will be black.
# Routers/Cluster Heads should be blue
