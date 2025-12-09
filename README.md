# EE662Fall2021

WsnLab.py is a simulation library in Python based on WsnSimPy for self-organized networks.

# Requirements

You need to install the following packages.
- simpy
- python3-tk (tkinter)

- Activate the venv using `source WSNVenv/bin/activate`

To Run execute: `python3 wsnlab/run_sim.py`

The implementation of sensor_node.py includes:
- A multihop neighbor discovery protocol (two hops using published neighbor tables)
- Tree and mesh based routing
- Reports for the average time to join the network and average packet delay (from source to destination)
- Customizable number of children per cluster
- Customizable number of clusters
- Customizable packet loss rate
- Customizable node Transmit Range
- The use of Routers and a mobile cluster head role to limit overlap between clusters (the network is optimized to have the minimum number of clusters)
- Automatic recovery from link failures and nodes leaving (set the "NUM_FAULTY_NODES" parameter to see nodes die randomly)
- An energy model that is based on CC2420 that includes nodes having a set battery amount and each transmission taking a certain amount of energy based on TX_RANGE and Message Length

## FINAL EXAM 

Title: A hybrid self organizing network

Abstract: (short)
- Why is this an important problem? -- limited energy so we're trying to save it
- What do we propose as a solution?
- Main achievements (network lifetime is increased by __%, etc)

Introduction:
- Why this is an important problem? (some repition but we're expanding on the abstract)
- What have others done? (Cluster Tree algorithm, (zigbee, AODV))
    - Throw some shade on other algorithms
- What gaps are we trying to close?
- What are we suggesting? (Cluster Tree + Mesh)

Cluster Tree Mesh Algorithm:
- Explain algorithm in detail
- Subsections
    - Simulation environment
    - Create cluster tree with variations (routers)
    - Routing Algorithm
    - Router and Cluster Head nominations
    - Recovery Algorithm
    - Energy Model

Experiments:
- Simulations and graphs (see below)
```md
- Disable Mesh (show differences) (configurable mesh size)
- Energy Model
    - \# of packets transmitted vs # nodes disconnected
    - \# Avg energy of all nodes over time (mesh vs not)
- AVG time to join network vs # of nodes at varying packet loss rate
- \# of nodes vs avg Time to deliver packet to destination (with or without mesh) (randomized source and destination sensor messages)
- \# of nodes vs Avg energy spent per packet (with or without mesh)
- Leaving and Rejoining
    - At t1, kill N nodes, at t2 bring back those nodes (take picture before, during and after) Record # of nodes unable to connect before bringing back nodes
    - Show four pictures and tell the story
    - Graph # of nodes killed vs # of nodes disconnected (without bringing back the killed nodes)
```

Discussion:
- What is achieved
- Weaknesses
- Future work


TODO:
- Faulty nodes sleep for a configurable period
- TX range for clusters set to limit farthest cluster member from CH