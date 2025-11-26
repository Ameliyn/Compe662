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