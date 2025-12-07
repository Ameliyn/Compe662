## network properties
BROADCAST_NET_ADDR = 255
BROADCAST_NODE_ADDR = 255

## node properties
NODE_ARRIVAL_MAX = 200  # max time to wake up
ACK_TIMEOUT = 100

## simulation properties
SIM_NODE_COUNT = 50  # noce count in simulation
SIM_NODE_PLACING_CELL_SIZE = 75  # cell size to place one node
SIM_DURATION = 10000  # simulation Duration in seconds
SIM_TIME_SCALE = 0.00001  #  The real time dureation of 1 second simualtion time
SIM_TERRAIN_SIZE = (1400, 1400)  #terrain size
SIM_TITLE = 'Data Collection Tree'  # title of visualization window
SIM_VISUALIZATION = True  # visualization active
SCALE = 1  # scale factor for visualization
PACKET_TTL = 15
TX_CIRCLE_MASK = ["NONE"] # Either use "ALL", "NONE" or list "PACKET_TYPE" (ex. ["ALL"] or ["PROBE", "HEART_BEAT", "JOIN_ACK"])
LOG_LEVEL = "INFO"
DO_SENSOR_MESSAGES = False

## application properties
HEART_BEAT_TIME_INTERVAL = 10
TIMER_NETWORK_UPDATE_INTERVAL = 1000
NETWORK_REQUEST_TIMEOUT = 500
REPAIRING_METHOD = 'FIND_ANOTHER_PARENT' # 'ALL_ORPHAN', 'FIND_ANOTHER_PARENT'
EXPORT_CH_CSV_INTERVAL = 10  # simulation time units;
EXPORT_NEIGHBOR_CSV_INTERVAL = 10  # simulation time units;

## Logging Properties
PACKET_CACHE_COUNT = 25
NODE_LOG_CACHE_COUNT = 25
PACKET_LOG_MASK = ["ALL"]

################################
###### MIDTERM 2 FEATURES ######
################################

# - A multihop neighbor discovery protocol (two hops using published neighbor tables)
NEIGHBOR_PUBLISH_INTERVAL = 100
MULTIHOP_LIMIT = 2

# - Reports for the average time to join the network and average packet delay (from source to destination)
GENERATE_AVG_PACKET_DELAY = True
GENERATE_AVG_JOIN_DELAY = True

# - Customizable number of children per cluster
CLUSTER_SIZE = 10

# - Customizable number of clusters
CLUSTER_LIMIT = 200

# - Customizable packet loss rate
PACKET_LOSS_RATE = 0.0

# - Customizable and variable node Transmit Range
NODE_TX_RANGE = 100  # transmission range of nodes
NODE_TX_MIN = 10

# - The use of Routers and a mobile cluster head role to limit overlap between clusters (the network is optimized to have the minimum number of clusters)
NETWORK_OPTIMIZATOIN_CHECK = True
NETWORK_OPTIMIZATOIN_CHECK_INTERVAL = 100

# - Automatic recovery from link failures and nodes leaving (set the "NUM_FAULTY_NODES" parameter to see nodes die randomly)
NUM_FAULTY_NODES = 0
FAULTY_NODE_PERIOD = [1000,1500]
FAULTY_NODE_REPEAT = False

# - An energy model that is based on CC2420 that includes nodes having a set battery amount and each transmission taking a certain amount of energy based on TX_RANGE and Message Length
NODE_CHARGE_AMOUNT = 20000
NODE_CHARGE_TIME = 100000
TX_RANGE_COST = 1 # Scalar for node TX_RANGE to set volume (simulated dBm)
RECEIVE_COST = 18
SEND_COST = 17
USE_SIMPLE_POWER = True
USE_BATTERY_POWER = False

