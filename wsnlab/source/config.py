## network properties
BROADCAST_NET_ADDR = 255
BROADCAST_NODE_ADDR = 255



## node properties
NODE_TX_RANGE = 100  # transmission range of nodes
NODE_TX_MIN = 10
NODE_ARRIVAL_MAX = 200  # max time to wake up
ROUTER_CHECK_INTERVAL = 100
CLUSTER_SIZE = 100
CLUSTER_LIMIT = 100
NEIGHBOR_PUBLISH_INTERVAL = 500
NODE_CHARGE_AMOUNT = 40
NODE_CHARGE_TIME = 100
TX_RANGE_COST = 1 # Scalar for node TX_RANGE to set volume
USE_BATTERY_POWER = False
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
SHOW_TX_CIRCLES = False
TX_CIRCLE_MASK = ["ALL"]
LOG_LEVEL = "INFO"
DO_SENSOR_MESSAGES = False
PACKET_LOSS_RATE = 0.00000

ALLOW_ROUTERS = True
NUM_FAULTY_NODES = 0
FAULTY_NODE_PERIOD = [1000,1500]

## application properties
HEART_BEAT_TIME_INTERVAL = 100
TIMER_NETWORK_UPDATE_INTERVAL = 1000
NETWORK_REQUEST_TIMEOUT = 500
REPAIRING_METHOD = 'FIND_ANOTHER_PARENT' # 'ALL_ORPHAN', 'FIND_ANOTHER_PARENT'
EXPORT_CH_CSV_INTERVAL = 10  # simulation time units;
EXPORT_NEIGHBOR_CSV_INTERVAL = 10  # simulation time units;


## Logging Properties
PACKET_CACHE_COUNT = 25
NODE_LOG_CACHE_COUNT = 25
PACKET_LOG_MASK = ["ALL"]
GENERATE_AVG_PACKET_DELAY = True
GENERATE_AVG_JOIN_DELAY = True