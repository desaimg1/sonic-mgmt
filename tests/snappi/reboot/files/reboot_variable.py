from tests.common.snappi.snappi_fixtures import create_ip_list
from functools import reduce

###############################################################
#                  Declaring Global variables
###############################################################
TGEN_AS_NUM = 65101
TIMEOUT = 30
FLAP_TIME = 45
BGP_TYPE = 'ebgp'
ITERATION = 2

AS_PATHS = [64000]
NO_OF_ROUTES = 4000
NO_OF_DEVICES = 1000

#RX_DUTS_PORT_RATIO is nth DUT and n number of ports associated on the receiver side
RX_DUTS_PORT_RATIO = [(1, 0), (2, 2)]
REBOOT_DUT_LISTS = [1, 2]
NO_OF_TX_PORTS = 1
VLAN_ID = 2

sleep10 = 10
ipMask = 16
ipv6Mask = 64
port_speed = "speed_400_gbps"
tolerenceVal = 10
tolerence_pkts = 500
no_of_ports=int(NO_OF_TX_PORTS) + reduce(lambda x,y : x+y , [val[1] for val in RX_DUTS_PORT_RATIO]) 
#dutIps = create_ip_list("192.168.1.1", no_of_ports, mask=8)
dutIps = ["192.168.1.1"] * no_of_ports
#tgenIps = create_ip_list("192.168.1.2", no_of_ports, mask=24)
tgenIps =  ["192.168.1.2", "192.168.6.2", "192.168.10.2"]
dutV6Ips = create_ip_list("1000:0:0:1:0:0:0:1", no_of_ports, mask=112)
tgenV6Ips = create_ip_list("1000:0:0:1:0:0:0:2", no_of_ports, mask=112)
dutsAsNum = 65000
inter_dut_network_start = '20.0.0.1'

print(tgenIps, dutIps)
