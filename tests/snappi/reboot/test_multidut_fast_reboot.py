from unittest import result
from tests.common.snappi.snappi_fixtures import cvg_api
from tests.common.snappi.snappi_fixtures import (
   snappi_api_serv_ip, snappi_api_serv_port, get_multidut_snappi_ports,
   create_ip_list, get_tgen_peer_ports)
from tests.common.fixtures.conn_graph_facts import fanout_graph_facts
from tests.common.helpers.assertions import pytest_assert
logger = logging.getLogger(__name__)
from tabulate import tabulate
from tests.common.utilities import (wait, wait_until)
import pytest
from files.reboot_variable import *
from files.reboot_multi_helper import *

"""
This covers following testcase from testplan :

BGP-Convergence test with MUltiple DUTs

Test Steps :


            
Topology Used :

									 --------         
									|        |        
									|        |   Rx1  
							--------|  DUT2  |---------
						   |		|        |         |
						   |		|        |         |
						   |		 --------          |
       ------          --------         |          --------
      |      |        |        |        |         |        |
      |      |   Tx   |        |        |         |        |
      | TGEN |--------|  DUT1  |        |         |  TGEN  |
      |      |        |        |        |         |        |
      |      |        |        |        |         |        |
       ------          --------         |          --------
	                       |            |              |
	                       |         --------          |
                           |        |        |         |
                           |        |        |   Rx2   |
                            --------|  DUT3  |-------- 
                                    |        |        
                                    |        |        
                                     --------         
    
"""

###############################################################
#                   Start of Test Procedure
###############################################################

def test_multidut_fast_reboot(cvg_api, duthosts, localhost, get_multidut_snappi_ports):
        
    # Initial steps
    dut_ports, tg_ports = [], []
    for i in range(0,len(RX_DUTS_PORT_RATIO)):
        if i ==0:
            port_set = get_tgen_peer_ports(get_multidut_snappi_ports, duthosts[i].hostname)[0:NO_OF_TX_PORTS+RX_DUTS_PORT_RATIO[i][1]]            
        else:
            port_set = get_tgen_peer_ports(get_multidut_snappi_ports, duthosts[i].hostname)[0:RX_DUTS_PORT_RATIO[i][1]]
        dut_ports.extend([val[1] for val in port_set])
        tg_ports.extend([val[0] for val in port_set])

    logger.info("dut_ports {}".format(dut_ports))
    logger.info("tg_ports {}".format(tg_ports))
    
    #declare result
    result = True

    # save current config in DUTs before start of test
    logger.info("Save configuration before start of test ...")
    for i in range(0,len(RX_DUTS_PORT_RATIO)):
        save_current_config(duthosts[i])

    # Step 1 Configure DUTs
    logger.info("Configure DUTs to TGEN and inter DUTs ...")
    configure_duts(duthosts, dut_ports)
        
    # Step 2 Configure TGEN 
    logger.info("Configure TGEN") 
    rbt_cfg  = reboot_config(cvg_api, tg_ports)
    rx_port_names = []
    for i in range(1, len(rbt_cfg.config.ports)):
        rx_port_names.append(rbt_cfg.config.ports[i].name)
    rbt_cfg.rx_rate_threshold = 90
    cvg_api.set_config(rbt_cfg)
    
    # Step 3 Start the protocol
    logger.info("Starting all protocols ...")
    cs = cvg_api.convergence_state()
    cs.protocol.state = cs.protocol.START
    cvg_api.set_state(cs)
    wait(TIMEOUT, "For Protocols To start")

    # Step 4 Verify Interfaces Up Initially
    logger.info("Verify Interfaces States Initially UP")
    verify_interfaces(duthosts, dut_ports)
    
    # Step 5: Verify Ping from DUT to IXIA
    logger.info("Verify ping to TGEN successful")
    if not verify_ping(duthosts, tgenIps):
        result = False
    
    # Step 6: verify BGP neighbors established
    logger.info("Verify BGP neighbors established")
    if not verify_bgp_neighbors(duthosts, tgenIps[0:NO_OF_TX_PORTS], route_type='ipv4'):
        result = False
    # if not verify_bgp_neighbors(duthosts, tgenIps[0:NO_OF_TX_PORTS], route_type='ipv6'):
    #     result = False
        
    # Step 7: verify ip route summary initially
    logger.info("Verify routes injected")
    if not verify_routes(duthosts, route_type='ipv4'):
        result = False
    # if not verify_routes(duthosts, route_type='ipv6'):
    #     result = False

    # Step 8: Verify convergence with fast reboot scenario
    logger.info("Verify convergence with fast reboot scenario")

    table = get_convergence_for_reboot_test(duthosts, localhost, cvg_api, 'fast')
    columns = ['Reboot Type', 'Traffic Item Name', 'Data Plane Convergence Time (ms)', 'Time (ms)']
    logger.info("\n%s" % tabulate(table, headers=columns, tablefmt="psql"))

    # Step 9: cleanup_config
    logger.info("Cleanup configs from DUTs")
    for i in range(0,len(RX_DUTS_PORT_RATIO)):
        cleanup_config(duthosts[i])
    
    # Step 10: Final Result
    logger.info("Determine the final result of the test")
    pytest_assert(result == True, 'Test case test_multidut_fast_reboot failed')

