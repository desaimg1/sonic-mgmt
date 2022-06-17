import pytest
from tests.common.helpers.assertions import pytest_require, pytest_assert
from tests.common.fixtures.conn_graph_facts import conn_graph_facts,\
    fanout_graph_facts
from tests.common.snappi.snappi_fixtures import snappi_api_serv_ip, snappi_api_serv_port,\
    snappi_api, snappi_dut_base_config, get_tgen_peer_ports, get_multidut_snappi_ports
from tests.common.snappi.qos_fixtures import lossy_prio_list, prio_dscp_map_dut_base,\
             lossless_prio_list_dut_base
import random
from files.multidut_helper import run_pfc_test
from tests.common.reboot import reboot
from tests.common.utilities import wait_until
import logging
logger = logging.getLogger(__name__)


pytestmark = [ pytest.mark.topology('snappi') ]

def test_pfc_pause_single_lossy_prio(snappi_api,
                      conn_graph_facts,
                      fanout_graph_facts,
                      duthosts,
                      rand_select_two_dut,
                      get_multidut_snappi_ports):
    """
    Test if PFC will impact a single lossy priority

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        enum_dut_lossy_prio (str): name of lossy priority to test, e.g., 's6100-1|2'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    duts = rand_select_two_dut
    duthost1 = duts[0]
    duthost2 = duts[1]
    snappi_ports = get_multidut_snappi_ports
    port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
    port_set2 = random.sample(get_tgen_peer_ports(snappi_ports, duthost2.hostname), 1)[0]
    tgen_ports = [port_set1[0], port_set2[0]]
    
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
                                                              tgen_ports,
                                                              snappi_ports,
                                                              snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    lossless_prio_list = lossless_prio_list_dut_base(duthost1)
    lossy_prio_list = [x for x in all_prio_list if x not in lossless_prio_list]
    lossy_prio = int(random.sample(lossy_prio_list,1)[0])
    pause_prio_list = [lossy_prio]
    test_prio_list = pause_prio_list
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)


    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)


def test_pfc_pause_multi_lossy_prio(snappi_api,
                      conn_graph_facts,
                      fanout_graph_facts,
                      duthosts,
                      rand_select_two_dut,
                      get_multidut_snappi_ports):
    """
    Test if PFC will impact multiple lossy priorities

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).

    Returns:
        N/A
    """
    duts = rand_select_two_dut
    duthost1 = duts[0]
    duthost2 = duts[1]
    snappi_ports = get_multidut_snappi_ports
    port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
    port_set2 = random.sample(get_tgen_peer_ports(snappi_ports, duthost2.hostname), 1)[0]
    tgen_ports = [port_set1[0], port_set2[0]]
    
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
                                                              tgen_ports,
                                                              snappi_ports,
                                                              snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    lossless_prio_list = lossless_prio_list_dut_base(duthost1)
    lossy_prio_list = [x for x in all_prio_list if x not in lossless_prio_list]
    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
def test_pfc_pause_single_lossy_prio_reboot(snappi_api,
                                            conn_graph_facts,
                                            fanout_graph_facts,
                                            duthosts,
                                            localhost,
                                            rand_select_two_dut,
                                            get_multidut_snappi_ports
                                            reboot_type):
    """
    Test if PFC will impact a single lossy priority after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        rand_lossy_prio (str): lossy priority to test, e.g., 's6100-1|2'
        all_prio_list (pytest fixture): list of all the priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        reboot_type (str): reboot type to be issued on the DUT

    Returns:
        N/A
    """
    duts = rand_select_two_dut
    duthost1 = duts[0]
    duthost2 = duts[1]
    snappi_ports = get_multidut_snappi_ports
    port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
    port_set2 = random.sample(get_tgen_peer_ports(snappi_ports, duthost2.hostname), 1)[0]
    tgen_ports = [port_set1[0], port_set2[0]]
    
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
                                                              tgen_ports,
                                                              snappi_ports,
                                                              snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    lossless_prio_list = lossless_prio_list_dut_base(duthost1)
    lossy_prio_list = [x for x in all_prio_list if x not in lossless_prio_list]
    lossy_prio = int(random.sample(lossy_prio_list,1)[0])
    pause_prio_list = [lossy_prio]
    test_prio_list = pause_prio_list
    bg_prio_list = [p for p in all_prio_list]
    bg_prio_list.remove(lossy_prio)

    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost.hostname))
    reboot(duthost1, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, 0, duthost1.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)

@pytest.mark.disable_loganalyzer
@pytest.mark.parametrize('reboot_type', ['warm', 'cold', 'fast'])
def test_pfc_pause_multi_lossy_prio_reboot(snappi_api,
                                            conn_graph_facts,
                                            fanout_graph_facts,
                                            duthosts,
                                            localhost,
                                            rand_select_two_dut,
                                            get_multidut_snappi_ports,
                                            reboot_type):
    """
    Test if PFC will impact multiple lossy priorities after various kinds of reboots

    Args:
        snappi_api (pytest fixture): SNAPPI session
        snappi_testbed_config (pytest fixture): testbed configuration information
        conn_graph_facts (pytest fixture): connection graph
        fanout_graph_facts (pytest fixture): fanout graph
        localhost (pytest fixture): localhost handle
        duthosts (pytest fixture): list of DUTs
        rand_one_dut_hostname (str): hostname of DUT
        rand_one_dut_portname_oper_up (str): port to test, e.g., 's6100-1|Ethernet0'
        lossless_prio_list (pytest fixture): list of all the lossless priorities
        lossy_prio_list (pytest fixture): list of all the lossy priorities
        prio_dscp_map (pytest fixture): priority vs. DSCP map (key = priority).
        reboot_type (str): reboot type to be issued on the DUT

    Returns:
        N/A
    """

    duts = rand_select_two_dut
    duthost1 = duts[0]
    duthost2 = duts[1]
    snappi_ports = get_multidut_snappi_ports
    port_set1 = random.sample(get_tgen_peer_ports(snappi_ports, duthost1.hostname), 1)[0]
    port_set2 = random.sample(get_tgen_peer_ports(snappi_ports, duthost2.hostname), 1)[0]
    tgen_ports = [port_set1[0], port_set2[0]]
    
    testbed_config, port_config_list, snappi_ports = snappi_dut_base_config([duthost1, duthost2],
                                                              tgen_ports,
                                                              snappi_ports,
                                                              snappi_api)
    prio_dscp_map = prio_dscp_map_dut_base(duthost1)
    all_prio_list = prio_dscp_map.keys()
    lossless_prio_list = lossless_prio_list_dut_base(duthost1)
    lossy_prio_list = [x for x in all_prio_list if x not in lossless_prio_list]
    pause_prio_list = lossy_prio_list
    test_prio_list = lossy_prio_list
    bg_prio_list = lossless_prio_list

    logger.info("Issuing a {} reboot on the dut {}".format(reboot_type, duthost1.hostname))
    reboot(duthost1, localhost, reboot_type=reboot_type)
    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, 0, duthost1.critical_services_fully_started),
                  "Not all critical services are fully started")

    run_pfc_test(api=snappi_api,
                 testbed_config=testbed_config,
                 port_config_list=port_config_list,
                 conn_data=conn_graph_facts,
                 fanout_data=fanout_graph_facts,
                 duthost1=duthost1,
                 rx_port_id=snappi_ports[0]["port_id"],
                 duthost2=duthost2,
                 tx_port_id=snappi_ports[1]["port_id"],
                 global_pause=False,
                 pause_prio_list=pause_prio_list,
                 test_prio_list=test_prio_list,
                 bg_prio_list=bg_prio_list,
                 prio_dscp_map=prio_dscp_map,
                 test_traffic_pause=False)
