logger = logging.getLogger(__name__)
import re
from reboot_variable import *
from tests.common.utilities import (wait, wait_until)
from tests.common.snappi.snappi_fixtures import (
   snappi_api_serv_ip, snappi_api_serv_port, get_multidut_snappi_ports,
   get_dut_interconnected_ports,
   create_ip_list, get_tgen_peer_ports)
from statistics import mean
from tests.common.helpers.assertions import pytest_assert
from tests.common.reboot import reboot
from threading import Thread
import time
import json


###############################################################
#                   supporting functions
###############################################################
def get_macs(mac, count, offset=1):
    """
    Take mac as start mac returns the count of macs in a list
    """
    mac_list = list()
    for i in range(count):
        mac_address = "{:012X}".format(int(mac, 16) + offset * i)
        mac_address = ":".join(
            format(s, "02x") for s in bytearray.fromhex(mac_address)
        )
        mac_list.append(mac_address)
    return mac_list

def reboot_config(cvg_api, tg_ports):
    """
    1.Configure IPv4 EBGP sessions between Keysight ports(rx & tx)
    2.Configure and advertise IPv4 routes from rx
    """
    port_count = len(tg_ports)
    conv_config = cvg_api.convergence_config()
    cvg_api.enable_scaling(True)
    config = conv_config.config
    ipv4_1_names = []
    ipv4_2_names = []
    # ipv6_1_names = []
    # ipv6_2_names = []

    for i in range(1, port_count+1):
        if i ==1 :
            config.ports.port(name='Test_Port_%d' % i, location=tg_ports[i-1])
        else:
            config.ports.port(name='Server_Port_{}'.format(i-1), location=tg_ports[i-1])
                  
    config.options.port_options.location_preemption = True
    layer1 = config.layer1.layer1()[-1]
    layer1.name = 'port settings'
    layer1.port_names = [port.name for port in config.ports]
    layer1.ieee_media_defaults = False
    layer1.auto_negotiation.rs_fec = True
    layer1.auto_negotiation.link_training = False
    layer1.speed = port_speed
    layer1.auto_negotiate = False
    for i in range(1, port_count+1):
        if len(str(hex(i).split('0x')[1])) == 1:
            m = '0'+hex(i).split('0x')[1]
        else:
            m = hex(i).split('0x')[1]
        if i==1 :
            d1 = config.devices.device(name='T1')[-1]
            ethernet_stack = d1.ethernets.add()
            ethernet_stack.port_name = config.ports[i-1].name
            ethernet_stack.name = 'Ethernet %d' % i
            ethernet_stack.mac = "00:00:00:00:00:%s" % m
            ipv4_stack = ethernet_stack.ipv4_addresses.add()
            ipv4_stack.name = 'IPv4 %d' % i
            ipv4_stack.address = tgenIps[i-1]
            ipv4_stack.gateway = dutIps[i-1]
            ipv4_stack.prefix = ipMask
            bgpv4 = config.devices[i-1].bgp
            bgpv4.router_id =  dutIps[i-1] 
            bgpv4_int = bgpv4.ipv4_interfaces.add()
            bgpv4_int.ipv4_name = ipv4_stack.name
            bgpv4_peer = bgpv4_int.peers.add()
            bgpv4_peer.name = 'BGP %d' % i
            bgpv4_peer.as_type = BGP_TYPE
            bgpv4_peer.peer_address = dutIps[i-1]
            bgpv4_peer.as_number = int(TGEN_AS_NUM)
            v4_route_range = bgpv4_peer.v4_routes.add(name="Network_Group_1") #snappi object named Network Group 2 not found in internal db
            v4_route_range.addresses.add(address='200.1.0.1', prefix=32, count=NO_OF_ROUTES)
            # ipv6_stack = ethernet_stack.ipv6_addresses.add()
            # ipv6_stack.name = 'IPv6 %d' % i
            # ipv6_stack.address = tgenV6Ips[i-1]
            # ipv6_stack.gateway = dutV6Ips[i-1]
            # ipv6_stack.prefix = int(ipv6Mask)
            # bgpv6_int = bgpv4.ipv6_interfaces.add()
            # bgpv6_int.ipv6_name = ipv6_stack.name
            # bgpv6_peer = bgpv6_int.peers.add()
            # bgpv6_peer.name  = 'BGP+_%d' % i
            # bgpv6_peer.as_type = BGP_TYPE
            # bgpv6_peer.peer_address = dutV6Ips[i-1]
            # bgpv6_peer.as_number = int(TGEN_AS_NUM)
            # v6_route_range = bgpv6_peer.v6_routes.add(name="Network_Group_2")
            # v6_route_range.addresses.add(address='3000::1', prefix=64, count=NO_OF_ROUTES)
        else:
            for j in range(1, NO_OF_DEVICES+1):
                if len(str(hex(j).split('0x')[1])) == 1:
                    m = '0'+hex(j).split('0x')[1]
                else:
                    m = hex(j).split('0x')[1]
                d1 = config.devices.device(name='Server_{}_{}'.format(i-1, j))[-1]
                eth_1 = d1.ethernets.add()
                eth_1.port_name = config.ports[i-1].name
                eth_1.name = 'Ethernet {}_{}'.format(i-1, j)
                eth_1.mac = get_macs("000{}00000011".format(i), NO_OF_DEVICES)[j-1]
                ipv4_1 = eth_1.ipv4_addresses.add()
                ipv4_1.name = 'IPv4 {}_{}'.format(i-1, j)
                ipv4_1.address = create_ip_list(tgenIps[i-1], NO_OF_DEVICES, mask=32)[j-1]
                ipv4_1.gateway = dutIps[i-1]
                ipv4_1.prefix = ipMask
                # ipv6_1 = eth_1.ipv6_addresses.add()
                # ipv6_1.name = 'IPv6 {}_{}'.format(i-1, j)
                # ipv6_1.address = create_ip_list(tgenV6Ips[i-1], NO_OF_DEVICES, mask=128)[j-1]
                # ipv6_1.gateway = dutV6Ips[i-1]
                # ipv6_1.prefix = ipv6Mask
                if (i%2 ==0):
                    ipv4_1_names.append(ipv4_1.name)
                #    ipv6_1_names.append(ipv6_1.name)
                else:
                    ipv4_2_names.append(ipv4_1.name)
                #    ipv6_2_names.append(ipv6_1.name)

    def createTrafficItem(traffic_name, src, dest, rate=50):
        flow1 = config.flows.flow(name=str(traffic_name))[-1]
        flow1.tx_rx.device.tx_names = src
        flow1.tx_rx.device.rx_names = dest
        flow1.size.fixed = 1024
        flow1.rate.percentage = rate
        flow1.metrics.enable = True

    createTrafficItem("IPv4_1-IPv4_2", ipv4_1_names, ipv4_2_names)
    # createTrafficItem("IPv6_2-IPv6_1", ipv6_2_names, ipv6_1_names)
    createTrafficItem("IPv4_1-T1", ipv4_1_names, [v4_route_range.name])
    # createTrafficItem("IPv6_2-T1", ipv6_2_names, [v6_route_range.name])
    createTrafficItem("T1-IPv4_1", [v4_route_range.name], ipv4_1_names)
    # createTrafficItem("T1-IPv6_2", [v6_route_range.name], ipv6_2_names)
    return conv_config



def configure_duts(duthosts, ports):
    logger.info("Configure DUTS initially")
    j, port_count=0, 0
    for val in RX_DUTS_PORT_RATIO:
        host = duthosts[val[0]-1]
        vlan_config = (
                    'sudo config vlan add %s\n'
                    'sudo config interface ip add Vlan%s %s/%s\n'
        )
        vlan_config %= (VLAN_ID, VLAN_ID, dutIps[0], ipMask)
        host.shell(vlan_config)

        dut="dut" + str(val[0])
        dutAs=dutsAsNum
        if j == 0:
            port_count = NO_OF_TX_PORTS + val[1]
        else:
            port_count +=val[1]
        for i in range(j, port_count):
            vlan_config = (
                    'sudo config vlan member add -u %s %s\n'
            )
            vlan_config %= (VLAN_ID, ports[i])
            host.shell(vlan_config)
            if j == 0:
                # portchannel_config = (
                #     " sudo config int fec %s rs \n"
                #     " sudo config portchannel add PortChannel%s \n"
                #     " sudo config portchannel member add PortChannel%s %s \n"
                #     " sudo config interface ip add PortChannel%s %s/%s \n"
                #     " sudo config interface ip add PortChannel%s %s/%s \n"
                # )%(ports[i], i+1, i+1, ports[i], i+1, dutIps[i], ipMask, i+1, dutV6Ips[i], ipv6Mask )
                # host.shell(portchannel_config) 
                # bgp_config = (
                #         "vtysh "
                #         "-c 'configure terminal' "
                #         "-c 'router bgp %s' "
                #         "-c 'no bgp ebgp-requires-policy' "
                #         "-c 'bgp bestpath as-path multipath-relax' "
                #         "-c 'maximum-paths 64' "
                #         "-c 'neighbor tgen-v4 peer-group' "
                #         "-c 'neighbor tgen-v4 remote-as %s' "
                #         "-c 'neighbor %s peer-group tgen-v4' "
                #         "-c 'neighbor tgen-v6 peer-group' "
                #         "-c 'neighbor tgen-v6 remote-as %s' "
                #         "-c 'neighbor %s peer-group tgen-v6' "
                #         "-c 'address-family ipv4 unicast' "
                #         "-c 'neighbor tgen-v4 activate' "
                #         "-c 'address-family ipv6 unicast' "
                #         "-c 'neighbor tgen-v6 activate' "
                #         "-c 'exit' "
                # )
                # bgp_config %= (dutAs, TGEN_AS_NUM, tgenIps[i], TGEN_AS_NUM, tgenV6Ips[i])
                # portchannel_config = (
                #     " sudo config int fec %s rs \n"
                #     " sudo config portchannel add PortChannel%s \n"
                #     " sudo config portchannel member add PortChannel%s %s \n"
                #     " sudo config interface ip add PortChannel%s %s/%s \n"

                # )%(ports[i], i+1, i+1, ports[i], i+1, dutIps[i], ipMask)
                # host.shell(portchannel_config) 
                bgp_config = (
                        "vtysh "
                        "-c 'configure terminal' "
                        "-c 'router bgp %s' "
                        "-c 'no bgp ebgp-requires-policy' "
                        "-c 'bgp bestpath as-path multipath-relax' "
                        "-c 'maximum-paths 64' "
                        "-c 'neighbor tgen-v4 peer-group' "
                        "-c 'neighbor tgen-v4 remote-as %s' "
                        "-c 'neighbor %s peer-group tgen-v4' "
                        "-c 'address-family ipv4 unicast' "
                        "-c 'neighbor tgen-v4 activate' "
                        "-c 'exit' "
                )
                bgp_config %= (dutAs, TGEN_AS_NUM, tgenIps[i])

                host.shell(bgp_config)
                loopback = (
                    "sudo config interface ip add Loopback1 1.1.1.1/32\n"
                )
                logger.info('Configuring 1.1.1.1/32 on the loopback interface')
                host.shell(loopback)
            j+=1
    
    start = time.time()
    host = duthosts[0]   
    logger.info('Configuring BGP in config_db.json')
    bgp_neighbors = {tgenIps[0]: {"rrclient": "0", "name": "ARISTA08T0",
                                           "local_addr": dutIps[0], "nhopself": "0",
                                           "holdtime": "90", "asn": TGEN_AS_NUM,"keepalive": "30"}}
    import pdb; pdb.set_trace()
    cdf = json.loads(host.shell("sonic-cfggen -d --print-data")['stdout'])
    for neighbor, neighbor_info in bgp_neighbors.items():
        cdf["BGP_NEIGHBOR"][neighbor] = neighbor_info

    with open("/tmp/sconfig_db.json", 'w') as fp:
        json.dump(cdf, fp, indent=4)
    host.copy(src="/tmp/sconfig_db.json", dest="/tmp/config_db_temp.json")
    cdf = json.loads(host.shell("sonic-cfggen -j /tmp/config_db_temp.json --print-data")['stdout'])
    print(cdf)
    host.command("sudo cp {} {} \n".format("/tmp/config_db_temp.json", "/etc/sonic/config_db.json"))
    logger.info('Reloading config to apply BGP config')
    host.shell("sudo config reload -y \n")
    wait(TIMEOUT+60, "For Config to reload \n")
    end = time.time()
    logger.info('duthost_bpg_config() took {}s to complete'.format(end-start))


def get_flow_stats(cvg_api):
    """
    Args:
        cvg_api (pytest fixture): Snappi API
    """
    request = cvg_api.convergence_request()
    request.metrics.flow_names = []
    return cvg_api.get_results(request).flow_metric

def get_bgpv4_metrics(cvg_api, bgp_req):
    """
    Args:
        cvg_api (pytest fixture): snappi API
        bgp_req : ping_req, snappi API object

    """
    return cvg_api.get_results(bgp_req).bgpv4_metrics

def ping_loopback_if(cvg_api, ping_req):
    """
    Args:
        cvg_api (pytest fixture): snappi API
        ping_req : ping_req, snappi API object

    """
    return cvg_api.send_ping(ping_req).responses

def wait_for_bgp_and_lb_soft(cvg_api, ping_req,):
    """
    Method for when reboot type is Soft.  Check for Loopback I/F to go down then take timestamp.
    Then check for LoopBack I/F state to change from down to up and record timestamp.

    Args:
        cvg_api (pytest fixture): snappi API
        ping_req : ping_req, snappi API

    """
    global loopback_down_start_timer
    global loopback_up_start_timer

    found_lb_state = False
    while True:
        responses = ping_loopback_if(cvg_api, ping_req)
        if not found_lb_state and not responses[-1].result in "success":
            loopback_down_start_timer = time.time()
            found_lb_state = True
            logger.info('!!!!!!! 1. loopback timer started {} !!!!!!'.format(loopback_down_start_timer))
            break

    # reset states, look for BGP and Loopback states to come back up and mark time
    found_lb_state = False
    while True:
        responses = ping_loopback_if(cvg_api, ping_req)
        if not found_lb_state and responses[-1].result in "success":
            loopback_up_start_timer = time.time()
            found_lb_state = True
            logger.info('!!!!!!! 2. loopback up end time {} !!!!!!'.format(loopback_up_start_timer))
            break


def wait_for_bgp_and_lb(cvg_api, ping_req,):
    """
    Method to wait for BGP and Loopback state to change from up to down take timestamp of event.
    Then wait for BGP and Loopback state to change from down to up and take timestamp of event.

    Args:
        cvg_api (pytest fixture): snappi API
        ping_req : ping_req, snappi API
    """
    global loopback_down_start_timer
    global loopback_up_start_timer
    global bgp_down_start_timer
    global bgp_up_start_timer

    bgp_req = cvg_api.convergence_request()
    bgp_req.bgpv4.peer_names = []

    found_bgp_state = False
    found_lb_state = False
    while True:
        bgpv4_metrics = get_bgpv4_metrics(cvg_api, bgp_req)
        responses = ping_loopback_if(cvg_api, ping_req)
        if not found_bgp_state and bgpv4_metrics[-1].session_state in "down":
            bgp_down_start_timer = time.time()
            found_bgp_state = True
            logger.info('!!!!! 1. bgp is down time started {} !!!!!'.format(bgp_down_start_timer))
        if not found_lb_state and not responses[-1].result in "success":
            loopback_down_start_timer = time.time()
            found_lb_state = True
            logger.info('!!!!!!! 1. loopback timer started {} !!!!!!'.format(loopback_down_start_timer))
        if bgpv4_metrics[-1].session_state in "down" and not responses[-1].result in "success" and \
                found_bgp_state and found_lb_state:
            logger.info('BGP Control And LoopBack I/F Down')
            break

    # reset states, look for BGP and Loopback states to come back up and mark time
    found_bgp_state = False
    found_lb_state = False
    while True:
        bgpv4_metrics = get_bgpv4_metrics(cvg_api, bgp_req)
        responses = ping_loopback_if(cvg_api, ping_req)
        if not found_bgp_state and bgpv4_metrics[-1].session_state in "up":
            bgp_up_start_timer = time.time()
            found_bgp_state = True
            logger.info('^^^^^ 2. bgp is up end time {} ^^^^^'.format(bgp_up_start_timer))
        if not found_lb_state and responses[-1].result in "success":
            loopback_up_start_timer = time.time()
            found_lb_state = True
            logger.info('!!!!!!! 2. loopback up end time {} !!!!!!'.format(loopback_up_start_timer))
        if bgpv4_metrics[-1].session_state in "up" and responses[-1].result in "success" and \
               found_bgp_state and found_lb_state:
            logger.info('BGP Control And LoopBack I/F Up')
            break

def get_convergence_for_reboot_test(duthosts,
                                    localhost,
                                    cvg_api,
                                    reboot_type,
                                    ):
    """
    Args:
        duthost (pytest fixture): duthost fixture
        localhost (pytest fixture): localhost handle
        cvg_api (pytest fixture): snappi API
        bgp_config: __tgen_bgp_config
        reboot_type: Type of reboot
    """
    global bgp_up_start_timer
    global bgp_down_start_timer
    global loopback_up_start_timer
    global loopback_down_start_timer
    table, dp = [], []
    logger.info('Starting Traffic')
    cs = cvg_api.convergence_state()
    #flow_names = ["IPv4_1-IPv4_2", "IPv6_2-IPv6_1", "IPv4_1-T1", "IPv6_2-T1", "T1-IPv4_1", "T1-IPv6_2"]
    flow_names = ["IPv4_1-IPv4_2", "IPv4_1-T1", "T1-IPv4_1"]
    cs.transmit.flow_names = flow_names
    logger.info('Starting Protocol')
    time.sleep(10)
    cs.protocol.state = cs.protocol.START
    cvg_api.set_state(cs)
    logger.info('Starting Traffic')
    cs.transmit.state = cs.transmit.START
    cvg_api.set_state(cs)
    wait(TIMEOUT-10, "For Traffic To start")

    def check_bgp_state():
        req = cvg_api.convergence_request()
        req.bgpv4.peer_names = []
        bgpv4_metrics = cvg_api.get_results(req).bgpv4_metrics
        assert bgpv4_metrics[-1].session_state == "up", "BGP v4 Session State is not UP"
        logger.info("BGP v4 Session State is UP")
        # req.bgpv6.peer_names = []
        # bgpv6_metrics = cvg_api.get_results(req).bgpv6_metrics
        # assert bgpv6_metrics[-1].session_state == "up", "BGP v6 Session State is not UP"
        # logger.info("BGP v6 Session State is UP")

    check_bgp_state()
    ping_req = cvg_api.ping_request()
    p1 = ping_req.endpoints.ipv4()[-1]
    p1.src_name = 'IPv4 1'
    p1.dst_ip = "1.1.1.1"
    for i in range(len(REBOOT_DUT_LISTS)):
        duthosts[REBOOT_DUT_LISTS[i]-1].command("sudo config save -y")
        logger.info("Issuing a {} reboot on the dut {}".format(reboot_type,duthosts[REBOOT_DUT_LISTS[i]-1].hostname))
        Thread(target=reboot, args=([duthosts[REBOOT_DUT_LISTS[i]-1], localhost, reboot_type])).start()
    reboot_type_lists = ['warm', 'cold', 'fast']
    if reboot_type in reboot_type_lists:
        wait_for_bgp_and_lb(cvg_api, ping_req,)
    else:
        # soft-reboot
        wait_for_bgp_and_lb_soft(cvg_api, ping_req)
    bgp_up_time = bgp_up_start_timer - bgp_down_start_timer
    loopback_up_time = loopback_up_start_timer - loopback_down_start_timer
    logger.info("Wait until the system is stable")
    wait_until(360, 10, 1, duthosts[REBOOT_DUT_LISTS[i]-1].critical_services_fully_started)

    request = cvg_api.convergence_request()
    request.convergence.flow_names = flow_names
    convergence_metrics = cvg_api.get_results(request).flow_convergence

    for i, metrics in zip(flow_names, convergence_metrics):
        if reboot_type == "warm":
            request.metrics.flow_names = [i]
            flow = cvg_api.get_results(request).flow_metric
            if flow[0].frames_tx_rate != flow[0].frames_tx_rate:
                logger.info("Some Loss Observed in Traffic Item {}".format(i))
                dp.append(metrics.data_plane_convergence_us/1000)
                logger.info('DP/DP Convergence Time (ms) of {} : {}'.format(i, metrics.data_plane_convergence_us/1000))
            else:
                dp.append(0)
                logger.info('DP/DP Convergence Time (ms) of {} : {}'.format(i, 0))
        else:
            request.metrics.flow_names = [i]
            flow = cvg_api.get_results(request).flow_metric
            assert int(flow[0].frames_tx_rate) != 0, "No Frames sent for traffic item: {}".format(i)
            assert flow[0].frames_tx_rate == flow[0].frames_tx_rate, "Loss observed for Traffic Item: {}".format(i)
            logger.info("No Loss Observed in Traffic Item {}".format(i))
            dp.append(metrics.data_plane_convergence_us/1000)
            logger.info('DP/DP Convergence Time (ms) of {} : {}'.format(i, metrics.data_plane_convergence_us/1000))

    #flow_names_table_rows = ["Server IPv4_1 - Server IPv4_2", "Server IPv6_2 - Server IPv6_1", "Server IPv4_1 - T1",
    #                         "Server IPv6_2 - T1", "T1 - Server IPv4_1", "T1 - Server IPv6_2"]
    flow_names_table_rows = ["Server IPv4_1 - Server IPv4_2",  "Server IPv4_1 - T1",
                              "T1 - Server IPv4_1"]
    for j, i in enumerate(flow_names_table_rows):
        table.append([reboot_type, i, dp[j], float(0.0)])
    table.append([reboot_type, 'BGP Control Plane Up Time', float(0.0), float(bgp_up_time)*1000])
    table.append([reboot_type, ''.join('Loopback Up Time'.format(p1.dst_ip)), float(0.0),
                  float(loopback_up_time)*1000])
                  
    return table

def configure_inter_duts(duthosts, conn_graph_facts, route_type ='ipv4'):
    nwlist = create_ip_list(inter_dut_network_start, len(duthosts)-1, 8) 
    for i in range(0, len(duthosts)-1):
        host1 = duthosts[i]
        host2 = duthosts[i+1]
        h1_h2_ports = get_dut_interconnected_ports(conn_graph_facts, host1.hostname, host2.hostname)
        iplist = create_ip_list(nwlist[i], 2, 32)
        h1_h2_port = h1_h2_ports[0]
        host1.shell("sudo config interface ip add %s %s/%s \n"%(h1_h2_port[0], iplist[0], ipMask))
        host2.shell("sudo config interface ip add %s %s/%s \n"%(h1_h2_port[1], iplist[1], ipMask))
        bgp_config1 = (
                    "vtysh "
                    "-c 'configure terminal' "
                    "-c 'router bgp %s' "
                    "-c 'neighbor %s remote-as %s' "
                    "-c 'address-family ipv4 unicast' "
                    "-c 'neighbor %s activate' "
                    "-c 'exit' "
        )%(dutsAsNum[i], iplist[1], dutsAsNum[i+1], iplist[1] )
        host1.shell(bgp_config1)
        bgp_config2 = (
                    "vtysh "
                    "-c 'configure terminal' "
                    "-c 'router bgp %s' "
                    "-c 'neighbor %s remote-as %s' "
                    "-c 'address-family ipv4 unicast' "
                    "-c 'neighbor %s activate' "
                    "-c 'exit' "
        )%(dutsAsNum[i+1], iplist[0], dutsAsNum[i], iplist[0] )
        host2.shell(bgp_config2)

def save_current_config(duthost):
    duthost.command("sudo config save -y")
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db.json", "/etc/sonic/config_db_backup.json"))

def cleanup_config(duthost):
    """
    Cleaning up dut config at the end of the test

    Args:
        duthost (pytest fixture): duthost fixture
    """
    duthost.command("sudo cp {} {}".format("/etc/sonic/config_db_backup.json","/etc/sonic/config_db.json"))
    duthost.shell("sudo config reload -y \n")
    logger.info("Wait until all critical services are fully started")
    wait_until(120, 10, 1, duthost.critical_services_fully_started)
    logger.info('Convergence Test Completed')

def verify_loadshare(tx_pkt, rx_pkt):
    tol_val = tx_pkt * tolerenceVal / 100
    if rx_pkt > tx_pkt + tol_val or rx_pkt < tx_pkt - tol_val :
        raise Exception("Traffic Loadshare failed")

def verify_interface(duthost,interface):
    """
       proc : verify_interface
       :param :
       :return admin and oper state of interface

    """
    admin_status = ""
    oper_status = ""
    out = duthost.command("show interfaces status {}".format(interface))['stdout']
    logger.info(out)
    match = re.search("%s.*\w+\s+(\w+)\s+(\w+)\s+\S+\s+\S+" % interface, out)
    if match:
        admin_status = match.group(1)
        oper_status = match.group(2)
    return (admin_status, oper_status)

def verify_ping_from_dut(duthost, ip):
    """
       proc: verify_ping_from_dut
       :return True/False
    """
    logger.info("Verify ping to {} from DUT".format(ip))
    try:
        res = duthost.command("ping -c 5 {}".format(ip))['stdout']
    except:
        res = "100% packet loss"
    if re.search(" 0% packet loss",res):
        logger.info("ping successful to {}. PASSED!!".format(ip))
        return True
    else:
        logger.info("ping unsuccessful to {}. FAILED!!".format(ip))
        return False

def verify_bgp_neighbor_state(duthost, ipAddress, iterVal=1, sleepVal=10, expState ="Established", route_type='ipv4'):
    """
       proc : verify_bgp_neighbor_state
       :param :
       :return : True/False

    """
    logger.info("Verify BGP Neighbor state {}".format(ipAddress))
    for count in range(iterVal):
        if route_type == 'ipv4':
            ret = duthost.command("show ip bgp neighbors {}".format(ipAddress))["stdout"]
        else:
            ret = duthost.command("show ipv6 bgp neighbors {}".format(ipAddress))["stdout"]
        if re.search('BGP\s+state\s+=\s+%s'%(expState), ret):
            logger.info(ret)
            logger.info("BGP neighbor {} Established between {} and IXIA PASSED".format(ipAddress, duthost.hostname))
            return True
        else:
            logger.info("Waiting for bgp neighbors to come up")
            wait(sleepVal, "For Protocols To start")
    else:
        logger.info("BGP neighbor {} Established between {} and IXIA FAILED".format(ipAddress, duthost.hostname))
        return False

def verify_route_summary(duthost, expRts, version="ip", protocol="ebgp", iterVal=1, sleepVal =2):
    result = True
    availableRoutes = 0

    for i in range (iterVal):
        logger.info("ITERATION : {}".format(i))
        out = duthost.command("show {} route summary".format(version))["stdout"]
        logger.info(out)
        match = re.search("%s\s+\d+\s+(\d+)"%protocol, out)
        if match:
            availableRoutes = int(match.group(1))
            if availableRoutes == int(expRts):
                logger.info("Verify routes  in {} via ebgp PASSED!!".format(duthost.hostname))
                break
            else:
                logger.info("Expected {} routes {}, actual {}".format(protocol, expRts,
                                                                       availableRoutes))
                wait(sleepVal, "For routes to update")
    else:
        logger.info("Verify routes in {} via ebgp FAILED!!".format(duthost.hostname))
        result = False

    return {'result' : result, 'avlRoutes' : availableRoutes}

def get_system_stats(duthost):
    """Gets Memory and CPU usage from DUT"""
    stdout_lines = duthost.command("vmstat")["stdout_lines"]
    data = list(map(float, stdout_lines[2].split()))

    total_memory  = sum(data[2:6])
    used_memory = sum(data[4:6])

    total_cpu = sum(data[12:15])
    used_cpu = sum(data[12:14])

    return (used_memory, total_memory, used_cpu, total_cpu)

def verify_interfaces(duthosts, ports):
    j, port_count=0, 0
    for val in RX_DUTS_PORT_RATIO:
        host = duthosts[val[0]-1]
        if j == 0:
            port_count = NO_OF_TX_PORTS + val[1]
        else:
            port_count +=val[1]
        for i in range(j, port_count):  
            admin_state, oper_state = verify_interface(host, ports[i])
            if not (admin_state == "up" and oper_state == "up"):
                logger.info("port {} is not up initially. Hence Aborting!!".format(ports[i]))
                raise Exception("Initial port Check failed for {} in dut {}".format(ports[i], host.hostname))
            j +=1

def verify_ping(duthosts, tgenIps):
    result = True
    j, port_count=0, 0
    for val in RX_DUTS_PORT_RATIO:
        host = duthosts[val[0]-1]
        if j == 0:
            port_count = NO_OF_TX_PORTS + val[1]
        else:
            port_count +=val[1]
        for i in range(j, port_count):   
            if not verify_ping_from_dut(host, tgenIps[i]):
                result = False
            j+=1
    logger.info("return verify ping {}".format(result))
    return result

def verify_bgp_neighbors(duthosts, tgenIps, route_type='ipv4'):
    result = True
    host = duthosts[0]
    if not verify_bgp_neighbor_state(host, tgenIps[0], route_type=route_type):   
        result = False
    logger.info("return verify bgp neighbors {}".format(result))
    return result

def verify_routes(duthosts , route_type = 'ipv4'):
    result = True
    if route_type == 'ipv4':
        if not verify_route_summary(duthosts[0], NO_OF_ROUTES)['result']:
            result = False
    else:
        if not verify_route_summary(duthosts[0], NO_OF_ROUTES, version=route_type)['result']:
            result = False
    logger.info("return verify routes {}".format(result))
    return result

