from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3


class ForwardingSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Network Definitions
    CLIENT_IP = "10.0.1.5"
    SERVER1_IP = "10.0.1.2"
    SERVER2_IP = "10.0.1.3"

    # Switch Port Definitions
    PORT_SERVER1 = 1
    PORT_SERVER2 = 2
    PORT_CLIENT = 3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry (send unmatched packets to controller)
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions, idle_timeout=0)

    def add_flow(
        self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0
    ):
        # Standard helper to send FlowMod messages
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                buffer_id=buffer_id,
                priority=priority,
                match=match,
                idle_timeout=idle_timeout,
                instructions=inst,
            )
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=priority,
                match=match,
                idle_timeout=idle_timeout,
                instructions=inst,
            )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Learn the MAC address
        self.mac_to_port[dpid][src] = in_port

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Check for IPv4 and TCP packets
        if ipv4_pkt and tcp_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst

            # Specific Logic: Monitor traffic from Client to Server 1
            if src_ip == self.CLIENT_IP and dst_ip == self.SERVER1_IP:
                if tcp_pkt.bits & tcp.TCP_SYN:
                    # Log the detection of a TCP handshake start
                    self.logger.info(
                        "TCP SYN detected from Client to Server1! Installing specific flow."
                    )

                    out_port = self.PORT_SERVER1
                    actions = [parser.OFPActionOutput(out_port)]

                    # Create a specific match for this conversation
                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ip_proto=6,  # TCP
                        ipv4_src=self.CLIENT_IP,
                        ipv4_dst=self.SERVER1_IP,
                    )

                    # Install specific flow entry (Priority 10)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(
                            datapath,
                            10,
                            match,
                            actions,
                            buffer_id=msg.buffer_id,
                            idle_timeout=5,
                        )
                        return
                    else:
                        self.add_flow(datapath, 10, match, actions, idle_timeout=5)

                    # Send the packet out
                    data = msg.data
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=in_port,
                        actions=actions,
                        data=data,
                    )
                    datapath.send_msg(out)
                    return

        # Normal L2 Forwarding Logic (Flooding or Unicast)
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

            # Install normal flow entry (Priority 1)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath, 1, match, actions, buffer_id=msg.buffer_id, idle_timeout=5
                )
                return
            else:
                self.add_flow(datapath, 1, match, actions, idle_timeout=5)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
