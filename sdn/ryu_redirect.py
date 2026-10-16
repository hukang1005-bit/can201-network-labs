from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types, ethernet, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3


class RedirectSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # IP addresses for the network hosts
    SERVER1_IP = "10.0.1.2"
    SERVER2_IP = "10.0.1.3"
    CLIENT_IP = "10.0.1.5"

    # MAC addresses for the network hosts
    SERVER1_MAC = "00:00:00:00:00:01"
    SERVER2_MAC = "00:00:00:00:00:02"
    CLIENT_MAC = "00:00:00:00:00:03"

    # Port mappings on the OpenFlow switch
    PORT_SERVER1 = 1
    PORT_SERVER2 = 2
    PORT_CLIENT = 3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Dictionary to store MAC-to-Port mappings (Simple L2 Learning)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        Handshake phase: Install the Table-Miss Flow Entry.
        This tells the switch to send any unmatched packets to the Controller.
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(
        self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0
    ):
        """
        Helper function to add a Flow Entry to the switch's flow table.
        """
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
        """
        Main logic: Handles incoming packets sent by the switch to the controller.
        """
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP (Link Layer Discovery Protocol) packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        # Check if the packet is IPv4 and TCP
        if ipv4_pkt and tcp_pkt:
            src = ipv4_pkt.src
            dst = ipv4_pkt.dst

            # Detect traffic flow direction
            # Case 1: Client trying to reach Server 1 (The target to redirect)
            is_client_to_server = src == self.CLIENT_IP and dst == self.SERVER1_IP

            # Case 2: Server 2 replying to Client (Masquerading as Server 1)
            is_server_to_client = src == self.SERVER2_IP and dst == self.CLIENT_IP

            if is_client_to_server or is_server_to_client:
                is_syn = tcp_pkt.bits & tcp.TCP_SYN

                if is_syn:
                    # If it's the start of a TCP connection (SYN), install a flow rule
                    self._logic_tcp_syn_flow(
                        datapath, msg, in_port, is_client_to_server
                    )
                else:
                    # For other TCP packets (ACK, PSH, etc.), just forward them immediately
                    # (Note: Usually the flow installed by SYN handles this, but this covers buffering gaps)
                    self._logic_tcp_packet_out(
                        datapath, msg, in_port, is_client_to_server
                    )
                return

        # If not specific TCP traffic, fall back to normal Layer 2 switching
        self._logic_normal(datapath, msg, in_port, eth.src, eth.dst)

    def _logic_tcp_syn_flow(self, datapath, msg, in_port, is_client_to_server):
        """
        Handles TCP SYN packets by installing a Flow Modification (FlowMod).
        This performs the actual redirection (Header Rewriting).
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.logger.info("Logic 1: TCP SYN detected. Installing Priority 10 Flow.")

        if is_client_to_server:
            # Client -> Server 1: Redirect to Server 2
            # Rewrite Dest MAC and Dest IP to Server 2's details
            actions = [
                parser.OFPActionSetField(eth_dst=self.SERVER2_MAC),
                parser.OFPActionSetField(ipv4_dst=self.SERVER2_IP),
                parser.OFPActionOutput(self.PORT_SERVER2),
            ]
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP,
                ip_proto=6,
                ipv4_src=self.CLIENT_IP,
                ipv4_dst=self.SERVER1_IP,
            )
        else:
            # Server 2 -> Client: Masquerade as Server 1
            # Rewrite Src MAC and Src IP to look like they came from Server 1
            actions = [
                parser.OFPActionSetField(eth_src=self.SERVER1_MAC),
                parser.OFPActionSetField(ipv4_src=self.SERVER1_IP),
                parser.OFPActionOutput(self.PORT_CLIENT),
            ]
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=ether_types.ETH_TYPE_IP,
                ip_proto=6,
                ipv4_src=self.SERVER2_IP,
                ipv4_dst=self.CLIENT_IP,
            )

        # Install the flow with high priority (10) and a short timeout
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            self.add_flow(
                datapath, 10, match, actions, buffer_id=msg.buffer_id, idle_timeout=5
            )
        else:
            self.add_flow(datapath, 10, match, actions, idle_timeout=5)

            # Send the current packet out immediately so it isn't lost
            data = msg.data
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=data,
            )
            datapath.send_msg(out)

    def _logic_tcp_packet_out(self, datapath, msg, in_port, is_client_to_server):
        """
        Manually sends a single packet out with header rewriting (without installing a flow).
        """
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if is_client_to_server:
            # Rewrite Dest to Server 2
            actions = [
                parser.OFPActionSetField(eth_dst=self.SERVER2_MAC),
                parser.OFPActionSetField(ipv4_dst=self.SERVER2_IP),
                parser.OFPActionOutput(self.PORT_SERVER2),
            ]
        else:
            # Rewrite Src to appear as Server 1
            actions = [
                parser.OFPActionSetField(eth_src=self.SERVER1_MAC),
                parser.OFPActionSetField(ipv4_src=self.SERVER1_IP),
                parser.OFPActionOutput(self.PORT_CLIENT),
            ]

        data = msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    def _logic_normal(self, datapath, msg, in_port, src, dst):
        """
        Standard Layer 2 Learning Switch Logic.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # Learn the Source MAC address to avoid flooding next time
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Check if we know the output port for the Destination MAC
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD  # Flood if unknown

        actions = [parser.OFPActionOutput(out_port)]

        # If destination is known, install a flow to avoid future Packet-Ins for this pair
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
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

        # Send the packet out
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
