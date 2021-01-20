from ryu.base import app_manager
from ryu.lib import hub
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types,lldp,packet,ethernet
import subprocess
import networkx as nx
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
from webob import Response
import requests
from networkx.readwrite import json_graph


controller_instance_name = 'controller_api_app'
url = '/topology'

### Controller 0 ###
class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self,*args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.C1nodes = []
        self.C2nodes = []
        self.net = nx.DiGraph()
        self.monitor_thread = hub.spawn(self.topology_discovery)


        wsgi = kwargs['wsgi']
        wsgi.register(RESTController,
                      {controller_instance_name: self})

    ### Switch Features Request ####
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        match_lldp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP,eth_dst=lldp.LLDP_MAC_NEAREST_BRIDGE)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                      ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath,0xFFFF,match_lldp,actions)
        self.send_port_desc_stats_request(datapath)

    def send_port_desc_stats_request(self, datapath):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    ### Add a flow in a Flow Table ###
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    ### Port desc handler ###
    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        switch = Switch(datapath)
        for stat in ev.msg.body:
            port = Port(ev.msg.datapath.id, ofproto, stat)
            switch.add_port(port)
        self.datapaths[datapath.id] = switch
        self.logger.info('OFPPortDescStatsReply received: %s' % (str(switch)))

    ### Topology discovery ###
    def topology_discovery(self):
        while True:
            for datap in self.datapaths.values():
                for port in datap.ports:
                    self.send_lldp_packet(datap.dp, port.port_no, port.hw_addr, 10)
            hub.sleep(10)  # every 10 seconds

    ### Send the lldp packet ###
    def send_lldp_packet(self, datapath, port, hw_addr, ttl):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        # LLDP packet
        pkt_lldp = self.lldp_packet(datapath, hw_addr, port)

        #self.logger.info("packet - out % s" % pkt_lldp)
        data = pkt_lldp.data
        actions = [ofp_parser.OFPActionOutput(port=port)]
        out = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions, data=data)
        datapath.send_msg(out)

    ### Create an LLDP packet ###
    def lldp_packet(self,datapath,hw_addr,port):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=ether_types.ETH_TYPE_LLDP, src=hw_addr, dst=lldp.LLDP_MAC_NEAREST_BRIDGE))
        chassis_id = lldp.ChassisID(subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
                                    chassis_id=str(datapath.id).encode('utf-8'))
        port_id = lldp.PortID(subtype=lldp.PortID.SUB_LOCALLY_ASSIGNED, port_id=str(port).encode('utf-8'))
        ttl = lldp.TTL(ttl=1)
        controller_id = lldp.SystemName(system_name=b"C0")
        end = lldp.End()
        tlvs = (chassis_id, port_id, ttl, controller_id ,end)
        pkt.add_protocol(lldp.lldp(tlvs))
        pkt.serialize()

        return pkt

    ### PACKET-IN handler ####
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        pkt = packet.Packet(data=msg.data)
        dst_dpid = datapath.id  # switch id which send the packetin
        dst_port_no = msg.match['in_port']

        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_lldp = pkt.get_protocol(lldp.lldp)
        if not pkt_ethernet:
            return
        ### LLDP handler
        if pkt_lldp:
            controller_id = pkt_lldp.tlvs[3].system_name.decode('utf-8')
            src_dpid = pkt_lldp.tlvs[0].chassis_id
            src_port_no = pkt_lldp.tlvs[1].port_id
            switch_src, src_port, switch_dst, dst_port = self.parse_lldp(src_dpid,src_port_no,dst_dpid,dst_port_no)
            if controller_id == "C0":
                self.update_graph(switch_dst, switch_src, dst_port)
            elif controller_id == "host":
                self.update_graph(switch_src, switch_dst,src_port)
                self.update_graph(switch_dst, switch_src, dst_port)
            else:
               self.logger.info("invia al controller superiore")

            #self.logger.info("packet-in %s %s" % (dst_dpid,dst_port_no,))

    # Asks weighted clique's children
    def get_clique(self):
        try:
            c1_response = requests.get('http://10.0.0.4:8080/clique')
            c2_response = requests.get('http://10.0.0.1:8080/clique')
            cliqueC1 = json_graph.node_link_graph(c1_response.json())
            cliqueC2 = json_graph.node_link_graph(c2_response.json())
            #print("C2 CLIQUE", cliqueC2.edges(data=True))
            self.C1nodes = cliqueC1.nodes()
            self.C2nodes = cliqueC2.nodes()
            list_edges_c1 = cliqueC1.edges()
            list_edges_c2 = cliqueC2.edges()
            self.net.add_edges_from(list_edges_c1)
            self.net.add_edges_from(list_edges_c2)
        except requests.exceptions.ConnectionError:
            time.sleep(10)
            self.get_clique

    # Send flow-rule to children
    def send_children(self,path):
        c1_nodes_in_path =[]
        c2_nodes_in_path = []
        src = path[len(path)-1]
        dst = path[0]
        for node in path:
            if node in self.C1nodes:
                c1_nodes_in_path.append(node)
            if node in self.C2nodes:
                c2_nodes_in_path.append(node)
        if len(c1_nodes_in_path) != 0:
            egress_node, egress_port , ingress_node, ingress_port = self.get_egress_ingress(path,c1_nodes_in_path)
            self.path_to_children(egress_node, egress_port, ingress_node, ingress_port,src,dst,"c1")
        if len(c2_nodes_in_path) !=0:
            egress_node, egress_port, ingress_node, ingress_port = self.get_egress_ingress(path, c2_nodes_in_path)
            self.path_to_children(egress_node, egress_port, ingress_node, ingress_port, src, dst,"c2")

    # Defines egress node and ingress node for each area
    def get_egress_ingress(self, path, tupla):
        egress_node = tupla[0]
        index = path.index(egress_node)
        prec = path[index - 1]
        egress_port = self.net[egress_node][prec]['port']
        # egress != ingress
        if len(tupla) > 1:
            ingress_node = tupla[1]
            index = path.index(ingress_node)
            succ = path[index + 1]
            ingress_port = self.net[ingress_node][succ]['port']
        else:
            ingress_node = egress_node
            ind = index
            succ = path[index + 1]
            ingress_port = self.net[ingress_node][succ]['port']
        return egress_node, egress_port, ingress_node, ingress_port

    # Asks children to compute path from <EgressSwitch,EgressPort,IngressSwitch,IngressPort>
    def path_to_children(self,egressSwitch,egressPort,ingressSwitch,ingressPort,src,dst,id):
        try:
            dict = {}
            dict["egressSwitch"] = egressSwitch
            dict["egressPort"] = egressPort
            dict["ingressSwitch"] = ingressSwitch
            dict["ingressPort"] = ingressPort
            dict["src"] = src
            dict["dst"] = dst
            payload = json.dumps(dict)
            if id == "c1":
                requests.post('http://10.0.0.4:8080/path',data=payload)
            if id == "c2":
                requests.post('http://10.0.0.1:8080/path', data=payload)

        except requests.exceptions.ConnectionError:
            time.sleep(10)
            self.path_to_children(egressSwitch,egressPort,ingressSwitch,ingressPort,src,dst,id)
    
    def add_flow_in_each_switch(self,path,src,dst):
        for node in path:
            # Add flow entry in my switches
            if node != src and node != dst and node not in self.C1nodes and node not in self.C2nodes:
                index = path.index(node)
                prec = path[index - 1]
                succ = path[index + 1]
                out_port = self.net[node][prec]['port']
                in_port = self.net[node][succ]['port']
                dp = self.my_switches[int(node)]
                parser = dp.ofproto_parser
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(dp, 1, match, actions)  # add flow entry in every switch in path


    def parse_lldp(self,src_dpid,src_port_no,dst_dpid,dst_port_no):
        switch_src = src_dpid.decode('utf-8')
        src_port = int(src_port_no.decode('utf-8'))
        switch_dst = str(dst_dpid)
        dst_port = dst_port_no
        return switch_src, src_port, switch_dst, dst_port

    # Update network
    def update_graph(self, switch_a, switch_b, port_a):
        self.net.add_edge(switch_a, switch_b, port=port_a)
        self.logger.info("My net %s", self.net.edges(data=True))
        



class RESTController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RESTController, self).__init__(req, link, data, **config)
        self.controller_app = data[controller_instance_name]
    
    @route('topology', url, methods=['POST'])
    def get_topology_information(self, req, **kwargs):
        controller_data = self.controller_app
        request_json = req.json_body
        id = request_json["id"]
        if "C0" in id.split("."):
            src = request_json["src"]
            src_port = request_json["src_port"]
            dst = request_json["dst"]
            dst_port = request_json["dst_port"]
            controller_data.update_graph(dst, src, dst_port)
        elif id == "host":
            src = request_json["src"]
            src_port = request_json["src_port"]
            dst = request_json["dst"]
            dst_port = request_json["dst_port"]
            controller_data.update_graph(dst, src, dst_port)
            controller_data.update_graph(src,dst, src_port)

        else:
            print("invia al controller superiore")

    # Helps children to find dst
    @route('findDst','/findDst', methods=['POST'])
    def get_destination(self, req, **kwargs):
        controller_data = self.controller_app
        request_json = req.json_body
        src = request_json["src"]
        dst = request_json["dst"]
        if src in controller_data.net and dst in controller_data.net:
            controller_data.get_clique()
            path = nx.shortest_path(controller_data.net, source=dst, target=src, method="dijkstra")
            print("PATH", path)
            controller_data.send_children(path)
            controller_data.add_flow_in_each_switch(path, src, dst)
       

class Link(object):
    def __init__(self, src, src_port, dst, dst_port):
        super(Link, self).__init__()
        self.src = src
        self.src_port = src_port
        self.dst = dst
        self.dst_port = dst_port

    def to_dict(self):
        d = {'src': self.src.to_dict(),
             'dst': self.dst.to_dict()}
        return d

    # this type is used for key value of LinkState
    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.src, self.dst))

    def __str__(self):
        return 'Link: %s port %s to %s port %s' % (self.src,self.src_port, self.dst,self.dst_port)


class Switch(object):
    def __init__(self, dp):
        super(Switch, self).__init__()

        self.dp = dp
        self.ports = []

    def add_port(self, ofpport):
        port = Port(self.dp.id, self.dp.ofproto, ofpport)
        self.ports.append(port)

    def to_dict(self):
        d = {'dpid': dpid_to_str(self.dp.id),
             'ports': [port.to_dict() for port in self.ports]}
        return d

    def __str__(self):
        msg = 'Switch<dpid=%s, ' % self.dp.id
        for port in self.ports:
            msg += str(port) + ' '

        msg += '>'
        return msg

class Port(object):
    def __init__(self, dpid, ofproto, ofpport):
        super(Port, self).__init__()

        self.dpid = dpid
        self._ofproto = ofproto

        self.port_no = ofpport.port_no
        self.hw_addr = ofpport.hw_addr

        def __str__(self):
            return 'Port<dpid=%s, port_no=%s>' % \
                   (self.dpid, self.port_no)






