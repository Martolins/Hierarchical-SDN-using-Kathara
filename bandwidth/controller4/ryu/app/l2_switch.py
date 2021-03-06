from ryu.base import app_manager
from ryu.lib import hub
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types,lldp,packet,ethernet,icmp
import subprocess
import networkx as nx
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
import json
from webob import Response
import requests
import time
from networkx.readwrite import json_graph

controller_instance_name = 'controller_api_app'
url = '/clique'
BW = 20000000000


### Controller 4 ###
class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self,*args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.my_switches={}
        self.datapaths = {}
        self.to_parent= {}
        self.port_stats = {}
        self.edge_switches = []
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
        match = parser.OFPMatch() # Table-Miss
        match_lldp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP,eth_dst=lldp.LLDP_MAC_NEAREST_BRIDGE)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                      ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath,0, match, actions)
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
        self.my_switches[datapath.id] = datapath
        
        ofp_parser = datapath.ofproto_parser
        switch = Switch(datapath)
        for stat in ev.msg.body:
            port_no = str(stat.port_no)
            datapath_id = str(datapath.id)
            # 20.000.000.000/LinkSpeed in kbps IEEE2004
            if stat.curr_speed != 0:
                bandwidth = BW / stat.curr_speed
                # dict <datapath_id,port> -> bandwidth
                if self.port_stats.get(datapath_id) is None:
                    self.port_stats[datapath_id] = {}
                self.port_stats[datapath_id][port_no] = bandwidth
            port = Port(datapath.id, ofproto, stat)
            switch.add_port(port)
        self.datapaths[datapath.id] = switch
        self.logger.info('OFPPortDescStatsReply received: %s' % (str(switch)))

    ### Update graph with bandwidth label
    def add_label_bw(self, datapath_A, datapath_B, bandwidth):
        # find the right link
        if self.net.has_edge(datapath_A, datapath_B):
            self.net[datapath_A][datapath_B]['bandwidth'] = bandwidth

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
        controller_id = lldp.SystemName(system_name=b"C4.C2.C0")
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
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        if not pkt_ethernet:
            return
        ### LLDP handler
        if pkt_lldp:
            controller_id = pkt_lldp.tlvs[3].system_name.decode('utf-8')
            src_dpid = pkt_lldp.tlvs[0].chassis_id
            src_port_no = pkt_lldp.tlvs[1].port_id
            switch_src, src_port, switch_dst, dst_port = self.parse_lldp(src_dpid,src_port_no,dst_dpid,dst_port_no)
            if self.port_stats[switch_dst][str(dst_port)] != None:
                bw = self.port_stats[switch_dst][str(dst_port)]
            if "C4" in controller_id.split("."):
                self.update_graph(switch_dst,switch_src, dst_port)
                self.add_label_bw(switch_dst, switch_src, bw)
            elif controller_id == "host":
                link = Link(switch_src,src_port, switch_dst, dst_port)
                self.update_graph(link.src, link.dst, link.src_port)
                self.update_graph(link.dst, link.src, link.dst_port)
                self.add_label_bw(link.dst, link.src, bw)
                self.add_label_bw(link.src, link.dst, bw)
                if switch_dst in self.edge_switches:
                    if self.to_parent.get(link.src) is None:
                        self.to_parent[link.src] = 0
                    if self.to_parent[link.src] == 0:
                        key = link.src
                        dict = link.__dict__
                        dict["id"] = controller_id
                        dict["bw"] = bw
                        payload = json.dumps(dict)
                        self.send_topology_info_to_parent(payload, key)
                else:
                    self.host_reachability(switch_src)
            else:
                link = Link(switch_src, src_port, switch_dst, dst_port)
                if self.to_parent.get(link.src) is None:
                    self.to_parent[link.src] = 0
                if self.to_parent[link.src] == 0:
                    key = link.src
                    dict = link.__dict__
                    dict["id"] = controller_id
                    dict["bw"] = bw
                    payload = json.dumps(dict)
                    self.send_topology_info_to_parent(payload,key)
                    if link.dst not in self.edge_switches:
                        self.edge_switches.append(link.dst) #collect switch edges for clique
                    print("EDGE",self.edge_switches)
        ### ICMP handler
        if pkt_icmp:
            print("PACKET ICMP", pkt_icmp)
            dst = pkt_ethernet.dst
            src = pkt_ethernet.src
            if src in self.net and dst in self.net:
                # Computes the shortest path from source to target using Dijkstra
                path = nx.shortest_path(self.net, source=dst, target=src, method="dijkstra", weight="weight")
                print("Shortest path", path)
                path2 = nx.shortest_path(self.net, source=dst, target=src, method="dijkstra", weight="bandwidth")
                print("Path with higher bandwidth", path2)
                self.add_flow_in_each_switch(path,src,dst)
            if src in self.net and dst not in self.net:
                # Ask to parent
                self.find_destination(src, dst)

    # It calculates the distance of a host from the edge switches and sends it to the parent
    def host_reachability(self,host):
        try:
            hosts = {}
            list = []
            # Compute the shortest path length between source and all other reachable nodes for a weighted graph.
            # Returns : length – Dict keyed by node to shortest path length from source.
            distance = nx.single_source_dijkstra_path_length(self.net,host,weight="weight")
            bandwidth = nx.single_source_dijkstra_path_length(self.net,host,weight="bandwidth")
            for edge_sw in self.edge_switches:
                host_edge_dist = distance[edge_sw]
                host_edge_bw = bandwidth[edge_sw]
                list.append((edge_sw,host_edge_dist,host_edge_bw))
            hosts[host] = list
            payload = json.dumps(hosts)
            print("Pc2 distance", payload)
            requests.post('http://10.0.0.1:8080/hostReachability', data=payload)
        except requests.exceptions.ConnectionError:
                time.sleep(10)
                self.host_reachability(host)


    # Adds flow-rule to the flow table of each switch in the path
    def add_flow_in_each_switch(self,path,src,dst):
        for node in path:
            if node != src and node != dst:
                index = path.index(node)
                prec = path[index - 1]
                succ = path[index + 1]
                in_port = self.net[node][succ]['port']
                out_port = self.net[node][prec]['port']
                dp = self.my_switches[int(node)]
                parser = dp.ofproto_parser
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(dp, 1, match, actions)

    def find_destination(self, src, dst):
        try:
            dict = {}
            dict["src"] = src
            dict["dst"] = dst
            payload = json.dumps(dict)
            r = requests.post('http://10.0.0.1:8080/findDst', data=payload)
        except requests.exceptions.ConnectionError:
                time.sleep(10)
                self.find_destination(src, dst)

            #self.logger.info("packet-in %s %s" % (dst_dpid,dst_port_no,))

    def send_topology_info_to_parent(self,payload,key):
        try:
            r = requests.post('http://10.0.0.1:8080/topology', data=payload)
            self.to_parent[key] = 1
        except requests.exceptions.ConnectionError:
            time.sleep(10)
            self.to_parent[key] = 0
            self.send_topology_info_to_parent(payload,key)



    def parse_lldp(self,src_dpid,src_port_no,dst_dpid,dst_port_no):
        switch_src = src_dpid.decode('utf-8')
        src_port = int(src_port_no.decode('utf-8'))
        switch_dst = str(dst_dpid)
        dst_port = dst_port_no
        return switch_src, src_port, switch_dst, dst_port

    # Updates network graph
    def update_graph(self,switch_a, switch_b, port_a):
        self.net.add_edge(switch_a,switch_b, port=port_a)
        self.logger.info("My net %s", self.net.edges(data=True))


class RESTController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RESTController, self).__init__(req, link, data, **config)
        self.controller_app = data[controller_instance_name]
        self.net_clique = nx.DiGraph()

    # Provides weighted clique to parent
    @route('clique',url, methods=['GET'])
    def get_clique(self, req, **kwargs):
        controller_data = self.controller_app
        clique_weight = dict(nx.all_pairs_dijkstra_path_length(controller_data.net, weight="weight"))
        clique_bw = dict(nx.all_pairs_dijkstra_path_length(controller_data.net, weight="bandwidth"))
        self.clique_to_send(clique_weight, "weight")
        self.clique_to_send(clique_bw, "bandwidth")
        jg = json_graph.node_link_data(self.net_clique)
        body = json.dumps(jg)
        return Response(content_type='application/json', text=body)

    def clique_to_send(self, clique, label, **kwargs):
        controller_data = self.controller_app
        for key in clique:
            if key in controller_data.edge_switches:
                for node in clique[key]:
                    if node in controller_data.edge_switches and node != key:
                        if label == "weight":
                            self.net_clique.add_edge(key, node, weight=clique[key][node])
                        else:
                            self.net_clique.add_edge(key, node, bandwidth=clique[key][node])

    @route('path', '/path', methods=['POST'])
    def find_shortest_path(self, req, **kwargs):
        controller_data = self.controller_app
        request_json = req.json_body
        egressSwitch = request_json["egressSwitch"]
        egressPort = request_json["egressPort"]
        ingressSwitch = request_json["ingressSwitch"]
        ingressPort = request_json["ingressPort"]
        src = request_json["src"]
        dst = request_json["dst"]
        # print("INGRESS",ingressSwitch)
        # print("EGRESS", egressSwitch)
        path = nx.shortest_path(controller_data.net, source=str(egressSwitch), target=str(ingressSwitch),
                                method="dijkstra", weight="weight")
        print("Shortest path", path)
        path2 = nx.shortest_path(controller_data.net, source=str(egressSwitch), target=str(ingressSwitch),
                                 method="dijkstra", weight="bandwidth")
        print("Path with higher bandwidth", path2)
        # Single switch path
        if len(path) == 1:
            node = egressSwitch
            in_port = ingressPort
            out_port = egressPort
            self.send_flow(node,out_port,in_port,dst,src)
        else:
            for node in path:
                index = path.index(node)
                if node == dst or node == src:
                    continue
                elif node == egressSwitch:
                    succ = path[index + 1]
                    in_port = controller_data.net[node][succ]['port']
                    out_port = egressPort
                elif node == ingressSwitch:
                    prec = path[index - 1]
                    out_port = controller_data.net[node][prec]['port']
                    in_port = ingressPort
                else:
                    prec = path[index - 1]
                    succ = path[index + 1]
                    in_port = controller_data.net[node][succ]['port']
                    out_port = controller_data.net[node][prec]['port']
                self.send_flow(node,out_port,in_port,dst,src)
            

    def send_flow(self,node,out_port,in_port,dst,src,**kwargs):
        controller_data = self.controller_app
        dp = controller_data.my_switches[int(node)]
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        controller_data.add_flow(dp, 1, match, actions)

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





    
 
