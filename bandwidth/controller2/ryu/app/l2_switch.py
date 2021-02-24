from ryu.base import app_manager
from ryu.lib import hub
from eventlet.timeout import Timeout
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
url = '/topology'
BW = 20000000000

### Controller 2 ###
class L2Switch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self,*args, **kwargs):
        super(L2Switch, self).__init__(*args, **kwargs)
        self.my_switches = {}
        self.datapaths = {}
        self.to_parent={}
        self.port_stats = {}
        self.C3nodes = []
        self.C4nodes = []
        self.C4hosts = []
        self.C3hosts = []
        self.net = nx.DiGraph()
        self.edge_switches = []
        self.is_complete = False
        self.graph_children = nx.DiGraph()
        self.monitor_thread = hub.spawn(self.topology_discovery)

        wsgi = kwargs['wsgi']
        wsgi.register(RESTController,
                      {controller_instance_name: self})

    ### Switch Features Request ####
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        self.my_switches[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
    
        match = parser.OFPMatch() #Table-Miss
        match_lldp = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_LLDP,eth_dst=lldp.LLDP_MAC_NEAREST_BRIDGE)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                      ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
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
            for stat in ev.msg.body:
                port_no = str(stat.port_no)
                datapath_id = str(datapath.id)
                # 20.000.000.000/LinkSpeed in kbps IEEE 802.1D-2004
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
        controller_id = lldp.SystemName(system_name=b"C2.C0")
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
            if "C2" in controller_id.split("."):
                self.update_graph(switch_dst, switch_src, dst_port)
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
                    self.send_topology_info_to_parent(payload, key)
                    if link.dst not in self.edge_switches:
                        self.edge_switches.append(link.dst)
                    #print("EDGES",self.edge_switches)
                    
        ### ICMP handler
        if pkt_icmp:
            print("PACKET ICMP", pkt_icmp)
            dst = pkt_ethernet.dst
            src = pkt_ethernet.src
            if src in self.net and dst in self.net:
                if self.is_complete == False:
                    self.get_clique()
                path = nx.shortest_path(self.net, source=dst, target=src, method="dijkstra",weight="weight")
                print("Shortest path", path)
                path2 = nx.shortest_path(self.net, source=dst, target=src, method="dijkstra", weight="bandwidth")
                print("Path with higher bandwidth", path2)
                self.send_children(path,src,dst)
                self.add_flow_in_each_switch(path, src, dst)
            if src in self.net and dst not in self.net:
                # Ask to parent
                self.find_destination(src, dst)
            #self.logger.info("packet-in %s %s" % (dst_dpid,dst_port_no,))

    # It calculates the distance of a host from the edge switches and sends it to the parent
    def host_reachability(self, host):
        try:
            hosts = {}
            list = []
            # Computes the shortest path length between source and all other reachable nodes for a weighted graph.
            # Returns : distance – Dict keyed by node to shortest path length from source.
            if self.is_complete == False:
                self.get_clique()
            distance = nx.single_source_dijkstra_path_length(self.net, host,weight="weight")
            bandwidth = nx.single_source_dijkstra_path_length(self.net, host, weight="bandwidth")
            for edge_sw in self.edge_switches:
                host_edge_dist = distance[edge_sw]
                host_edge_bw = bandwidth[edge_sw]
                list.append((edge_sw, host_edge_dist,host_edge_bw))
            hosts[host] = list
            payload = json.dumps(hosts)
            print("Pc2 distance", payload)
            requests.post('http://10.0.0.5:8080/hostReachability', data=payload)
        except requests.exceptions.ConnectionError:
            time.sleep(10)
            self.host_reachability(host)

    # Adds flow-rule to the flow table of each switch in the path
    def add_flow_in_each_switch(self,path,src,dst,egressSwitch = None,egressPort = None,ingressSwitch = None ,ingressPort = None):
        for node in path:
            # Add flow entry in my switches
            if node != src and node != dst and node not in self.C3nodes and node not in self.C4nodes:
                index = path.index(node)
                if node == ingressSwitch:
                    prec = path[index - 1]
                    out_port = self.net[node][prec]['port']
                    in_port = ingressPort
                elif node == egressSwitch:
                    succ = path[index + 1]
                    in_port = self.net[node][succ]['port']
                    out_port = egressPort
                else:
                    prec = path[index - 1]
                    succ = path[index + 1]
                    out_port = self.net[node][prec]['port']
                    in_port = self.net[node][succ]['port']
                dp = self.my_switches[int(node)]
                parser = dp.ofproto_parser
                actions = [parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                self.add_flow(dp, 1, match, actions)  # add flow entry in every switch in path

    def find_destination(self,src,dst):
        try:
            dict = {}
            dict["src"] = src
            dict["dst"] = dst
            payload = json.dumps(dict)
            r = requests.post('http://10.0.0.5:8080/findDst', data=payload)
        except requests.exceptions.ConnectionError:
            time.sleep(10)
            self.find_destination(src,dst)

    # Send flow-rule to children
    def send_children(self,path,src,dst):
        c3_nodes_in_path =[]
        c4_nodes_in_path = []
        for node in path:
            if node in self.C3nodes or node in self.C3hosts:
                c3_nodes_in_path.append(node)
            if node in self.C4nodes or node in self.C4hosts:
                c4_nodes_in_path.append(node)
        if len(c3_nodes_in_path) != 0:
            egress_node, egress_port , ingress_node, ingress_port = self.get_egress_ingress(path,c3_nodes_in_path)
            self.path_to_children(egress_node, egress_port, ingress_node, ingress_port,src,dst,"c3")
        if len(c4_nodes_in_path) !=0:
            egress_node, egress_port, ingress_node, ingress_port = self.get_egress_ingress(path, c4_nodes_in_path)
            self.path_to_children(egress_node, egress_port, ingress_node, ingress_port, src, dst,"c4")

    # Defines egress node and ingress node for each area
    def get_egress_ingress(self,path,tupla):
        # egress != ingress
        if len(tupla) > 1:
            egress_node = tupla[0]
            ingress_node = tupla[1]
            if egress_node in self.C3hosts or egress_node in self.C4hosts:
                egress_port = 0
                index = path.index(ingress_node)
                succ = path[index + 1]
                ingress_port = self.net[ingress_node][succ]['port']
            elif ingress_node in self.C3hosts or ingress_node in self.C4hosts:
                index = path.index(egress_node)
                prec = path[index-1]
                egress_port = self.net[egress_node][prec]['port']
                ingress_port = 0
            else:
                index = path.index(egress_node)
                prec = path[index - 1]
                egress_port = self.net[egress_node][prec]['port']
                index = path.index(ingress_node)
                succ = path[index + 1]
                ingress_port = self.net[ingress_node][succ]['port']
        else:
            egress_node = tupla[0]
            index = path.index(egress_node)
            prec = path[index - 1]
            egress_port = self.net[egress_node][prec]['port']
            ingress_node = egress_node
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
            if id == "c3":
                requests.post('http://10.0.0.2:8080/path',data=payload)
            if id == "c4":
                requests.post('http://10.0.0.3:8080/path', data=payload)

        except requests.exceptions.ConnectionError:
            time.sleep(10)
            self.path_to_children(egressSwitch,egressPort,ingressSwitch,ingressPort,src,dst,id)

    # Asks weighted clique's children
    def get_clique(self):
        try:
            c3_response = requests.get('http://10.0.0.2:8080/clique')
            c4_response = requests.get('http://10.0.0.3:8080/clique')
            cliqueC3 = json_graph.node_link_graph(c3_response.json())
            cliqueC4 = json_graph.node_link_graph(c4_response.json())
            for node in cliqueC3.nodes:
                self.C3nodes.append(node)
            for node in cliqueC4.nodes:
                self.C4nodes.append(node)
            list_edges_c3 = cliqueC3.edges(data=True)
            list_edges_c4 = cliqueC4.edges(data=True)
            self.net.add_edges_from(list_edges_c3)
            self.net.add_edges_from(list_edges_c4)
            self.is_complete = True
        except requests.exceptions.ConnectionError:
            time.sleep(10)
            self.get_clique


    def send_topology_info_to_parent(self, payload,key):
        try:
            r = requests.post('http://10.0.0.5:8080/topology', data=payload)
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
    def update_graph(self, switch_a,switch_b, port_a):
        self.net.add_edge(switch_a, switch_b, port=port_a)
        self.logger.info("My net %s", self.net.edges(data=True))




class RESTController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RESTController, self).__init__(req, link, data, **config)
        self.controller_app = data[controller_instance_name]
        self.net_clique = nx.DiGraph()

    @route('topology', url, methods=['POST'])
    def get_topology_information(self, req, **kwargs):
        controller_data = self.controller_app
        request_json = req.json_body
        id =  request_json["id"]
        bw = request_json["bw"]

        if "C2" in id.split("."):
            src = request_json["src"]
            src_port = request_json["src_port"]
            dst = request_json["dst"]
            dst_port = request_json["dst_port"]
            controller_data.update_graph(dst,src, dst_port)
            controller_data.add_label_bw(dst, src, bw)
        elif id == "host":
            src = request_json["src"]
            src_port = request_json["src_port"]
            dst = request_json["dst"]
            dst_port = request_json["dst_port"]
            controller_data.update_graph(dst, src, dst_port)
            controller_data.update_graph(src, dst, src_port)
            controller_data.add_label_bw(dst, src, bw)
            controller_data.add_label_bw(src, dst, bw)
            
            # if host is attached to an edge switch
            if dst in controller_data.edge_switches:
                body = json.dumps(request_json)
                controller_data.send_topology_info_to_parent(body, src)
            else:
                controller_data.host_reachability(src)
        else:
            dst = request_json["dst"]
            if dst not in controller_data.edge_switches:
                controller_data.edge_switches.append(dst)
            print("EDGES",controller_data.edge_switches)
            body=json.dumps(request_json)
            requests.post('http://10.0.0.5:8080/topology', data=body)

    # Provides clique to parent
    @route('clique', '/clique', methods=['GET'])
    def get_clique(self, req, **kwargs):
        controller_data = self.controller_app
        if controller_data.is_complete == False:
            controller_data.get_clique()
        clique_weight = dict(nx.all_pairs_dijkstra_path_length(controller_data.net, weight="weight"))
        clique_bandwidth = dict(nx.all_pairs_dijkstra_path_length(controller_data.net, weight="bandwidth"))
        self.clique_to_send(clique_weight, "weight")
        self.clique_to_send(clique_bandwidth, "bandwidth")
        jg = json_graph.node_link_data(self.net_clique)
        body= json.dumps(jg)

        return Response(content_type='application/json', text=body)

    def clique_to_send(self,clique,label,**kwargs):
        controller_data = self.controller_app
        for key in clique:
            if key in controller_data.edge_switches:
                for node in clique[key]:
                    if node in controller_data.edge_switches  and node != key:
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
        c3_nodes_in_path = []
        c4_nodes_in_path = []
        my_nodes = []
        # print("INGRESS",ingressSwitch)
        # print("EGRESS", egressSwitch)

        # IF doesn't have the complete clique graph asks children
        if controller_data.is_complete == False:
            controller_data.get_clique()
        path = nx.shortest_path(controller_data.net, source=str(egressSwitch), target=str(ingressSwitch),
                                method="dijkstra",weight="weight")
        print("PATH",path)
        path2 = nx.shortest_path(controller_data.net, source=str(egressSwitch), target=str(ingressSwitch),
                                 method="dijkstra", weight="bandwidth")
        print("PATH2", path2)

        # Path is single switch
        if len(path) == 1:
            node = egressSwitch
            in_port = ingressPort
            out_port = egressPort
            if node in controller_data.C3nodes:
                controller_data.path_to_children(node, out_port,node, in_port, src, dst,"c3")
            elif node in controller_data.C4nodes:
                controller_data.path_to_children(node, out_port, node, in_port, src, dst, "c4")
            else:
                self.send_flow(node, out_port, in_port, dst, src)
        else:
            # egress node
            for node in path:
                if node in controller_data.C3nodes or node in controller_data.C3hosts:
                    c3_nodes_in_path.append(node)
                elif node in controller_data.C4nodes or node in controller_data.C4hosts:
                    c4_nodes_in_path.append(node)
                else:
                    if node != src and node != dst:
                        my_nodes.append(node)
            if len(c3_nodes_in_path) != 0:
                # if already has egressSwitch and ingressSwitch sends to the child else calculates them and sends
                if ingressSwitch in  c3_nodes_in_path and egressSwitch in c3_nodes_in_path:
                    controller_data.path_to_children(egressSwitch, egressPort, ingressSwitch , ingressPort, src, dst, "c3")
                if ingressSwitch in c3_nodes_in_path:
                    prec,out_port = self.get_egress(path,ingressSwitch)
                    in_port = ingressPort
                    controller_data.path_to_children(prec, out_port, ingressSwitch, in_port, src, dst, "c3")
                elif egressSwitch in c3_nodes_in_path:
                    succ,in_port = self.get_ingress(path,egressSwitch)
                    out_port = egressPort
                    controller_data.path_to_children(egressSwitch, out_port, succ, in_port, src, dst, "c3")
                else:
                    # calculates egressSwitch and ingressSwitch for C3
                    egress_node, egress_port, ingress_node, ingress_port = controller_data.get_egress_ingress(path,c3_nodes_in_path)
                    controller_data.path_to_children(egress_node, egress_port, ingress_node, ingress_port, src, dst, "c3")
            if len(c4_nodes_in_path) != 0:
                # if already has egressSwitch and ingressSwitch sends to the child else calculates them and sends
                if ingressSwitch in  c4_nodes_in_path and egressSwitch in c4_nodes_in_path:
                    controller_data.path_to_children(egressSwitch, egressPort, ingressSwitch , ingressPort, src, dst, "c4")
                elif ingressSwitch in c4_nodes_in_path:
                    prec, out_port = self.get_egress(path, ingressSwitch)
                    in_port = ingressPort
                    controller_data.path_to_children(prec, out_port, ingressSwitch, in_port, src, dst, "c4")
                elif egressSwitch in c4_nodes_in_path:
                    succ, in_port = self.get_ingress(path, egressSwitch)
                    out_port = egressPort
                    controller_data.path_to_children(egressSwitch, out_port, succ, in_port, src, dst, "c4")
                else:
                    # calculates egressSwitch and ingressSwitch for C4
                    egress_node, egress_port, ingress_node, ingress_port = controller_data.get_egress_ingress(path,c4_nodes_in_path)
                    controller_data.path_to_children(egress_node, egress_port, ingress_node, ingress_port, src, dst,"c4")
            if len(my_nodes) != 0:
                controller_data.add_flow_in_each_switch(path,src, dst,egressSwitch,egressPort,ingressSwitch,ingressPort)


    def get_egress(self,path,ingressSwitch, **kwargs):
        controller_data = self.controller_app
        index = path.index(ingressSwitch)
        prec = path[index-1]
        prev_prec = path[index-2]
        out_port = controller_data.net[prec][prev_prec]['port']
        return prec,out_port

    def get_ingress(self,path,egressSwitch, **kwargs):
        controller_data = self.controller_app
        index = path.index(egressSwitch)
        succ = path[index + 1]
        next_succ = path[index + 2]
        in_port = controller_data.net[succ][next_succ]['port']
        return succ,in_port

    def send_flow(self,node,out_port,in_port,dst,src,**kwargs):
        controller_data = self.controller_app
        dp = controller_data.my_switches[int(node)]
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
        controller_data.add_flow(dp, 1, match, actions)

    # Helps children to find dst
    @route('findDst', '/findDst', methods=['POST'])
    def get_destination(self, req, **kwargs):
        controller_data = self.controller_app
        request_json = req.json_body
        src = request_json["src"]
        dst = request_json["dst"]
        if src in controller_data.net and dst in controller_data.net:
            if controller_data.is_complete == False:
                controller_data.get_clique()
            path = nx.shortest_path(controller_data.net, source=dst, target=src, method="dijkstra", weight="weight")
            print("Shortest path", path)
            path2 = nx.shortest_path(controller_data.net, source=dst, target=src, method="dijkstra", weight="bandwidth")
            print("Path with higher bandwidth", path2)
            controller_data.send_children(path,src,dst)
            controller_data.add_flow_in_each_switch(path, src, dst)
        else:
            # Ask to parent
            controller_data.find_destination(src, dst)

    # Collects hosts within an area and creates imaginary links to connect them to the edges
    @route('hostReachability', '/hostReachability', methods=['POST'])
    def host_reachability(self, req, **kwargs):
            controller_data = self.controller_app
            request_json = req.json_body
            for key, value in request_json.items():
                for el in value:
                    controller_data.net.add_edge(key,el[0],weight=el[1])
                    controller_data.net.add_edge(el[0],key,weight=el[1])
                    controller_data.add_label_bw(key,el[0],el[2])
                    controller_data.add_label_bw(el[0],key, el[2])
            controller_data.host_reachability(key)
            if req.client_addr == '10.0.0.3':
                controller_data.C4hosts.append(key)
            if req.client_addr == '10.0.0.2':
                controller_data.C3hosts.append(key)
            #print("REQ PRINT",value)



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
            msg += str(port.port_no) + ' '

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
                   (self.dpid.decode("utf-8"), self.port_no.decode("utf-8"))






