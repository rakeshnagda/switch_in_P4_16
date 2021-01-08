/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions &&
limitations under the License.
*/
#include<core.p4>
#include<v1model.p4>



#include "includes/headers.p4"
#include "includes/metadata.p4"
#include "includes/header_collection.p4"
#include "includes/p4features.h"
#include "includes/drop_reason_codes.h"
#include "includes/cpu_reason_codes.h"
#include "includes/p4_table_sizes.h"
#include "includes/parser.p4"
#include "includes/defines.p4"
#include "includes/intrinsic.p4"

/* METADATA */



#include "switch_src/switch_config.p4"
#ifdef OPENFLOW_ENABLE
#include "switch_src/openflow.p4"
#endif /* OPENFLOW_ENABLE */
#include "switch_src/port.p4"
#include "switch_src/l2.p4"
#include "switch_src/l3.p4"
#include "switch_src/ipv4.p4"
#include "switch_src/ipv6.p4"
#include "switch_src/tunnel.p4"
#include "switch_src/acl.p4"
#include "switch_src/nat.p4"
#include "switch_src/multicast.p4"
#include "switch_src/nexthop.p4"
#include "switch_src/rewrite.p4"
#include "switch_src/security.p4"
#include "switch_src/fabric.p4"
#include "switch_src/egress_filter.p4"
#include "switch_src/mirror.p4"
#include "switch_src/int_transit.p4"
#include "switch_src/hashes.p4"
#include "switch_src/meter.p4"
#include "switch_src/sflow.p4"
#include "switch_src/qos.p4"


action nop() {
}

action on_miss() {
}

// control Ingress<H, M>(inout H hdr,
//                       inout M meta,
//                       inout standard_metadata_t standard_metadata);

control ingress  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    /* input mapping - derive an ifindex */
    process_ingress_port_mapping() ingress_port_mapping;

    /* process outer packet headers */
    process_validate_outer_header() validate_outer_header;

    /* read && apply system configuration parametes */
    process_global_params() global_params;

    /* derive bd && its properties  */
    process_port_vlan_mapping() port_vlan_mapping;

    /* spanning tree state checks */
    process_spanning_tree() spanning_tree;

    /* ingress qos map */
    process_ingress_qos_map() ingress_qos_map;

    /* IPSG */
    process_ip_sourceguard() ip_sourceguard;

    /* INT src,sink determination */
    process_int_endpoint() int_endpoint;

    /* ingress sflow determination */
    process_ingress_sflow() ingress_sflow;

    /* tunnel termination processing */
    process_tunnel() tunnel;

    /* storm control */
    process_storm_control() storm_control;

    /* validate packet */
    process_validate_packet() validate_packet;

    /* perform ingress l4 port range */
    process_ingress_l4port() ingress_l4port;

    /* l2 lookups */
    process_mac() mac;

    /* port && vlan ACL */
    process_mac_acl() mac_acl;
    process_ip_acl() ip_acl;

    process_multicast() multicast;

    /* router ACL/PBR */
    process_ipv4_racl() ipv4_racl;
    process_ipv4_urpf() ipv4_urpf;
    process_ipv4_fib() ipv4_fib;

    /* router ACL/PBR */
    process_ipv6_racl() ipv6_racl;
    process_ipv6_urpf() ipv6_urpf;
    process_ipv6_fib() ipv6_fib;

    process_urpf_bd() urpf_bd;

    /* ingress NAT */
    process_ingress_nat() ingress_nat;

    process_meter_index() meter_index;

    /* compute hashes based on packet type  */
    process_hashes() hashes;

    process_meter_action() meter_action;

    /* update statistics */
    process_ingress_bd_stats() ingress_bd_stats;
    process_ingress_acl_stats() ingress_acl_stats;
    process_storm_control_stats() storm_control_stats;

    /* decide final forwarding choice */
    process_fwd_results() fwd_results;

    /* ecmp/nexthop lookup */
    process_nexthop() nexthop;

    // TODO
    // process_ofpat_ingress() ofpat_ingress;

    /* resolve multicast index for flooding */
    process_multicast_flooding() multicast_flooding;

    /* resolve final egress port for unicast traffic */
    process_lag() lag;


    /* generate learn notify digest if permitted */
    process_mac_learning() mac_learning;


    /* resolve fabric port to destination device */
    process_fabric_lag() fabric_lag;

    /* set queue id for tm */
    process_traffic_class() traffic_class;


    /* system acls */
    process_system_acl() system_acl;


    /*****************************************************************************/
    /* Router MAC lookup                                                         */
    /*****************************************************************************/
    action rmac_hit() {
        meta.l3_metadata.rmac_hit= TRUE;
    }

    action rmac_miss() {
        meta.l3_metadata.rmac_hit= FALSE;
    }

    table rmac {
        key = {
            meta.l3_metadata.rmac_group : exact;
            meta.l2_metadata.lkp_mac_da : exact;
        }
        actions =  {
            rmac_hit;
            rmac_miss;
        }
        size = ROUTER_MAC_TABLE_SIZE;
    }

    apply {
        ingress_port_mapping.apply(hdr, meta, standard_metadata);
        validate_outer_header.apply(hdr, meta, standard_metadata);
        global_params.apply(hdr, meta, standard_metadata);
        port_vlan_mapping.apply(hdr, meta, standard_metadata);
        spanning_tree.apply(hdr, meta, standard_metadata);
        ingress_qos_map.apply(hdr, meta, standard_metadata);
        ip_sourceguard.apply(hdr, meta, standard_metadata);
        int_endpoint.apply(hdr, meta, standard_metadata);
        ingress_sflow.apply(hdr, meta, standard_metadata);
        tunnel.apply(hdr, meta, standard_metadata);
        storm_control.apply(hdr, meta, standard_metadata);

        if (meta.ingress_metadata.port_type != PORT_TYPE_FABRIC) {

            if ( !(hdr.mpls[0].isValid() && (meta.l3_metadata.fib_hit == TRUE))) {
                
                validate_packet.apply(hdr, meta, standard_metadata);
                ingress_l4port.apply(hdr, meta, standard_metadata);
                mac.apply(hdr, meta, standard_metadata);

                
                if (meta.l3_metadata.lkp_ip_type == IPTYPE_NONE) {
                    mac_acl.apply(hdr, meta, standard_metadata);
                } 
                else {
                    ip_acl.apply(hdr, meta, standard_metadata);
                }

                switch (rmac.apply().action_run){
                    rmac_miss: {
                        multicast.apply(hdr, meta, standard_metadata);
                    }
                    default: {
                        if (DO_LOOKUP(L3)) {
                            if ((meta.l3_metadata.lkp_ip_type == IPTYPE_IPV4) &&
                                (meta.ipv4_metadata.ipv4_unicast_enabled == TRUE)) {
                                ipv4_racl.apply(hdr, meta, standard_metadata);
                                ipv4_urpf.apply(hdr, meta, standard_metadata);
                                ipv4_fib.apply(hdr, meta, standard_metadata);

                            } 
                            else {
                                if ((meta.l3_metadata.lkp_ip_type == IPTYPE_IPV6) &&
                                    (meta.ipv6_metadata.ipv6_unicast_enabled == TRUE)) {
                                    ipv6_racl.apply(hdr, meta, standard_metadata);
                                    ipv6_urpf.apply(hdr, meta, standard_metadata);
                                    ipv6_fib.apply(hdr, meta, standard_metadata);
                                }
                            }
                            urpf_bd.apply(hdr, meta, standard_metadata);
                        }
                    }
                }

                ingress_nat.apply(hdr, meta, standard_metadata);
            }
        }

        meter_index.apply(hdr, meta, standard_metadata);
        hashes.apply(hdr, meta, standard_metadata);
        meter_action.apply(hdr, meta, standard_metadata);

        if (meta.ingress_metadata.port_type != PORT_TYPE_FABRIC) {
            ingress_bd_stats.apply(hdr, meta, standard_metadata);
            ingress_acl_stats.apply(hdr, meta, standard_metadata);
            storm_control_stats.apply(hdr, meta, standard_metadata);
            fwd_results.apply(hdr, meta, standard_metadata);
            nexthop.apply(hdr, meta, standard_metadata);


            if (meta.ingress_metadata.egress_ifindex == IFINDEX_FLOOD) {
                /* resolve multicast index for flooding */
                multicast_flooding.apply(hdr, meta, standard_metadata);
            } 
            else {
                /* resolve final egress port for unicast traffic */
                lag.apply(hdr, meta, standard_metadata);
            }

            /* generate learn notify digest if permitted */
            mac_learning.apply(hdr, meta, standard_metadata);
        }

        /* resolve fabric port to destination device */
        fabric_lag.apply(hdr, meta, standard_metadata);

        /* set queue id for tm */
        traffic_class.apply(hdr, meta, standard_metadata);

        if (meta.ingress_metadata.port_type != PORT_TYPE_FABRIC) {
            /* system acls */
            system_acl.apply(hdr, meta, standard_metadata);
        }
    }
}


    
    
    
// control Egress<H, M>(inout H hdr,
//                      inout M meta,
//                      inout standard_metadata_t standard_metadata);    


control egress  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 

    // TODO
    // process_ofpat_egress() ofpat_egress;

    /* set the nexthop for the mirror id */
    /* for sflow i2e mirror pkt, result will set required sflow info */
    process_mirroring() mirroring;

    /* multi-destination replication */
    process_replication() replication;

    /* strip vlan header */
    process_vlan_decap() vlan_decap;

    /* perform tunnel decap */
    process_tunnel_decap() tunnel_decap;

    /* apply nexthop_index based packet rewrites */
    process_rewrite() rewrite;

    /* egress bd properties */
    process_egress_bd() egress_bd;

    /* egress qos map */
    process_egress_qos_map() egress_qos_map;

    /* rewrite source/destination mac if needed */
    process_mac_rewrite() mac_rewrite;

    /* egress mtu checks */
    process_mtu() mtu;

    /* INT processing */
    process_int_insertion() int_insertion;

    /* egress nat processing */
    process_egress_nat() egress_nat;

    /* update egress bd stats */
    process_egress_bd_stats() egress_bd_stats;

    /* perform egress l4 port range */
    process_egress_l4port() egress_l4port;

    /* perform tunnel encap */
    process_tunnel_encap() tunnel_encap;

    /* egress acl */
    process_egress_acl() egress_acl;

    /* update underlay header based on INT information inserted */
    process_int_outer_encap() int_outer_encap;

    /* egress vlan translation */
    process_vlan_xlate() vlan_xlate;

    /* egress filter */
    process_egress_filter() egress_filter;

    /* apply egress acl */
    process_egress_system_acl() egress_system_acl;

    /*****************************************************************************/
    /* Egress port lookup                                                        */
    /*****************************************************************************/
    action egress_port_type_normal(bit<IFINDEX_BIT_WIDTH> ifindex, bit<5> qos_group, bit<16> if_label) {
        meta.egress_metadata.port_type = PORT_TYPE_NORMAL;
        meta.egress_metadata.ifindex = ifindex;
        meta.qos_metadata.egress_qos_group = qos_group;
        meta.acl_metadata.egress_if_label = if_label;
    }

    action egress_port_type_fabric(bit<IFINDEX_BIT_WIDTH> ifindex) {
        meta.egress_metadata.port_type = PORT_TYPE_FABRIC;
        meta.egress_metadata.ifindex = ifindex;
        meta.tunnel_metadata.egress_tunnel_type = EGRESS_TUNNEL_TYPE_FABRIC;
    }

    action egress_port_type_cpu(bit<IFINDEX_BIT_WIDTH> ifindex) {
        meta.egress_metadata.port_type = PORT_TYPE_CPU;
        meta.egress_metadata.ifindex = ifindex;
        meta.tunnel_metadata.egress_tunnel_type = EGRESS_TUNNEL_TYPE_CPU;
    }

    table egress_port_mapping {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            egress_port_type_normal;
            egress_port_type_fabric;
            egress_port_type_cpu;
        }
        size = PORTMAP_TABLE_SIZE;
    }

    apply{
        /* check for -ve mirrored pkt */
        if ((meta.intrinsic_metadata.deflection_flag == FALSE) &&
            (meta.egress_metadata.bypass == FALSE)) {

            /* check if pkt is mirrored */
            if (pkt_is_mirrored) {
                /* set the nexthop for the mirror id */
                /* for sflow i2e mirror pkt, result will set required sflow info */
                mirroring.apply(hdr, meta, standard_metadata);
            } else {

                /* multi-destination replication */
                replication.apply(hdr, meta, standard_metadata);
            }

            /* determine egress port properties */
            switch (egress_port_mapping.apply().action_run){
                egress_port_type_normal: {
                    if (pkt_is_not_mirrored) {
                        /* strip vlan header */
                        vlan_decap.apply(hdr, meta, standard_metadata);
                    }

                    /* perform tunnel decap */
                    tunnel_decap.apply(hdr, meta, standard_metadata);

                    /* apply nexthop_index based packet rewrites */
                    rewrite.apply(hdr, meta, standard_metadata);

                    /* egress bd properties */
                    egress_bd.apply(hdr, meta, standard_metadata);

                    /* egress qos map */
                    egress_qos_map.apply(hdr, meta, standard_metadata);

                    /* rewrite source/destination mac if needed */
                    mac_rewrite.apply(hdr, meta, standard_metadata);

                    /* egress mtu checks */
                    mtu.apply(hdr, meta, standard_metadata);

                    /* INT processing */
                    int_insertion.apply(hdr, meta, standard_metadata);

                    /* egress nat processing */
                    egress_nat.apply(hdr, meta, standard_metadata);

                    /* update egress bd stats */
                    egress_bd_stats.apply(hdr, meta, standard_metadata);
                }
            }

            /* perform egress l4 port range */
            egress_l4port.apply(hdr, meta, standard_metadata);

            /* perform tunnel encap */
            tunnel_encap.apply(hdr, meta, standard_metadata);

            if (meta.egress_metadata.port_type == PORT_TYPE_NORMAL) {
                /* egress acl */
                egress_acl.apply(hdr, meta, standard_metadata);
            }

            /* update underlay header based on INT information inserted */
            int_outer_encap.apply(hdr, meta, standard_metadata);

            if (meta.egress_metadata.port_type == PORT_TYPE_NORMAL) {
                /* egress vlan translation */
                vlan_xlate.apply(hdr, meta, standard_metadata);
            }

            /* egress filter */
            egress_filter.apply(hdr, meta, standard_metadata);
        }

        if (meta.egress_metadata.port_type == PORT_TYPE_NORMAL) {
            /* apply egress acl */
            egress_system_acl.apply(hdr, meta, standard_metadata);
        }
    }
}

// control Deparser<H>(packet_out b, in H hdr);
control SwitchDeparser(packet_out pkt, in headers_t hdr) {
    //  emit(hdr): serializes header if it is valid
    apply{
        // pkt.emit(hdr.ethernet);
        // pkt.emit(hdr.ipv4);
        // pkt.emit(hdr.ipv6);


        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.llc_header);
        pkt.emit(hdr.snap_header);
        pkt.emit(hdr.roce);
        pkt.emit(hdr.fcoe);
        pkt.emit(hdr.vlan_tag_);
        pkt.emit(hdr.mpls);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.icmp);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.roce_v2);
        pkt.emit(hdr.int_header);
        pkt.emit(hdr.int_switch_id_header);
        pkt.emit(hdr.int_ingress_port_id_header);
        pkt.emit(hdr.int_hop_latency_header);
        pkt.emit(hdr.int_q_occupancy_header);
        pkt.emit(hdr.int_ingress_tstamp_header);
        pkt.emit(hdr.int_egress_port_id_header);
        pkt.emit(hdr.int_q_congestion_header);
        pkt.emit(hdr.int_egress_port_tx_utilization_header);
        pkt.emit(hdr.vxlan_gpe_int_header);
        pkt.emit(hdr.int_val);
        pkt.emit(hdr.sctp);
        pkt.emit(hdr.gre);
        pkt.emit(hdr.nvgre);
        pkt.emit(hdr.inner_ethernet);
        pkt.emit(hdr.inner_ipv4);
        pkt.emit(hdr.inner_ipv6);
        pkt.emit(hdr.outer_udp);
        pkt.emit(hdr.erspan_t3_header);
        pkt.emit(hdr.eompls);
        pkt.emit(hdr.vxlan);
        pkt.emit(hdr.vxlan_gpe);
        pkt.emit(hdr.genv);
        pkt.emit(hdr.nsh);
        pkt.emit(hdr.nsh_context);
        pkt.emit(hdr.lisp);
        pkt.emit(hdr.inner_icmp);
        pkt.emit(hdr.inner_tcp);
        pkt.emit(hdr.inner_udp);
        pkt.emit(hdr.inner_sctp);
        pkt.emit(hdr.trill);
        pkt.emit(hdr.vntag);
        pkt.emit(hdr.bfd);
        pkt.emit(hdr.sflow);
        pkt.emit(hdr.sflow_sample);
        pkt.emit(hdr.sflow_raw_hdr_record);
        pkt.emit(hdr.fabric_header);
        pkt.emit(hdr.fabric_header_unicast);
        pkt.emit(hdr.fabric_header_multicast);
        pkt.emit(hdr.fabric_header_mirror);
        pkt.emit(hdr.fabric_header_cpu);
        pkt.emit(hdr.fabric_header_sflow);
        pkt.emit(hdr.fabric_payload_header);
    }
}
// package V1Switch<H, M>(Parser<H, M> p,
//                        VerifyChecksum<H, M> vr,
//                        Ingress<H, M> ig,
//                        Egress<H, M> eg,
//                        ComputeChecksum<H, M> ck,
//                        Deparser<H> dep
//                        );

V1Switch(SwitchParser(), verifyChecksum(), ingress(), egress(), updateChecksum(), SwitchDeparser()) main;