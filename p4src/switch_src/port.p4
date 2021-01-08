/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef __PORT__
#define __PORT__

#include "ipv4.p4"
#include "ipv6.p4"
#include "tunnel.p4"

/*
 * Input processing - port and packet related
 */

/*****************************************************************************/
/* Validate outer packet header                                              */
/*****************************************************************************/

// [P4-14 p59] [P4-16 s12.4, s12.2.2]
control process_validate_outer_header (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 

    validate_outer_ipv4_header() validate_outer_ipv4_header_instance;
    validate_outer_ipv6_header() validate_outer_ipv6_header_instance;
    validate_mpls_header() validate_mpls_header_instance;

    action set_valid_outer_unicast_packet_untagged() {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
    }

    action set_valid_outer_unicast_packet_single_tagged() {
        meta.l2_metadata.lkp_pkt_type =  L2_UNICAST;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[0].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action set_valid_outer_unicast_packet_double_tagged() {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[1].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action set_valid_outer_unicast_packet_qinq_tagged() {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action set_valid_outer_multicast_packet_untagged() {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
    }

    action set_valid_outer_multicast_packet_single_tagged() {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[0].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action set_valid_outer_multicast_packet_double_tagged() {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[1].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action set_valid_outer_multicast_packet_qinq_tagged() {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action set_valid_outer_broadcast_packet_untagged() {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
    }

    action set_valid_outer_broadcast_packet_single_tagged() {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[0].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action set_valid_outer_broadcast_packet_double_tagged() {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.lkp_mac_type = hdr.vlan_tag_[1].etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action set_valid_outer_broadcast_packet_qinq_tagged() {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
        meta.l2_metadata.lkp_pcp = hdr.vlan_tag_[0].pcp;
    }

    action malformed_outer_ethernet_packet(bit<8> drop_reason) {
        meta.ingress_metadata.drop_flag = TRUE;
        meta.ingress_metadata.drop_reason = drop_reason;
    }

    table validate_outer_ethernet {
        key = {
            hdr.ethernet.srcAddr : ternary;
            hdr.ethernet.dstAddr : ternary;
            hdr.vlan_tag_[0].isValid() : exact;
            hdr.vlan_tag_[1].isValid() : exact;
        }
        actions = {
            malformed_outer_ethernet_packet;
            set_valid_outer_unicast_packet_untagged;
            set_valid_outer_unicast_packet_single_tagged;
            set_valid_outer_unicast_packet_double_tagged;
            set_valid_outer_unicast_packet_qinq_tagged;
            set_valid_outer_multicast_packet_untagged;
            set_valid_outer_multicast_packet_single_tagged;
            set_valid_outer_multicast_packet_double_tagged;
            set_valid_outer_multicast_packet_qinq_tagged;
            set_valid_outer_broadcast_packet_untagged;
            set_valid_outer_broadcast_packet_single_tagged;
            set_valid_outer_broadcast_packet_double_tagged;
            set_valid_outer_broadcast_packet_qinq_tagged;
        }
        size = VALIDATE_PACKET_TABLE_SIZE;
    }
    apply{
        switch(validate_outer_ethernet.apply().action_run){
            malformed_outer_ethernet_packet: {

            }

            default: {            
                if(hdr.ipv4.isValid()){
                    validate_outer_ipv4_header_instance.apply(hdr, meta, standard_metadata);
                }
                else{
                    if(hdr.ipv6.isValid()){
                        validate_outer_ipv6_header_instance.apply(hdr, meta, standard_metadata);
                    }
                    else{
#ifndef MPLS_DISABLE
                        if(hdr.mpls[0].isValid()){
                            validate_mpls_header_instance.apply(hdr, meta, standard_metadata);
                        }
#endif
                    }
                }
            }
        }
    }
}


/*****************************************************************************/
/* Ingress port lookup                                                       */
/*****************************************************************************/
control process_ingress_port_mapping (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 

    action set_ifindex(bit<IFINDEX_BIT_WIDTH> ifindex, bit<2> port_type) {
        meta.ingress_metadata.ifindex = ifindex;
        meta.ingress_metadata.port_type = port_type;
    }

    table ingress_port_mapping {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_ifindex;
        }
        size = PORTMAP_TABLE_SIZE;
    }

    action set_ingress_port_properties(bit<16> if_label, bit<5> qos_group, bit<5> tc_qos_group,
                                   bit<8> tc, bit<2> color, bit<1> trust_dscp, bit<1> trust_pcp) {
        meta.acl_metadata.if_label = if_label;
        meta.qos_metadata.ingress_qos_group = qos_group;
        meta.qos_metadata.tc_qos_group = tc_qos_group;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
        meta.qos_metadata.trust_dscp = trust_dscp;
        meta.qos_metadata.trust_pcp = trust_pcp;
    }

    table ingress_port_properties {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {
            set_ingress_port_properties;
        }
        size = PORTMAP_TABLE_SIZE;
    }
     
    apply {
        ingress_port_mapping.apply();
        ingress_port_properties.apply();
    }
}

/*****************************************************************************/
/* Ingress port-vlan mapping lookup                                          */
/*****************************************************************************/

control process_port_vlan_mapping (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 

    action set_bd_properties(bit<BD_BIT_WIDTH> bd, bit<VRF_BIT_WIDTH> vrf, bit<10> stp_group, bit<1> learning_enabled,
                         bit<16> bd_label, bit<16> stats_idx, bit<10> rmac_group,
                         bit<1> ipv4_unicast_enabled, bit<1> ipv6_unicast_enabled,
                         bit<2> ipv4_urpf_mode, bit<2> ipv6_urpf_mode,
                         bit<1> igmp_snooping_enabled, bit<1> mld_snooping_enabled,
                         bit<1> ipv4_multicast_enabled, bit<1> ipv6_multicast_enabled,
                         bit<BD_BIT_WIDTH> mrpf_group,
                         bit<BD_BIT_WIDTH> ipv4_mcast_key, bit<1> ipv4_mcast_key_type,
                         bit<BD_BIT_WIDTH> ipv6_mcast_key, bit<1> ipv6_mcast_key_type){
        meta.ingress_metadata.bd = bd;
        meta.ingress_metadata.outer_bd = bd;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.stp_group = stp_group;
        meta.l2_metadata.bd_stats_idx = stats_idx;
        meta.l2_metadata.learning_enabled = learning_enabled;

        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;

        meta.multicast_metadata.igmp_snooping_enabled = igmp_snooping_enabled;
        meta.multicast_metadata.mld_snooping_enabled = mld_snooping_enabled;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv4_mcast_key_type = ipv4_mcast_key_type;
        meta.multicast_metadata.ipv4_mcast_key = ipv4_mcast_key;
        meta.multicast_metadata.ipv6_mcast_key_type = ipv6_mcast_key_type;
        meta.multicast_metadata.ipv6_mcast_key = ipv6_mcast_key;
    }

    action port_vlan_mapping_miss() {
        meta.l2_metadata.port_vlan_mapping_miss = TRUE;
    }

    action_profile(BD_TABLE_SIZE) ap;

    table port_vlan_mapping {
        key =  {
            meta.ingress_metadata.ifindex : exact;
            hdr.vlan_tag_[0].isValid() : exact;
            hdr.vlan_tag_[0].vid : exact;
            hdr.vlan_tag_[1].isValid() : exact;
            hdr.vlan_tag_[1].vid : exact;
        }
        actions = {
            set_bd_properties;
            port_vlan_mapping_miss;
        }
        // size = PORT_VLAN_TABLE_SIZE;
        // implementation = action_profile(BD_TABLE_SIZE);
        implementation = ap;
    }

    action ipv4_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv4_metadata.lkp_ipv4_sa = hdr.ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = hdr.ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv4.protocol;
        meta.l3_metadata.lkp_ip_ttl = hdr.ipv4.ttl;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }

    action ipv6_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv6_metadata.lkp_ipv6_sa = hdr.ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = hdr.ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv6.nextHdr;
        meta.l3_metadata.lkp_ip_ttl = hdr.ipv6.hopLimit;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }

    action non_ip_lkp() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
    }

    table adjust_lkp_fields {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
        }
        actions = {
            non_ip_lkp;
            ipv4_lkp;
    #ifndef IPV6_DISABLE
            ipv6_lkp;
    #endif /* IPV6_DISABLE */
        }
    }
     
    apply{
        port_vlan_mapping.apply();
    #ifdef TUNNEL_DISABLE
        adjust_lkp_fields.apply();
    #endif
    }
}

/*****************************************************************************/
/* Ingress BD stats based on packet type                                     */
/*****************************************************************************/

counter(BD_STATS_TABLE_SIZE, CounterType.packets_and_bytes) cnt;

control process_ingress_bd_stats (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 

#ifndef STATS_DISABLE

    action update_ingress_bd_stats() {
        cnt.count((bit<32>)meta.l2_metadata.bd_stats_idx);
    }

    table ingress_bd_stats {
        actions = {
            update_ingress_bd_stats;
        }
        // size = BD_STATS_TABLE_SIZE;
    }
#endif /* STATS_DISABLE */

    apply {
    #ifndef STATS_DISABLE
        ingress_bd_stats.apply();
    #endif /* STATS_DISABLE */
    }
}

/*****************************************************************************/
/* LAG lookup/resolution                                                     */
/*****************************************************************************/

control process_lag (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 

#ifdef FABRIC_ENABLE
    action set_lag_remote_port(bit<8> device, bit<16> port) {
        meta.fabric_metadata.dst_device = device;
        meta.fabric_metadata.dst_port = port;
    }
#endif /* FABRIC_ENABLE */

    action set_lag_port(bit<9>  port) {
        standard_metadata.egress_spec = port;
    }

    action set_lag_miss() {
    }

    table lag_group {
        key = {
            meta.hash_metadata.hash2 : selector;
            meta.ingress_metadata.egress_ifindex : exact;
        }
        actions = {
            set_lag_miss;
            set_lag_port;
#ifdef FABRIC_ENABLE
            set_lag_remote_port;
#endif /* FABRIC_ENABLE */
        }
        size = LAG_SELECT_TABLE_SIZE;
        implementation = action_selector(HashAlgorithm.identity, LAG_GROUP_TABLE_SIZE, LAG_BIT_WIDTH);
    }

    apply{
        lag_group.apply();
    }
}




control process_vlan_xlate (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 

    /*****************************************************************************/
    /* Egress VLAN translation                                                   */
    /*****************************************************************************/
    action set_egress_packet_vlan_double_tagged(bit<12> s_tag, bit<12> c_tag) {
        hdr.vlan_tag_[1].setValid();
        hdr.vlan_tag_[0].setValid();
        hdr.vlan_tag_[1].etherType = hdr.ethernet.etherType;
        hdr.vlan_tag_[1].vid = c_tag;
        hdr.vlan_tag_[0].etherType = ETHERTYPE_VLAN;
        hdr.vlan_tag_[0].vid = s_tag;
        hdr.ethernet.etherType = ETHERTYPE_QINQ;
    }

    action set_egress_packet_vlan_tagged(bit<12> vlan_id) {
        hdr.vlan_tag_[0].setValid();
        hdr.vlan_tag_[0].etherType = hdr.ethernet.etherType;
        hdr.vlan_tag_[0].vid = vlan_id;
        hdr.ethernet.etherType = ETHERTYPE_VLAN;
    }

    action set_egress_packet_vlan_untagged() {
    }

    table egress_vlan_xlate {
        key = {
            meta.egress_metadata.ifindex: exact;
            meta.egress_metadata.bd : exact;
        }
        actions = {
            set_egress_packet_vlan_untagged;
            set_egress_packet_vlan_tagged;
            set_egress_packet_vlan_double_tagged;
        }
        size = EGRESS_VLAN_XLATE_TABLE_SIZE;
    }
    apply{
        egress_vlan_xlate.apply();
    }
}

#endif