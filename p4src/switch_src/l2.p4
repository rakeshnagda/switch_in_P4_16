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

/*
 * Layer-2 processing
 */


/*****************************************************************************/
/* Spanning tree lookup                                                      */
/*****************************************************************************/


control process_spanning_tree (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#ifndef L2_DISABLE
    action set_stp_state(bit<3> stp_state) {
        meta.l2_metadata.stp_state = stp_state;
    }
    table spanning_tree {
        key = {
            meta.ingress_metadata.ifindex : exact;
            meta.l2_metadata.stp_group: exact;
        }
        actions = {
            set_stp_state;
        }
        size = SPANNING_TREE_TABLE_SIZE;
    }

    apply{
        if((meta.ingress_metadata.port_type == PORT_TYPE_NORMAL) && (meta.l2_metadata.stp_group != STP_GROUP_NONE)) {
            spanning_tree.apply();
        } 
    }
    
#endif /* L2_DISABLE */
}


control process_mac (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
#ifndef L2_DISABLE
    /*****************************************************************************/
    /* Source MAC lookup                                                         */
    /*****************************************************************************/
    action smac_miss() {
        meta.l2_metadata.l2_src_miss = TRUE;
    }

    action smac_hit(bit<IFINDEX_BIT_WIDTH> ifindex) {
        meta.l2_metadata.l2_src_move = meta.ingress_metadata.ifindex ^ ifindex;
    }

    table smac {
        key = {
            meta.ingress_metadata.bd : exact;
            meta.l2_metadata.lkp_mac_sa : exact;
        }
        actions = {
            nop;
            smac_miss;
            smac_hit;
        }
        size = MAC_TABLE_SIZE;
    }

    /*****************************************************************************/
    /* Destination MAC lookup                                                    */
    /*****************************************************************************/
    action dmac_hit(bit<IFINDEX_BIT_WIDTH> ifindex) {
        meta.ingress_metadata.egress_ifindex =  ifindex;
        meta.l2_metadata.same_if_check = meta.l2_metadata.same_if_check ^ ifindex;
    }

    action dmac_multicast_hit(bit<16> mc_index) {
        meta.intrinsic_metadata.mcast_grp= mc_index;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device= FABRIC_DEVICE_MULTICAST;
    #endif /* FABRIC_ENABLE */
    }

    action dmac_miss() {
        meta.ingress_metadata.egress_ifindex= IFINDEX_FLOOD;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device= FABRIC_DEVICE_MULTICAST;
    #endif /* FABRIC_ENABLE */
    }

    action dmac_redirect_nexthop(bit<16> nexthop_index) {
        meta.l2_metadata.l2_redirect=TRUE;
        meta.l2_metadata.l2_nexthop= nexthop_index;
        meta.l2_metadata.l2_nexthop_type= NEXTHOP_TYPE_SIMPLE;
    }

    action dmac_redirect_ecmp(bit<16> ecmp_index) {
        meta.l2_metadata.l2_redirect= TRUE;
        meta.l2_metadata.l2_nexthop= ecmp_index;
        meta.l2_metadata.l2_nexthop_type= NEXTHOP_TYPE_ECMP;
    }

    action dmac_drop() {
        mark_to_drop(standard_metadata);
    }

    table dmac {
        key = {
            meta.ingress_metadata.bd : exact;
            meta.l2_metadata.lkp_mac_da : exact;
        }
        actions = {
    #ifdef OPENFLOW_ENABLE
            openflow_apply;
            openflow_miss;
    #endif /* OPENFLOW_ENABLE */
            nop;
            dmac_hit;
            dmac_multicast_hit;
            dmac_miss;
            dmac_redirect_nexthop;
            dmac_redirect_ecmp;
            dmac_drop;
        }
        size  = MAC_TABLE_SIZE;
        support_timeout = true;
    }
    apply{
        if (DO_LOOKUP(SMAC_CHK) && (meta.ingress_metadata.port_type == PORT_TYPE_NORMAL)) {
            smac.apply();
        }
        if (DO_LOOKUP(L2)) {
            dmac.apply();
        } 
    }
    
#endif /* L2_DISABLE */
}

/*****************************************************************************/
/* MAC learn notification                                                    */
/*****************************************************************************/


control process_mac_learning (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
#ifndef L2_DISABLE

    action generate_learn_notify() {
        digest(MAC_LEARN_RECEIVER, 
                        {
                            meta.ingress_metadata.bd,
                            meta.l2_metadata.lkp_mac_sa,
                            meta.ingress_metadata.ifindex
                        }
        );
    }

    table learn_notify {
        key = {
            meta.l2_metadata.l2_src_miss : ternary;
            meta.l2_metadata.l2_src_move : ternary;
            meta.l2_metadata.stp_state : ternary;
        }
        actions = {
            nop;
            generate_learn_notify;
        }
        size = LEARN_NOTIFY_TABLE_SIZE;
    }

    apply{
        if (meta.l2_metadata.learning_enabled == TRUE) {
            learn_notify.apply();
        }
    }
    
#endif /* L2_DISABLE */
}


/*****************************************************************************/
/* Validate packet                                                           */
/*****************************************************************************/


control process_validate_packet (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    action set_unicast() {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
    }

    action set_unicast_and_ipv6_src_is_link_local() {
        meta.l2_metadata.lkp_pkt_type = L2_UNICAST;
        meta.ipv6_metadata.ipv6_src_is_link_local = TRUE;
    }

    action set_multicast() {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.l2_metadata.bd_stats_idx = 1;
    }

    action set_multicast_and_ipv6_src_is_link_local() {
        meta.l2_metadata.lkp_pkt_type = L2_MULTICAST;
        meta.ipv6_metadata.ipv6_src_is_link_local = TRUE;
        meta.l2_metadata.bd_stats_idx = 1;
    }

    action set_broadcast() {
        meta.l2_metadata.lkp_pkt_type = L2_BROADCAST;
        meta.l2_metadata.bd_stats_idx = 2;
    }

    action set_malformed_packet(bit<8> drop_reason) {
        meta.ingress_metadata.drop_flag = TRUE;
        meta.ingress_metadata.drop_reason = drop_reason;
    }

    table validate_packet {
        key = {
            meta.l2_metadata.lkp_mac_sa : ternary;
            meta.l2_metadata.lkp_mac_da : ternary;
            meta.l3_metadata.lkp_ip_type : ternary;
            meta.l3_metadata.lkp_ip_ttl : ternary;
            meta.l3_metadata.lkp_ip_version : ternary;
            // TODO
            meta.ipv4_metadata.lkp_ipv4_sa & 0xFF000000 : ternary;
    #ifndef IPV6_DISABLE
            meta.ipv6_metadata.lkp_ipv6_sa & 0xFFFF0000000000000000000000000000 : ternary;
    #endif /* IPV6_DISABLE */
        }
        actions = {
            nop;
            set_unicast;
            set_unicast_and_ipv6_src_is_link_local;
            set_multicast;
            set_multicast_and_ipv6_src_is_link_local;
            set_broadcast;
            set_malformed_packet;
        }
        size = VALIDATE_PACKET_TABLE_SIZE;
    }
    apply{
        if (DO_LOOKUP(PKT_VALIDATION) && (meta.ingress_metadata.drop_flag == FALSE)) {
            validate_packet.apply();
        } 
    }
    
}


/*****************************************************************************/
/* Egress BD lookup                                                          */
/*****************************************************************************/


control process_egress_bd_stats (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
#ifndef STATS_DISABLE
    table egress_bd_stats {
    
        key = {
            meta.egress_metadata.bd : exact;
            meta.l2_metadata.lkp_pkt_type: exact;
        }
        actions = {
            nop;
        }
        size = EGRESS_BD_STATS_TABLE_SIZE;
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    apply{
        egress_bd_stats.apply();
    }
    
#endif /* STATS_DISABLE */
}



control process_egress_bd (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    action set_egress_bd_properties(bit<9> smac_idx, bit<2> nat_mode, bit<16> bd_label) {
        meta.egress_metadata.smac_idx = smac_idx;
        meta.nat_metadata.egress_nat_mode = nat_mode;
        meta.acl_metadata.egress_bd_label = bd_label;
    }

    table egress_bd_map {
        key = {
            meta.egress_metadata.bd : exact;
        }
        actions = {
            nop;
            set_egress_bd_properties;
        }
        size = EGRESS_BD_MAPPING_TABLE_SIZE;
    }
    apply{
        egress_bd_map.apply();
    }
    
}

/*****************************************************************************/
/* Egress VLAN decap                                                         */
/*****************************************************************************/


control process_vlan_decap (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    action remove_vlan_single_tagged() {
        hdr.ethernet.etherType = hdr.vlan_tag_[0].etherType;
        hdr.vlan_tag_[0].setInvalid();
    }

    action remove_vlan_double_tagged() {
        hdr.ethernet.etherType = hdr.vlan_tag_[1].etherType;
        hdr.vlan_tag_[0].setInvalid();
        hdr.vlan_tag_[1].setInvalid();
    }

    table vlan_decap {
        key = {
            hdr.vlan_tag_[0].isValid() : exact;
            hdr.vlan_tag_[1].isValid() : exact;
        }
        actions = {
            nop;
            remove_vlan_single_tagged;
            remove_vlan_double_tagged;
        }
        size = VLAN_DECAP_TABLE_SIZE;
    }
    apply{
        vlan_decap.apply();
    }
    
}
