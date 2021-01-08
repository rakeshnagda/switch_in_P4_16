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

#ifndef __TUNNEL__
#define __TUNNEL__

/*
 * Tunnel processing
 */

/*
 * Tunnel metadata
 */

#include "fabric.p4"
#include "multicast.p4"



/*****************************************************************************/
/* IPv4 source and destination VTEP lookups                                  */
/*****************************************************************************/

control process_ipv4_vtep (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#if !defined(TUNNEL_DISABLE) && !defined(IPV4_DISABLE)
    action nop() {
    }
    action on_miss() {
    }
    action set_tunnel_termination_flag() {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
    }

    action set_tunnel_vni_and_termination_flag(bit<24> tunnel_vni) {
        meta.tunnel_metadata.tunnel_vni = tunnel_vni;
        meta.tunnel_metadata.tunnel_terminate = TRUE;
    }

    action src_vtep_hit(bit<IFINDEX_BIT_WIDTH> ifindex) {
        meta.ingress_metadata.ifindex = ifindex;
    }    
    
    table ipv4_dest_vtep {
        key = {
            meta.l3_metadata.vrf : exact;
            hdr.ipv4.dstAddr : exact;
            meta.tunnel_metadata.ingress_tunnel_type : exact;
        }
        actions = {
            nop;
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        size = DEST_TUNNEL_TABLE_SIZE;
    }

    table ipv4_src_vtep {
        key = {
            meta.l3_metadata.vrf : exact;
            hdr.ipv4.srcAddr : exact;
            meta.tunnel_metadata.ingress_tunnel_type : exact;
        }
        actions = {
            on_miss;
            src_vtep_hit;
        }
        size = IPV4_SRC_TUNNEL_TABLE_SIZE;
    }

    apply{
        if(ipv4_src_vtep.apply().hit){
            ipv4_dest_vtep.apply();   
        }
    }

    #endif /* TUNNEL_DISABLE && IPV4_DISABLE */
    }

/*****************************************************************************/
/* IPv6 source and destination VTEP lookups                                  */
/*****************************************************************************/
control process_ipv6_vtep (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    #if !defined(TUNNEL_DISABLE) && !defined(IPV6_DISABLE)
    action nop() {
    }
    action on_miss(){

    }
    action set_tunnel_termination_flag() {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
    }

    action set_tunnel_vni_and_termination_flag(bit<24> tunnel_vni) {
        meta.tunnel_metadata.tunnel_vni = tunnel_vni;
        meta.tunnel_metadata.tunnel_terminate = TRUE;
    }

    action src_vtep_hit(bit<IFINDEX_BIT_WIDTH> ifindex) {
        meta.ingress_metadata.ifindex = ifindex;
    }

    table ipv6_dest_vtep {
        key = {
            meta.l3_metadata.vrf : exact;
            hdr.ipv6.dstAddr : exact;
            meta.tunnel_metadata.ingress_tunnel_type : exact;
        }
        actions = {
            nop;
            set_tunnel_termination_flag;
            set_tunnel_vni_and_termination_flag;
        }
        size = DEST_TUNNEL_TABLE_SIZE;
    }

    table ipv6_src_vtep {
        key = {
            meta.l3_metadata.vrf : exact;
            hdr.ipv6.srcAddr : exact;
            meta.tunnel_metadata.ingress_tunnel_type : exact;
        }
        actions = {
            on_miss;
            src_vtep_hit;
        }
        size = IPV6_SRC_TUNNEL_TABLE_SIZE;
    }
    apply{
        if(ipv6_src_vtep.apply().hit){
            ipv6_dest_vtep.apply();
        }
    }
#endif /* TUNNEL_DISABLE && IPV6_DISABLE */
}


#ifndef TUNNEL_DISABLE



/*****************************************************************************/
/* Validate MPLS header                                                      */
/*****************************************************************************/

control validate_mpls_header (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#if !defined(TUNNEL_DISABLE) && !defined(MPLS_DISABLE)
    action set_valid_mpls_label1() {
        meta.tunnel_metadata.mpls_label = hdr.mpls[0].label;
        meta.tunnel_metadata.mpls_exp = hdr.mpls[0].exp;
    }

    action set_valid_mpls_label2() {
        meta.tunnel_metadata.mpls_label = hdr.mpls[1].label;
        meta.tunnel_metadata.mpls_exp = hdr.mpls[1].exp;
    }

    action set_valid_mpls_label3() {
        meta.tunnel_metadata.mpls_label = hdr.mpls[2].label;
        meta.tunnel_metadata.mpls_exp = hdr.mpls[2].exp;
    }

    table validate_mpls_packet {
        key = {
            hdr.mpls[0].label : ternary;
            hdr.mpls[0].bos : ternary;
            hdr.mpls[0].isValid() : exact;
            hdr.mpls[1].label : ternary;
            hdr.mpls[1].bos : ternary;
            hdr.mpls[1].isValid() : exact;
            hdr.mpls[2].label : ternary;
            hdr.mpls[2].bos : ternary;
            hdr.mpls[2].isValid() : exact;
        }
        actions = {
            set_valid_mpls_label1;
            set_valid_mpls_label2;
            set_valid_mpls_label3;
            //TODO: Redirect to cpu if more than 5 labels
        }
        size = VALIDATE_MPLS_TABLE_SIZE;
    }
    apply{
        validate_mpls_packet.apply();
    }
    
#endif /* TUNNEL_DISABLE && MPLS_DISABLE */
}




/*****************************************************************************/
/* MPLS lookup/forwarding                                                    */
/*****************************************************************************/

control process_mpls (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#if !defined(TUNNEL_DISABLE) && !defined(MPLS_DISABLE)
    action terminate_eompls(bit<BD_BIT_WIDTH> bd, bit<5> tunnel_type) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.ingress_metadata.bd = bd;

        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
    }

    action terminate_vpls(bit<BD_BIT_WIDTH> bd, bit<5> tunnel_type) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.ingress_metadata.bd = bd;

        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
    }

    #ifndef IPV4_DISABLE
    action terminate_ipv4_over_mpls(bit<VRF_BIT_WIDTH> vrf, bit<5> tunnel_type) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.l3_metadata.vrf = vrf;

        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV4;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv4.version;
    #ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = hdr.inner_ipv4.diffserv;
    #endif /* QOS_DISABLE */
    }
    #endif /* IPV4_DISABLE */

    #ifndef IPV6_DISABLE
    action terminate_ipv6_over_mpls(bit<VRF_BIT_WIDTH> vrf, bit<5> tunnel_type) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.tunnel_metadata.ingress_tunnel_type = tunnel_type;
        meta.l3_metadata.vrf = vrf;

        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV6;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv6.version;
    #ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = hdr.inner_ipv6.trafficClass;
    #endif /* QOS_DISABLE */
    }
    #endif /* IPV6_DISABLE */

    action terminate_pw(bit<IFINDEX_BIT_WIDTH> ifindex) {
        meta.ingress_metadata.egress_ifindex = ifindex;

        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
    }

    action forward_mpls(bit<16> nexthop_index) {
        meta.l3_metadata.fib_nexthop = nexthop_index;
        meta.l3_metadata.fib_nexthop_type = NEXTHOP_TYPE_SIMPLE;
        meta.l3_metadata.fib_hit = TRUE;

        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
    }

    table mpls {
        key = {
            meta.tunnel_metadata.mpls_label: exact;
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
        }
        actions = {
            terminate_eompls;
            terminate_vpls;
    #ifndef IPV4_DISABLE
            terminate_ipv4_over_mpls;
    #endif /* IPV4_DISABLE */
    #ifndef IPV6_DISABLE
            terminate_ipv6_over_mpls;
    #endif /* IPV6_DISABLE */
            terminate_pw;
            forward_mpls;
        }
        size = MPLS_TABLE_SIZE;
    }

    apply{
        mpls.apply();
    }
    
#endif /* TUNNEL_DISABLE && MPLS_DISABLE */
}

/*****************************************************************************/
/* Ingress tunnel processing                                                 */
/*****************************************************************************/

control process_tunnel (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    process_mpls() process_mpls_instance;
    process_ingress_fabric() process_ingress_fabric_instance;
    process_outer_multicast() process_outer_multicast_instance;

    action nop(){

    }
    action on_miss(){

    }

    /*****************************************************************************/
    /* Tunnel termination                                                        */
    /*****************************************************************************/
    action terminate_tunnel_inner_non_ip(bit<BD_BIT_WIDTH> bd, bit<16> bd_label, bit<16> stats_idx) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.ingress_metadata.bd = bd;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;

        meta.l3_metadata.lkp_ip_type = IPTYPE_NONE;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
    }

    #ifndef IPV4_DISABLE
    action terminate_tunnel_inner_ethernet_ipv4(bit<BD_BIT_WIDTH> bd, bit<VRF_BIT_WIDTH> vrf,
            bit<10> rmac_group, bit<16> bd_label,
            bit<1> ipv4_unicast_enabled, bit<2> ipv4_urpf_mode,
            bit<1> igmp_snooping_enabled, bit<16> stats_idx,
            bit<1> ipv4_multicast_enabled, bit<BD_BIT_WIDTH> mrpf_group) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.ingress_metadata.bd = bd;
        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;

        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV4;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv4.version;
    #ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = hdr.inner_ipv4.diffserv;
    #endif /* QOS_DISABLE */

        meta.multicast_metadata.igmp_snooping_enabled = igmp_snooping_enabled;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
    }

    action terminate_tunnel_inner_ipv4(bit<VRF_BIT_WIDTH> vrf, bit<10> rmac_group,
            bit<2> ipv4_urpf_mode, bit<1> ipv4_unicast_enabled,
            bit<1> ipv4_multicast_enabled, bit<BD_BIT_WIDTH> mrpf_group) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.l3_metadata.vrf = vrf;
        meta.ipv4_metadata.ipv4_unicast_enabled = ipv4_unicast_enabled;
        meta.ipv4_metadata.ipv4_urpf_mode = ipv4_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;

        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV4;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv4.version;
    #ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = hdr.inner_ipv4.diffserv;
    #endif /* QOS_DISABLE */

        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv4_multicast_enabled = ipv4_multicast_enabled;
    }
    #endif /* IPV4_DISABLE */

    #ifndef IPV6_DISABLE
    action terminate_tunnel_inner_ethernet_ipv6(bit<BD_BIT_WIDTH> bd, bit<VRF_BIT_WIDTH> vrf,
            bit<10> rmac_group, bit<16> bd_label,
            bit<1> ipv6_unicast_enabled, bit<2> ipv6_urpf_mode,
            bit<1> mld_snooping_enabled, bit<16> stats_idx,
            bit<1> ipv6_multicast_enabled, bit<BD_BIT_WIDTH> mrpf_group) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.ingress_metadata.bd = bd;
        meta.l3_metadata.vrf = vrf;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;
        meta.acl_metadata.bd_label = bd_label;
        meta.l2_metadata.bd_stats_idx = stats_idx;

        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV6;
        meta.l2_metadata.lkp_mac_type = hdr.inner_ethernet.etherType;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv6.version;

    #ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = hdr.inner_ipv6.trafficClass;
    #endif /* QOS_DISABLE */

        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
        meta.multicast_metadata.mld_snooping_enabled = mld_snooping_enabled;
    }

    action terminate_tunnel_inner_ipv6(bit<VRF_BIT_WIDTH> vrf, bit<10> rmac_group,
            bit<1> ipv6_unicast_enabled, bit<2> ipv6_urpf_mode,
            bit<1> ipv6_multicast_enabled, bit<BD_BIT_WIDTH> mrpf_group) {
        meta.tunnel_metadata.tunnel_terminate = TRUE;
        meta.l3_metadata.vrf = vrf;
        meta.ipv6_metadata.ipv6_unicast_enabled = ipv6_unicast_enabled;
        meta.ipv6_metadata.ipv6_urpf_mode = ipv6_urpf_mode;
        meta.l3_metadata.rmac_group = rmac_group;

        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV6;
        meta.l3_metadata.lkp_ip_version = hdr.inner_ipv6.version;

    #ifdef QOS_DISABLE
        meta.l3_metadata.lkp_dscp = hdr.inner_ipv6.trafficClass;
    #endif /* QOS_DISABLE */

        meta.multicast_metadata.bd_mrpf_group = mrpf_group;
        meta.multicast_metadata.ipv6_multicast_enabled = ipv6_multicast_enabled;
    }
    #endif /* IPV6_DISABLE */

    action tunnel_lookup_miss() {
    }

    table tunnel {
        key = {
            meta.tunnel_metadata.tunnel_vni : exact;
            meta.tunnel_metadata.ingress_tunnel_type : exact;
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
        }
        actions = {
            nop;
            tunnel_lookup_miss;
            terminate_tunnel_inner_non_ip;
    #ifndef IPV4_DISABLE
            terminate_tunnel_inner_ethernet_ipv4;
            terminate_tunnel_inner_ipv4;
    #endif /* IPV4_DISABLE */
    #ifndef IPV6_DISABLE
            terminate_tunnel_inner_ethernet_ipv6;
            terminate_tunnel_inner_ipv6;
    #endif /* IPV6_DISABLE */
        }
        size = VNID_MAPPING_TABLE_SIZE;
    }
    #endif /* TUNNEL_DISABLE */

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

    table tunnel_lookup_miss_table {
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

    #ifndef TUNNEL_DISABLE
    /*****************************************************************************/
    /* Outer router mac lookup                                                   */
    /*****************************************************************************/
    action outer_rmac_hit() {
        meta.l3_metadata.rmac_hit = TRUE;
    }

    table outer_rmac {
        key = {
            meta.l3_metadata.rmac_group : exact;
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            on_miss;
            outer_rmac_hit;
        }
        size = OUTER_ROUTER_MAC_TABLE_SIZE;
    }
    #endif /* TUNNEL_DISABLE */

    apply{
#ifndef TUNNEL_DISABLE
        /* ingress fabric processing */
        process_ingress_fabric_instance.apply(hdr, meta, standard_metadata);
        if (meta.tunnel_metadata.ingress_tunnel_type != INGRESS_TUNNEL_TYPE_NONE) {

            /* outer RMAC lookup for tunnel termination */
            switch(outer_rmac.apply().action_run) {
                on_miss: {
                    process_outer_multicast_instance.apply(hdr, meta, standard_metadata);
                }
                default: {
                    if (hdr.ipv4.isValid()) {
                        process_ipv4_vtep.apply(hdr, meta, standard_metadata);
                    } 
                    else 
                    {
                        if (hdr.ipv6.isValid()) {
                            process_ipv6_vtep.apply(hdr, meta, standard_metadata);
                        } 
                        else 
                        {
                            /* check for hdr.mpls tunnel termination */
#ifndef MPLS_DISABLE
                            if (hdr.mpls[0].isValid()) {
                                process_mpls_instance.apply(hdr, meta, standard_metadata);
                            }
    #endif
                        }
                    }
                }
            }
        }
        /* perform tunnel termination */
        if ((meta.tunnel_metadata.tunnel_terminate == TRUE) ||
            ((meta.multicast_metadata.outer_mcast_route_hit == TRUE) &&
             (((meta.multicast_metadata.outer_mcast_mode == MCAST_MODE_SM) &&
               (meta.multicast_metadata.mcast_rpf_group == 0)) ||
              ((meta.multicast_metadata.outer_mcast_mode == MCAST_MODE_BIDIR) &&
               (meta.multicast_metadata.mcast_rpf_group != 0))))) {
            switch(tunnel.apply().action_run){
                tunnel_lookup_miss:{   
                    tunnel_lookup_miss_table.apply();
                }
            }
        } 
        else {
            adjust_lkp_fields.apply();
        }
#endif /* TUNNEL_DISABLE */
    }

}


/*****************************************************************************/
/* Tunnel decap processing                                                   */
/*****************************************************************************/
control process_tunnel_decap (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#ifndef TUNNEL_DISABLE
    /*****************************************************************************/
    /* Tunnel decap (strip tunnel header)                                        */
    /*****************************************************************************/
    action decap_vxlan_inner_ipv4() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.vxlan.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    action decap_vxlan_inner_ipv6() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.vxlan.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv6.setInvalid();
    }

    action decap_vxlan_inner_non_ip() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.vxlan.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.inner_ethernet.setInvalid();
    }

    action decap_genv_inner_ipv4() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.genv.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    action decap_genv_inner_ipv6() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.genv.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv6.setInvalid();
    }

    action decap_genv_inner_non_ip() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.genv.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.inner_ethernet.setInvalid();
    }

    #ifndef NVGRE_DISABLE
    action decap_nvgre_inner_ipv4() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.nvgre.setInvalid();
        hdr.gre.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    action decap_nvgre_inner_ipv6() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.nvgre.setInvalid();
        hdr.gre.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv6.setInvalid();
    }

    action decap_nvgre_inner_non_ip() {
        hdr.ethernet = hdr.inner_ethernet;
        hdr.nvgre.setInvalid();
        hdr.gre.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.inner_ethernet.setInvalid();
    }
    #endif

    action decap_gre_inner_ipv4() {
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.gre.setInvalid();
        hdr.ipv6.setInvalid();
        hdr.inner_ipv4.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action decap_gre_inner_ipv6() {
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.gre.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.inner_ipv6.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    action decap_gre_inner_non_ip() {
        hdr.ethernet.etherType = hdr.gre.proto;
        hdr.gre.setInvalid();
        hdr.ipv4.setInvalid();
        hdr.inner_ipv6.setInvalid();
    }

    action decap_ip_inner_ipv4() {
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.ipv6.setInvalid();
        hdr.inner_ipv4.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action decap_ip_inner_ipv6() {
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.ipv4.setInvalid();
        hdr.inner_ipv6.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    #ifndef MPLS_DISABLE
    action decap_mpls_inner_ipv4_pop1() {
        hdr.mpls[0].setInvalid();
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action decap_mpls_inner_ipv6_pop1() {
        hdr.mpls[0].setInvalid();
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.inner_ipv6.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    action decap_mpls_inner_ethernet_ipv4_pop1() {
        hdr.mpls[0].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    action decap_mpls_inner_ethernet_ipv6_pop1() {
        hdr.mpls[0].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv6.setInvalid();
    }

    action decap_mpls_inner_ethernet_non_ip_pop1() {
        hdr.mpls[0].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.inner_ethernet.setInvalid();
    }

    action decap_mpls_inner_ipv4_pop2() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action decap_mpls_inner_ipv6_pop2() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.inner_ipv6.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    action decap_mpls_inner_ethernet_ipv4_pop2() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    action decap_mpls_inner_ethernet_ipv6_pop2() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv6.setInvalid();
    }

    action decap_mpls_inner_ethernet_non_ip_pop2() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.inner_ethernet.setInvalid();
    }

    action decap_mpls_inner_ipv4_pop3() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.mpls[2].setInvalid();
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ipv4.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action decap_mpls_inner_ipv6_pop3() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.mpls[2].setInvalid();
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.inner_ipv6.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    action decap_mpls_inner_ethernet_ipv4_pop3() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.mpls[2].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv4 = hdr.inner_ipv4;
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv4.setInvalid();
    }

    action decap_mpls_inner_ethernet_ipv6_pop3() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.mpls[2].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.ipv6 = hdr.inner_ipv6;
        hdr.inner_ethernet.setInvalid();
        hdr.inner_ipv6.setInvalid();
    }

    action decap_mpls_inner_ethernet_non_ip_pop3() {
        hdr.mpls[0].setInvalid();
        hdr.mpls[1].setInvalid();
        hdr.mpls[2].setInvalid();
        hdr.ethernet = hdr.inner_ethernet;
        hdr.inner_ethernet.setInvalid();
    }
    #endif /* MPLS_DISABLE */

    table tunnel_decap_process_outer {
        key = {
            meta.tunnel_metadata.ingress_tunnel_type : exact;
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv6.isValid() : exact;
        }
        actions = {
            decap_vxlan_inner_ipv4;
            decap_vxlan_inner_ipv6;
            decap_vxlan_inner_non_ip;
            decap_genv_inner_ipv4;
            decap_genv_inner_ipv6;
            decap_genv_inner_non_ip;
    #ifndef NVGRE_DISABLE
            decap_nvgre_inner_ipv4;
            decap_nvgre_inner_ipv6;
            decap_nvgre_inner_non_ip;
    #endif
            decap_gre_inner_ipv4;
            decap_gre_inner_ipv6;
            decap_gre_inner_non_ip;
            decap_ip_inner_ipv4;
            decap_ip_inner_ipv6;
    #ifndef MPLS_DISABLE
            decap_mpls_inner_ipv4_pop1;
            decap_mpls_inner_ipv6_pop1;
            decap_mpls_inner_ethernet_ipv4_pop1;
            decap_mpls_inner_ethernet_ipv6_pop1;
            decap_mpls_inner_ethernet_non_ip_pop1;
            decap_mpls_inner_ipv4_pop2;
            decap_mpls_inner_ipv6_pop2;
            decap_mpls_inner_ethernet_ipv4_pop2;
            decap_mpls_inner_ethernet_ipv6_pop2;
            decap_mpls_inner_ethernet_non_ip_pop2;
            decap_mpls_inner_ipv4_pop3;
            decap_mpls_inner_ipv6_pop3;
            decap_mpls_inner_ethernet_ipv4_pop3;
            decap_mpls_inner_ethernet_ipv6_pop3;
            decap_mpls_inner_ethernet_non_ip_pop3;
    #endif /* MPLS_DISABLE */
        }
        size = TUNNEL_DECAP_TABLE_SIZE;
    }

    /*****************************************************************************/
    /* Tunnel decap (move inner header to outer)                                 */
    /*****************************************************************************/
    action decap_inner_udp() {
        hdr.udp = hdr.inner_udp;
        hdr.inner_udp.setInvalid();
    }

    action decap_inner_tcp() {
        hdr.tcp = hdr.inner_tcp;
        hdr.inner_tcp.setInvalid();
        hdr.udp.setInvalid();
    }

    action decap_inner_icmp() {
        hdr.icmp = hdr.inner_icmp;
        hdr.inner_icmp.setInvalid();
        hdr.udp.setInvalid();
    }

    action decap_inner_unknown() {
        hdr.udp.setInvalid();
    }

    table tunnel_decap_process_inner {
        key = {
            hdr.inner_udp.isValid() : exact;
            hdr.inner_tcp.isValid() : exact;
            hdr.inner_icmp.isValid() : exact;
        }
        actions = {
            decap_inner_udp;
            decap_inner_tcp;
            decap_inner_icmp;
            decap_inner_unknown;
        }
        size = TUNNEL_DECAP_TABLE_SIZE;
    }
    apply{
        if (meta.tunnel_metadata.tunnel_terminate == TRUE) {
            if ((meta.multicast_metadata.inner_replica == TRUE) ||
                (meta.multicast_metadata.replica == FALSE)) {
                tunnel_decap_process_outer.apply();
                tunnel_decap_process_inner.apply();
            }
        }  
    }
    
#endif /* TUNNEL_DISABLE */
}




/*****************************************************************************/
/* Tunnel encap processing                                                   */
/*****************************************************************************/
control process_tunnel_encap (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata){
#ifndef TUNNEL_DISABLE
    action nop(){

    }

    #ifndef TUNNEL_DISABLE
    /*****************************************************************************/
    /* Egress tunnel VNI lookup                                                  */
    /*****************************************************************************/
    action set_egress_tunnel_vni(bit<24> vnid) {
        meta.tunnel_metadata.vnid = vnid;
    }

    table egress_vni {
        key = {
            meta.egress_metadata.bd : exact;
            meta.tunnel_metadata.egress_tunnel_type: exact;
        }
        actions = {
            nop;
            set_egress_tunnel_vni;
        }
        size = EGRESS_VNID_MAPPING_TABLE_SIZE;
    }


    /*****************************************************************************/
    /* Tunnel encap (inner header rewrite)                                       */
    /*****************************************************************************/
    action inner_ipv4_udp_rewrite() {
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.inner_udp = hdr.udp;
        meta.egress_metadata.payload_length = hdr.ipv4.totalLen;
        hdr.udp.setInvalid();
        hdr.ipv4.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }

    action inner_ipv4_tcp_rewrite() {
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.inner_tcp = hdr.tcp;
        meta.egress_metadata.payload_length = hdr.ipv4.totalLen;
        hdr.tcp.setInvalid();
        hdr.ipv4.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }

    action inner_ipv4_icmp_rewrite() {
        hdr.inner_ipv4 = hdr.ipv4;
        hdr.inner_icmp = hdr.icmp;
        meta.egress_metadata.payload_length = hdr.ipv4.totalLen;
        hdr.icmp.setInvalid();
        hdr.ipv4.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }

    action inner_ipv4_unknown_rewrite() {
        hdr.inner_ipv4 = hdr.ipv4;
        meta.egress_metadata.payload_length = hdr.ipv4.totalLen;
        hdr.ipv4.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV4;
    }

    action inner_ipv6_udp_rewrite() {
        hdr.inner_ipv6 = hdr.ipv6;
        hdr.inner_udp = hdr.udp;
        meta.egress_metadata.payload_length = hdr.ipv6.payloadLen + 40;
        hdr.ipv6.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }

    action inner_ipv6_tcp_rewrite() {
        hdr.inner_ipv6 = hdr.ipv6;
        hdr.inner_tcp = hdr.tcp;
        meta.egress_metadata.payload_length = hdr.ipv6.payloadLen + 40;
        hdr.tcp.setInvalid();
        hdr.ipv6.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }

    action inner_ipv6_icmp_rewrite() {
        hdr.inner_ipv6 = hdr.ipv6;
        hdr.inner_icmp = hdr.icmp;
        meta.egress_metadata.payload_length = hdr.ipv6.payloadLen + 40;
        hdr.icmp.setInvalid();
        hdr.ipv6.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }

    action inner_ipv6_unknown_rewrite() {
        hdr.inner_ipv6 = hdr.ipv6;
        meta.egress_metadata.payload_length = hdr.ipv6.payloadLen + 40;
        hdr.ipv6.setInvalid();
        meta.tunnel_metadata.inner_ip_proto = IP_PROTOCOLS_IPV6;
    }

    action inner_non_ip_rewrite() {
        meta.egress_metadata.payload_length = (bit<16>)(standard_metadata.packet_length - 14);
    }

    table tunnel_encap_process_inner {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
            hdr.tcp.isValid() : exact;
            hdr.udp.isValid() : exact;
            hdr.icmp.isValid() : exact;
        }
        actions = {
            inner_ipv4_udp_rewrite;
            inner_ipv4_tcp_rewrite;
            inner_ipv4_icmp_rewrite;
            inner_ipv4_unknown_rewrite;
            inner_ipv6_udp_rewrite;
            inner_ipv6_tcp_rewrite;
            inner_ipv6_icmp_rewrite;
            inner_ipv6_unknown_rewrite;
            inner_non_ip_rewrite;
        }
        size = TUNNEL_HEADER_TABLE_SIZE;
    }


    /*****************************************************************************/
    /* Tunnel encap (insert tunnel header)                                       */
    /*****************************************************************************/
    #if !defined(TUNNEL_DISABLE) || !defined(MIRROR_DISABLE)

    action fabric_rewrite(bit<14> tunnel_index) {
        meta.tunnel_metadata.tunnel_index = tunnel_index;
    }

    action f_insert_ipv4_header(bit<8> proto) {
        hdr.ipv4.setValid();
        hdr.ipv4.protocol = proto;
        hdr.ipv4.ttl = 64;
        hdr.ipv4.version = 0x4;
        hdr.ipv4.ihl = 0x5;
        hdr.ipv4.identification = 0;
    }

    action f_insert_ipv6_header(bit<8> proto) {
        hdr.ipv6.setValid();
        hdr.ipv6.version = 0x6;
        hdr.ipv6.nextHdr = proto;
        hdr.ipv6.hopLimit = 64;
        hdr.ipv6.trafficClass = 0;
        hdr.ipv6.flowLabel = 0;
    }
    #endif /* !TUNNEL_DISABLE || !MIRROR_DISABLE*/
    
    action f_insert_vxlan_header() {
        hdr.inner_ethernet = hdr.ethernet;
        hdr.udp.setValid();
        hdr.vxlan.setValid();

        hdr.udp.srcPort = meta.hash_metadata.entropy_hash;
        hdr.udp.dstPort = UDP_PORT_VXLAN;
        meta.l3_metadata.egress_l4_sport = meta.hash_metadata.entropy_hash;
        meta.l3_metadata.egress_l4_dport = UDP_PORT_VXLAN;
        hdr.udp.checksum = 0;
        hdr.udp.length_ = meta.egress_metadata.payload_length + 30;

        hdr.vxlan.flags = 0x8;
        hdr.vxlan.reserved = 0;
        hdr.vxlan.vni = meta.tunnel_metadata.vnid;
        hdr.vxlan.reserved2 = 0;
    }

    action ipv4_vxlan_rewrite() {
        f_insert_vxlan_header();
        f_insert_ipv4_header(IP_PROTOCOLS_UDP);
        hdr.ipv4.totalLen = meta.egress_metadata.payload_length + 50;
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action ipv6_vxlan_rewrite() {
        f_insert_vxlan_header();
        f_insert_ipv6_header(IP_PROTOCOLS_UDP);
        hdr.ipv6.payloadLen = meta.egress_metadata.payload_length + 30;
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    action f_insert_genv_header() {
        hdr.inner_ethernet = hdr.ethernet;
        hdr.udp.setValid();
        hdr.genv.setValid();

        hdr.udp.srcPort = meta.hash_metadata.entropy_hash;
        hdr.udp.dstPort = UDP_PORT_GENV;
        meta.l3_metadata.egress_l4_sport = meta.hash_metadata.entropy_hash;
        meta.l3_metadata.egress_l4_dport = UDP_PORT_GENV;
        hdr.udp.checksum = 0;
        hdr.udp.length_ = meta.egress_metadata.payload_length + 30;

        hdr.genv.ver = 0;
        hdr.genv.oam = 0;
        hdr.genv.critical = 0;
        hdr.genv.optLen = 0;
        hdr.genv.protoType = ETHERTYPE_ETHERNET;
        hdr.genv.vni = meta.tunnel_metadata.vnid;
        hdr.genv.reserved = 0;
        hdr.genv.reserved2 = 0;
    }

    action ipv4_genv_rewrite() {
        f_insert_genv_header();
        f_insert_ipv4_header(IP_PROTOCOLS_UDP);
        hdr.ipv4.totalLen = meta.egress_metadata.payload_length + 50;
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action ipv6_genv_rewrite() {
        f_insert_genv_header();
        f_insert_ipv6_header(IP_PROTOCOLS_UDP);
        hdr.ipv6.payloadLen = meta.egress_metadata.payload_length + 30;
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    #ifndef NVGRE_DISABLE
    action f_insert_nvgre_header() {
        hdr.inner_ethernet = hdr.ethernet;
        hdr.gre.setValid();
        hdr.nvgre.setValid();
        hdr.gre.proto = ETHERTYPE_ETHERNET;
        hdr.gre.recurse = 0;
        hdr.gre.flags = 0;
        hdr.gre.ver = 0;
        hdr.gre.R = 0;
        hdr.gre.K = 1;
        hdr.gre.C = 0;
        hdr.gre.S = 0;
        hdr.gre.s = 0;
        hdr.nvgre.tni = meta.tunnel_metadata.vnid;
        //TODO  = meta.hash_metadata.entropy_hash, 0xFF;
    }

    action ipv4_nvgre_rewrite() {
        f_insert_nvgre_header();
        f_insert_ipv4_header(IP_PROTOCOLS_GRE);
        hdr.ipv4.totalLen = meta.egress_metadata.payload_length + 42;
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action ipv6_nvgre_rewrite() {
        f_insert_nvgre_header();
        f_insert_ipv6_header(IP_PROTOCOLS_GRE);
        hdr.ipv6.payloadLen = meta.egress_metadata.payload_length + 22;
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }
    #endif

    action f_insert_gre_header() {
        hdr.gre.setValid();
    }

    action ipv4_gre_rewrite() {
        f_insert_gre_header();
        hdr.gre.proto = hdr.ethernet.etherType;
        f_insert_ipv4_header(IP_PROTOCOLS_GRE);
        hdr.ipv4.totalLen = meta.egress_metadata.payload_length + 24;
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action ipv6_gre_rewrite() {
        f_insert_gre_header();
        hdr.gre.proto = hdr.ethernet.etherType;
        f_insert_ipv6_header(IP_PROTOCOLS_GRE);
        hdr.ipv6.payloadLen = meta.egress_metadata.payload_length + 4;
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    action ipv4_ip_rewrite() {
        f_insert_ipv4_header(meta.tunnel_metadata.inner_ip_proto);
        hdr.ipv4.totalLen = meta.egress_metadata.payload_length + 20;
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action ipv6_ip_rewrite() {
        f_insert_ipv6_header(meta.tunnel_metadata.inner_ip_proto);
        hdr.ipv6.payloadLen = meta.egress_metadata.payload_length;
        hdr.ethernet.etherType = ETHERTYPE_IPV6;
    }

    #ifndef MPLS_DISABLE
    action mpls_ethernet_push1_rewrite() {
        hdr.inner_ethernet = hdr.ethernet;
        hdr.mpls.push_front( 1);
        hdr.ethernet.etherType = ETHERTYPE_MPLS;
    }

    action mpls_ip_push1_rewrite() {
        hdr.mpls.push_front( 1);
        hdr.ethernet.etherType = ETHERTYPE_MPLS;
    }

    action mpls_ethernet_push2_rewrite() {
        hdr.inner_ethernet = hdr.ethernet;
        hdr.mpls.push_front( 2);
        hdr.ethernet.etherType = ETHERTYPE_MPLS;
    }

    action mpls_ip_push2_rewrite() {
        hdr.mpls.push_front( 2);
        hdr.ethernet.etherType = ETHERTYPE_MPLS;
    }

    action mpls_ethernet_push3_rewrite() {
        hdr.inner_ethernet = hdr.ethernet;
        hdr.mpls.push_front( 3);
        hdr.ethernet.etherType = ETHERTYPE_MPLS;
    }

    action mpls_ip_push3_rewrite() {
        hdr.mpls.push_front( 3);
        hdr.ethernet.etherType = ETHERTYPE_MPLS;
    }
    #endif /* MPLS_DISABLE */
    #endif /* TUNNEL_DISABLE */

    #ifndef MIRROR_DISABLE
    action f_insert_erspan_common_header() {
        hdr.inner_ethernet = hdr.ethernet;
        hdr.gre.setValid();
        hdr.erspan_t3_header.setValid();
        hdr.gre.C = 0;
        hdr.gre.R = 0;
        hdr.gre.K = 0;
        hdr.gre.S = 0;
        hdr.gre.s = 0;
        hdr.gre.recurse = 0;
        hdr.gre.flags = 0;
        hdr.gre.ver = 0;
        hdr.gre.proto = GRE_PROTOCOLS_ERSPAN_T3;
        hdr.erspan_t3_header.timestamp = meta.i2e_metadata.ingress_tstamp;
        hdr.erspan_t3_header.span_id = (bit<10>)meta.i2e_metadata.mirror_session_id;
        hdr.erspan_t3_header.version = 2;
        hdr.erspan_t3_header.sgt = 0;
    }

    action f_insert_erspan_t3_header() {
        f_insert_erspan_common_header();
    }

    action ipv4_erspan_t3_rewrite() {
        f_insert_erspan_t3_header();
        f_insert_ipv4_header(IP_PROTOCOLS_GRE);
        hdr.ipv4.totalLen = meta.egress_metadata.payload_length + 50;
    }

    action ipv6_erspan_t3_rewrite() {
        f_insert_erspan_t3_header();
        f_insert_ipv6_header(IP_PROTOCOLS_GRE);
        hdr.ipv6.payloadLen = meta.egress_metadata.payload_length + 26;
    }

    #ifdef NEGATIVE_MIRRORING_ENABLE
    action f_insert_erspan_negative_mirroring_header() {
        f_insert_erspan_common_header();
        hdr.erspan_platform_subheader.setValid();
        hdr.erspan_t3_header.ft_d_other = 1;
        modify_field_with_hash_based_offset(hdr.erspan_platform_subheader.neg_mirror, 0,
                                            calc_neg_mirror, 0x100000000);
        hdr.erspan_platform_subheader.switch_i d
                     global_config_metadata.switch_id);
    }

    action ipv4_erspan_nm_rewrite() {
        f_insert_erspan_negative_mirroring_header();
        f_insert_ipv4_header(IP_PROTOCOLS_GRE);
        hdr.ipv4.totalLen = meta.egress_metadata.payload_length + 58;
    }

    action ipv6_erspan_nm_rewrite() {
        f_insert_erspan_negative_mirroring_header();
        f_insert_ipv6_header(IP_PROTOCOLS_GRE);
        hdr.ipv6.payloadLen = meta.egress_metadata.payload_length + 34;
    }
    #endif /* NEGATIVE_MIRRORING_ENABLE */
    #endif /* MIRROR_DISABLE */

    table tunnel_encap_process_outer {
        key = {
            meta.tunnel_metadata.egress_tunnel_type : exact;
            meta.tunnel_metadata.egress_header_count : exact;
            meta.multicast_metadata.replica : exact;
        }
        actions = {
            nop;
            fabric_rewrite;
    #ifndef TUNNEL_DISABLE
            ipv4_vxlan_rewrite;
            ipv4_genv_rewrite;
    #ifndef NVGRE_DISABLE
            ipv4_nvgre_rewrite;
    #endif /* NVGRE_DISABLE */
            ipv4_gre_rewrite;
            ipv4_ip_rewrite;
    #ifndef TUNNEL_OVER_IPV6_DISABLE
            ipv6_gre_rewrite;
            ipv6_ip_rewrite;
    #ifndef NVGRE_DISABLE
            ipv6_nvgre_rewrite;
    #endif /* NVGRE_DISABLE */
            ipv6_vxlan_rewrite;
            ipv6_genv_rewrite;
    #endif /* TUNNEL_OVER_IPV6_DISABLE */
    #ifndef MPLS_DISABLE
            mpls_ethernet_push1_rewrite;
            mpls_ip_push1_rewrite;
            mpls_ethernet_push2_rewrite;
            mpls_ip_push2_rewrite;
            mpls_ethernet_push3_rewrite;
            mpls_ip_push3_rewrite;
    #endif /* MPLS_DISABLE */
    #endif /* TUNNEL_DISABLE */
    #ifndef MIRROR_DISABLE
            ipv4_erspan_t3_rewrite;
            ipv6_erspan_t3_rewrite;
    #endif /* MIRROR_DISABLE */
        }
        size = TUNNEL_HEADER_TABLE_SIZE;
    }


    /*****************************************************************************/
    /* Tunnel rewrite                                                            */
    /*****************************************************************************/
    action set_tunnel_rewrite_details(bit<BD_BIT_WIDTH> outer_bd, bit<9> smac_idx, bit<14> dmac_idx,
                                      bit<9> sip_index, bit<14> dip_index) {
        meta.egress_metadata.outer_bd = outer_bd;
        meta.tunnel_metadata.tunnel_smac_index = smac_idx;
        meta.tunnel_metadata.tunnel_dmac_index = dmac_idx;
        meta.tunnel_metadata.tunnel_src_index = sip_index;
        meta.tunnel_metadata.tunnel_dst_index = dip_index;
    }

    #ifndef MPLS_DISABLE
    action set_mpls_rewrite_push1(bit<20> label1, bit<3> exp1, bit<8> ttl1, bit<9> smac_idx, bit<14> dmac_idx) {
        hdr.mpls[0].label = label1;
        hdr.mpls[0].exp = exp1;
        hdr.mpls[0].bos = 0x1;
        hdr.mpls[0].ttl = ttl1;
        meta.tunnel_metadata.tunnel_smac_index = smac_idx;
        meta.tunnel_metadata.tunnel_dmac_index = dmac_idx;
    }

    action set_mpls_rewrite_push2(bit<20> label1, bit<3> exp1, bit<8> ttl1, bit<20> label2, bit<3> exp2, bit<8> ttl2,
                                  bit<9> smac_idx, bit<14> dmac_idx) {
        hdr.mpls[0].label = label1;
        hdr.mpls[0].exp = exp1;
        hdr.mpls[0].ttl = ttl1;
        hdr.mpls[0].bos = 0x0;
        hdr.mpls[1].label = label2;
        hdr.mpls[1].exp = exp2;
        hdr.mpls[1].ttl = ttl2;
        hdr.mpls[1].bos = 0x1;
        meta.tunnel_metadata.tunnel_smac_index = smac_idx;
        meta.tunnel_metadata.tunnel_dmac_index = dmac_idx;
    }

    action set_mpls_rewrite_push3(bit<20> label1, bit<3> exp1, bit<8> ttl1, bit<20> label2, bit<3> exp2, bit<8> ttl2,
                                  bit<20> label3, bit<3> exp3, bit<8> ttl3, bit<9> smac_idx, bit<14> dmac_idx) {
        hdr.mpls[0].label = label1;
        hdr.mpls[0].exp = exp1;
        hdr.mpls[0].ttl = ttl1;
        hdr.mpls[0].bos = 0x0;
        hdr.mpls[1].label = label2;
        hdr.mpls[1].exp = exp2;
        hdr.mpls[1].ttl = ttl2;
        hdr.mpls[1].bos = 0x0;
        hdr.mpls[2].label = label3;
        hdr.mpls[2].exp = exp3;
        hdr.mpls[2].ttl = ttl3;
        hdr.mpls[2].bos = 0x1;
        meta.tunnel_metadata.tunnel_smac_index = smac_idx;
        meta.tunnel_metadata.tunnel_dmac_index = dmac_idx;
    }
    action cpu_rx_rewrite() {
        hdr.fabric_header.setValid();
        hdr.fabric_header.headerVersion = 0;
        hdr.fabric_header.packetVersion = 0;
        hdr.fabric_header.pad1 = 0;
        hdr.fabric_header.packetType = FABRIC_HEADER_TYPE_CPU;
        hdr.fabric_header_cpu.setValid();
        hdr.fabric_header_cpu.ingressPort = (bit<16>)meta.ingress_metadata.ingress_port;
        hdr.fabric_header_cpu.ingressIfindex = meta.ingress_metadata.ifindex;
        hdr.fabric_header_cpu.ingressBd = meta.ingress_metadata.bd;
        hdr.fabric_header_cpu.reasonCode = meta.fabric_metadata.reason_code;
        hdr.fabric_payload_header.setValid();
        hdr.fabric_payload_header.etherType = hdr.ethernet.etherType;
        hdr.ethernet.etherType = ETHERTYPE_BF_FABRIC;
    }

    action fabric_unicast_rewrite() {
        hdr.fabric_header.setValid();
        hdr.fabric_header.headerVersion = 0;
        hdr.fabric_header.packetVersion = 0;
        hdr.fabric_header.pad1 = 0;
        hdr.fabric_header.packetType = FABRIC_HEADER_TYPE_UNICAST;
        hdr.fabric_header.dstDevice = meta.fabric_metadata.dst_device;
        hdr.fabric_header.dstPortOrGroup = meta.fabric_metadata.dst_port;

        hdr.fabric_header_unicast.setValid();
        hdr.fabric_header_unicast.tunnelTerminate = meta.tunnel_metadata.tunnel_terminate;
        hdr.fabric_header_unicast.routed = meta.l3_metadata.routed;
        hdr.fabric_header_unicast.outerRouted = meta.l3_metadata.outer_routed;
        hdr.fabric_header_unicast.ingressTunnelType = meta.tunnel_metadata.ingress_tunnel_type;
        hdr.fabric_header_unicast.nexthopIndex = meta.l3_metadata.nexthop_index;
        hdr.fabric_payload_header.setValid();
        hdr.fabric_payload_header.etherType = hdr.ethernet.etherType;
        hdr.ethernet.etherType = ETHERTYPE_BF_FABRIC;
    }
    action fabric_multicast_rewrite(bit<16> fabric_mgid) {
        hdr.fabric_header.setValid();
        hdr.fabric_header.headerVersion = 0;
        hdr.fabric_header.packetVersion = 0;
        hdr.fabric_header.pad1 = 0;
        hdr.fabric_header.packetType = FABRIC_HEADER_TYPE_MULTICAST;
        hdr.fabric_header.dstDevice = FABRIC_DEVICE_MULTICAST;
        hdr.fabric_header.dstPortOrGroup = fabric_mgid;
        hdr.fabric_header_multicast.ingressIfindex = meta.ingress_metadata.ifindex;
        hdr.fabric_header_multicast.ingressBd = meta.ingress_metadata.bd;

        hdr.fabric_header_multicast.setValid();
        hdr.fabric_header_multicast.tunnelTerminate = meta.tunnel_metadata.tunnel_terminate;
        hdr.fabric_header_multicast.routed = meta.l3_metadata.routed;
        hdr.fabric_header_multicast.outerRouted = meta.l3_metadata.outer_routed;
        hdr.fabric_header_multicast.ingressTunnelType = meta.tunnel_metadata.ingress_tunnel_type;

        hdr.fabric_header_multicast.mcastGrp = meta.multicast_metadata.mcast_grp;

        hdr.fabric_payload_header.setValid();
        hdr.fabric_payload_header.etherType = hdr.ethernet.etherType;
        hdr.ethernet.etherType = ETHERTYPE_BF_FABRIC;
    }
    #endif /* MPLS_DISABLE */

    table tunnel_rewrite {
        key = {
            meta.tunnel_metadata.tunnel_index : exact;
        }
        actions = {
            nop;
            cpu_rx_rewrite;
    #if !defined(TUNNEL_DISABLE) || !defined(MIRROR_DISABLE)
            set_tunnel_rewrite_details;
    #endif /* !TUNNEL_DISABLE || !MIRROR_DISABLE*/
    #ifndef MPLS_DISABLE
            set_mpls_rewrite_push1;
            set_mpls_rewrite_push2;
            set_mpls_rewrite_push3;
    #endif /* MPLS_DISABLE */
    #ifdef FABRIC_ENABLE
            fabric_unicast_rewrite;
    #ifndef MULTICAST_DISABLE
            fabric_multicast_rewrite;
    #endif /* MULTICAST_DISABLE */
    #endif /* FABRIC_ENABLE */
        }
        size = TUNNEL_REWRITE_TABLE_SIZE;
    }


    #if !defined(TUNNEL_DISABLE) || !defined(MIRROR_DISABLE)
    /*****************************************************************************/
    /* Tunnel MTU check                                                          */
    /*****************************************************************************/
    action tunnel_mtu_check(bit<16> l3_mtu) {
        meta.l3_metadata.l3_mtu_check = l3_mtu - meta.egress_metadata.payload_length;
    }

    action tunnel_mtu_miss() {
        meta.l3_metadata.l3_mtu_check = 0xFFFF;
    }

    table tunnel_mtu {
        key = {
            meta.tunnel_metadata.tunnel_index : exact;
        }
        actions = {
            tunnel_mtu_check;
            tunnel_mtu_miss;
        }
        size = TUNNEL_REWRITE_TABLE_SIZE;
    }


    /*****************************************************************************/
    /* Tunnel source IP rewrite                                                  */
    /*****************************************************************************/
    action rewrite_tunnel_ipv4_src(bit<32> ip) {
        hdr.ipv4.srcAddr = ip;
    }

    #ifndef IPV6_DISABLE
    action rewrite_tunnel_ipv6_src(bit<128> ip) {
        hdr.ipv6.srcAddr = ip;
    }
    #endif /* IPV6_DISABLE */

    table tunnel_src_rewrite {
        key = {
            meta.tunnel_metadata.tunnel_src_index : exact;
        }
        actions = {
            nop;
            rewrite_tunnel_ipv4_src;
    #ifndef IPV6_DISABLE
            rewrite_tunnel_ipv6_src;
    #endif /* IPV6_DISABLE */
        }
        size = TUNNEL_SRC_REWRITE_TABLE_SIZE;
    }


    /*****************************************************************************/
    /* Tunnel destination IP rewrite                                             */
    /*****************************************************************************/
    action rewrite_tunnel_ipv4_dst(bit<32> ip) {
        hdr.ipv4.dstAddr = ip;
    }

    #ifndef IPV6_DISABLE
    action rewrite_tunnel_ipv6_dst(bit<128> ip) {
        hdr.ipv6.dstAddr = ip;
    }
    #endif /* IPV6_DISABLE */

    table tunnel_dst_rewrite {
        key = {
            meta.tunnel_metadata.tunnel_dst_index : exact;
        }
        actions = {
            nop;
            rewrite_tunnel_ipv4_dst;
    #ifndef IPV6_DISABLE
            rewrite_tunnel_ipv6_dst;
    #endif /* IPV6_DISABLE */
        }
        size = TUNNEL_DST_REWRITE_TABLE_SIZE;
    }

    action rewrite_tunnel_smac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }


    /*****************************************************************************/
    /* Tunnel source MAC rewrite                                                 */
    /*****************************************************************************/
    table tunnel_smac_rewrite {
        key = {
            meta.tunnel_metadata.tunnel_smac_index : exact;
        }
        actions = {
            nop;
            rewrite_tunnel_smac;
        }
        size = TUNNEL_SMAC_REWRITE_TABLE_SIZE;
    }


    /*****************************************************************************/
    /* Tunnel destination MAC rewrite                                            */
    /*****************************************************************************/
    action rewrite_tunnel_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }

    table tunnel_dmac_rewrite {
        key = {
            meta.tunnel_metadata.tunnel_dmac_index : exact;
        }
        actions = {
            nop;
            rewrite_tunnel_dmac;
        }
        size = TUNNEL_DMAC_REWRITE_TABLE_SIZE;
    }
    #endif /* !TUNNEL_DISABLE || !MIRROR_DISABLE*/

    apply{
        if ((meta.fabric_metadata.fabric_header_present == FALSE) &&
        (meta.tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE)) {
            /* derive egress vni from egress bd */
            egress_vni.apply();

            /* tunnel rewrites */
            if ((meta.tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_FABRIC) &&
                (meta.tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_CPU)) {
                tunnel_encap_process_inner.apply();
            }
            tunnel_encap_process_outer.apply();
            tunnel_rewrite.apply();
            tunnel_mtu.apply();

            /* rewrite tunnel src and dst ip */
            tunnel_src_rewrite.apply();
            tunnel_dst_rewrite.apply();

            /* rewrite tunnel src and dst ip */
            tunnel_smac_rewrite.apply();
            tunnel_dmac_rewrite.apply();
        }
    }
    
#endif /* TUNNEL_DISABLE */
}

#endif