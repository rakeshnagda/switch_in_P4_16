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

#ifndef __FABRIC__
#define __FABRIC__

/*
 * Fabric processing for multi-device system
 */
    

/*****************************************************************************/
/* Ingress fabric header processing                                          */
/*****************************************************************************/
control process_ingress_fabric (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action nop(){

    }
    /*****************************************************************************/
    /* Fabric header - destination lookup                                        */
    /*****************************************************************************/
    action terminate_cpu_packet() {
        standard_metadata.egress_spec = (bit<9>)hdr.fabric_header.dstPortOrGroup;
        meta.egress_metadata.bypass = hdr.fabric_header_cpu.txBypass;
        meta.intrinsic_metadata.mcast_grp = hdr.fabric_header_cpu.mcast_grp;

        hdr.ethernet.etherType = hdr.fabric_payload_header.etherType;
        hdr.fabric_header.setInvalid();
        hdr.fabric_header_cpu.setInvalid();
        hdr.fabric_payload_header.setInvalid();
    }

#ifdef FABRIC_ENABLE
    action terminate_fabric_unicast_packet() {
        standard_metadata.egress_spec = (bit<9>)hdr.fabric_header.dstPortOrGroup;

        meta.tunnel_metadata.tunnel_terminate = hdr.fabric_header_unicast.tunnelTerminate;
        meta.tunnel_metadata.ingress_tunnel_type = hdr.fabric_header_unicast.ingressTunnelType;
        meta.l3_metadata.nexthop_index = hdr.fabric_header_unicast.nexthopIndex;
        meta.l3_metadata.routed = hdr.fabric_header_unicast.routed;
        meta.l3_metadata.outer_routed = hdr.fabric_header_unicast.outerRouted;

        hdr.ethernet.etherType = hdr.fabric_payload_header.etherType;
        hdr.fabric_header.setInvalid();
        hdr.fabric_header_unicast.setInvalid();
        hdr.fabric_payload_header.setInvalid();
    }

    action switch_fabric_unicast_packet() {
        meta.fabric_metadata.fabric_header_present = TRUE;
        meta.fabric_metadata.dst_device = hdr.fabric_header.dstDevice;
        meta.fabric_metadata.dst_port = hdr.fabric_header.dstPortOrGroup;
    }

#ifndef MULTICAST_DISABLE
    action terminate_fabric_multicast_packet() {
        meta.tunnel_metadata.tunnel_terminate = hdr.fabric_header_multicast.tunnelTerminate;
        meta.tunnel_metadata.ingress_tunnel_type = hdr.fabric_header_multicast.ingressTunnelType;
        meta.l3_metadata.nexthop_index = 0;
        meta.l3_metadata.routed = hdr.fabric_header_multicast.routed;
        meta.l3_metadata.outer_routed = hdr.fabric_header_multicast.outerRouted;

        meta.intrinsic_metadata.mcast_grp = hdr.fabric_header_multicast.mcastGrp;

        hdr.ethernet.etherType = hdr.fabric_payload_header.etherType;
        hdr.fabric_header.setInvalid();
        hdr.fabric_header_multicast.setInvalid();
        hdr.fabric_payload_header.setInvalid();
    }

    action switch_fabric_multicast_packet() {
        meta.fabric_metadata.fabric_header_present = TRUE;
        meta.intrinsic_metadata.mcast_grp = hdr.fabric_header.dstPortOrGroup;
    }
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */

    table fabric_ingress_dst_lkp {
        key = {
            hdr.fabric_header.dstDevice : exact;
        }
        actions = {
            nop;
            terminate_cpu_packet;
#ifdef FABRIC_ENABLE
            switch_fabric_unicast_packet;
            terminate_fabric_unicast_packet;
#ifndef MULTICAST_DISABLE
            switch_fabric_multicast_packet;
            terminate_fabric_multicast_packet;
#endif /* MULTICAST_DISABLE */
#endif /* FABRIC_ENABLE */
        }
    }

    /*****************************************************************************/
    /* Fabric header - source lookup                                             */
    /*****************************************************************************/
    #ifdef FABRIC_ENABLE
    action set_ingress_ifindex_properties() {
    }

    table fabric_ingress_src_lkp {
        key = {
            hdr.fabric_header_multicast.ingressIfindex : exact;
        }
        actions = {
            nop;
            set_ingress_ifindex_properties;
        }
        size = 1024;
    }
    #endif /* FABRIC_ENABLE */

    action non_ip_over_fabric() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.l2_metadata.lkp_mac_type = hdr.ethernet.etherType;
    }

    action ipv4_over_fabric() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv4_metadata.lkp_ipv4_sa = hdr.ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = hdr.ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv4.protocol;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }

    action ipv6_over_fabric() {
        meta.l2_metadata.lkp_mac_sa = hdr.ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.ethernet.dstAddr;
        meta.ipv6_metadata.lkp_ipv6_sa = hdr.ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = hdr.ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.ipv6.nextHdr;
        meta.l3_metadata.lkp_l4_sport = meta.l3_metadata.lkp_outer_l4_sport;
        meta.l3_metadata.lkp_l4_dport = meta.l3_metadata.lkp_outer_l4_dport;
    }

    table native_packet_over_fabric {
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
        }
        actions = {
            non_ip_over_fabric;
            ipv4_over_fabric;
    #ifndef IPV6_DISABLE
            ipv6_over_fabric;
    #endif /* IPV6_DISABLE */
        }
        size = 1024;
    }


    apply{
        if (meta.ingress_metadata.port_type != PORT_TYPE_NORMAL) {
            fabric_ingress_dst_lkp.apply();
#ifdef FABRIC_ENABLE
            if (meta.ingress_metadata.port_type == PORT_TYPE_FABRIC) {
                if (hdr.fabric_header_multicast.isValid()) {
                    fabric_ingress_src_lkp.apply();
                }
                if (meta.tunnel_metadata.tunnel_terminate == FALSE) {
                    native_packet_over_fabric.apply();
                }
#endif /* FABRIC_ENABLE */
            }        
        }
    }
    
}

/*****************************************************************************/
/* Fabric LAG resolution                                                     */
/*****************************************************************************/ 


control process_fabric_lag (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    action_selector(HashAlgorithm.identity, LAG_GROUP_TABLE_SIZE, LAG_BIT_WIDTH) act_selector;

    action nop(){

    }
#ifdef FABRIC_ENABLE
    action set_fabric_lag_port(bit<9>  port) {
        standard_metadata.egress_spec = port;
    }

#ifndef MULTICAST_DISABLE
    action set_fabric_multicast(bit<16> fabric_mgid) {
        meta.multicast_metadata.mcast_grp = meta.intrinsic_metadata.mcast_grp;

#ifdef FABRIC_NO_LOCAL_SWITCHING
        // no local switching, reset fields to send packet on fabric mgid
        meta.intrinsic_metadata.mcast_grp = fabric_mgid;
#endif /* FABRIC_NO_LOCAL_SWITCHING */
    }
#endif /* MULTICAST_DISABLE */


    table fabric_lag {
        key = {
            meta.hash_metadata.hash2 : selector;
            meta.fabric_metadata.dst_device : exact;
        }
        actions = {
            nop;
            set_fabric_lag_port;
#ifndef MULTICAST_DISABLE
            set_fabric_multicast;
#endif /* MULTICAST_DISABLE */
        }
        implementation = act_selector;
    }
#endif /* FABRIC_ENABLE */

    apply{
#ifdef FABRIC_ENABLE
        fabric_lag.apply();
#endif /* FABRIC_ENABLE */   
    }

}


/*****************************************************************************/
/* Fabric rewrite actions                                                    */
/*****************************************************************************/
 
#endif