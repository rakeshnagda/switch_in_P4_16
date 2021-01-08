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
 * ACL processing : MAC, IPv4, IPv6, RACL/PBR
 */

/*
 * ACL metadata
 */


/*****************************************************************************/
/* Egress ACL l4 port range                                                  */
/*****************************************************************************/
    

control process_egress_l4port (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }

#ifdef EGRESS_ACL_ENABLE
    action set_egress_tcp_port_fields() {
        meta.l3_metadata.egress_l4_sport = hdr.tcp.srcPort;
        meta.l3_metadata.egress_l4_dport = hdr.tcp.dstPort;
    }

    action set_egress_udp_port_fields() {
        meta.l3_metadata.egress_l4_sport = hdr.udp.srcPort;
        meta.l3_metadata.egress_l4_dport = hdr.udp.dstPort;
    }

    action set_egress_icmp_port_fields() {
        meta.l3_metadata.egress_l4_sport = hdr.icmp.typeCode;
    }

    table egress_l4port_fields {
        key = {
            hdr.tcp.isValid() : exact;
            hdr.udp.isValid() : exact;
            hdr.icmp.isValid() : exact;
        }
        actions = {
            nop;
            set_egress_tcp_port_fields;
            set_egress_udp_port_fields;
            set_egress_icmp_port_fields;
        }
        size = EGRESS_PORT_LKP_FIELD_SIZE;
    }

    #ifndef ACL_RANGE_DISABLE
    action set_egress_src_port_range_id(bit<8> range_id) {
        meta.acl_metadata.egress_src_port_range_id = range_id;
    }

    table egress_l4_src_port {
        key = {
            meta.l3_metadata.egress_l4_sport : range;
        }
        actions = {
            nop;
            set_egress_src_port_range_id;
        }
        size = EGRESS_ACL_RANGE_TABLE_SIZE;
    }

    action set_egress_dst_port_range_id(bit<8> range_id) {
        meta.acl_metadata.egress_dst_port_range_id = range_id;
    }

    table egress_l4_dst_port {
        key = {
            meta.l3_metadata.egress_l4_dport : range;
        }
        actions = {
            nop;
            set_egress_dst_port_range_id;
        }
        size = EGRESS_ACL_RANGE_TABLE_SIZE;
    }

    #endif /* ACL_RANGE_DISABLE */
    #endif /* EGRESS_ACL_ENABLE */    
    apply{
        #ifdef EGRESS_ACL_ENABLE
        egress_l4port_fields.apply();
    #ifndef ACL_RANGE_DISABLE
        egress_l4_src_port.apply();
        egress_l4_dst_port.apply();
    #endif /* ACL_RANGE_DISABLE */
    #endif /* EGRESS_ACL_ENABLE */
    }

}

/*****************************************************************************/
/* Ingress ACL l4 port range                                                 */
/*****************************************************************************/


control process_ingress_l4port (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
#ifndef ACL_RANGE_DISABLE
    action set_ingress_src_port_range_id(bit<8> range_id) {
        meta.acl_metadata.ingress_src_port_range_id = range_id;
    }

    table ingress_l4_src_port {
        key = {
            meta.l3_metadata.lkp_l4_sport : range;
        }
        actions = {
            nop;
            set_ingress_src_port_range_id;
        }
        size = INGRESS_ACL_RANGE_TABLE_SIZE;
    }

    action set_ingress_dst_port_range_id(bit<8> range_id) {
        meta.acl_metadata.ingress_dst_port_range_id = range_id;
    }

    table ingress_l4_dst_port {
        key = {
            meta.l3_metadata.lkp_l4_dport : range;
        }
        actions = {
            nop;
            set_ingress_dst_port_range_id;
        }
        size = INGRESS_ACL_RANGE_TABLE_SIZE;
    }
    apply{
        ingress_l4_src_port.apply();
        ingress_l4_dst_port.apply(); 
    }
    
#endif /* ACL_RANGE_DISABLE */
}

/*****************************************************************************/
/* ACL Actions                                                               */
/*****************************************************************************/
    

control process_mac_acl (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
#ifndef L2_DISABLE
    
    action acl_deny(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason,
                    bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_deny = TRUE;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */

    }

    action acl_permit(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason,
                      bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }


    action acl_mirror(bit<32> session_id, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<2> nat_mode,
                      bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.i2e_metadata.mirror_session_id = (bit<16>)session_id;

        clone3(CloneType.I2E, (bit<32>)session_id, {
                                        meta.i2e_metadata.ingress_tstamp,
                                        meta.i2e_metadata.mirror_session_id
                                    });

        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action acl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index, bit<16> acl_meter_index,
                                bit<16> acl_copy_reason, bit<2> nat_mode,
                                bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = TRUE;
        meta.acl_metadata.acl_nexthop = nexthop_index;
        meta.acl_metadata.acl_nexthop_type = NEXTHOP_TYPE_SIMPLE;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action acl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index, bit<16> acl_meter_index,
                             bit<16> acl_copy_reason, bit<2> nat_mode,
                             bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = TRUE;
        meta.acl_metadata.acl_nexthop = ecmp_index;
        meta.acl_metadata.acl_nexthop_type = NEXTHOP_TYPE_ECMP;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }



    /*****************************************************************************/
    /* MAC ACL                                                                   */
    /*****************************************************************************/
    #ifndef L2_DISABLE
    table mac_acl {
        key = {
            meta.acl_metadata.if_label : ternary;
            meta.acl_metadata.bd_label : ternary;

            meta.l2_metadata.lkp_mac_sa : ternary;
            meta.l2_metadata.lkp_mac_da : ternary;
            meta.l2_metadata.lkp_mac_type : ternary;
        }
        actions = {
            nop;
            acl_deny;
            acl_permit;
            acl_redirect_nexthop;
            acl_redirect_ecmp;
    #ifndef MIRROR_DISABLE
            acl_mirror;
    #endif /* MIRROR_DISABLE */
        }
        size = INGRESS_MAC_ACL_TABLE_SIZE;
    }
    #endif /* L2_DISABLE */

    apply{
        if (DO_LOOKUP(ACL)) {
            mac_acl.apply();
        }
    }
    
#endif /* L2_DISABLE */
}

    


/*****************************************************************************/
/* ACL Control flow                                                          */
/*****************************************************************************/
control process_ip_acl (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    action acl_deny(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason,
                    bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_deny = TRUE;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */

    }

    action acl_permit(bit<14> acl_stats_index, bit<16> acl_meter_index, bit<16> acl_copy_reason,
                      bit<2> nat_mode, bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }


    action acl_mirror(bit<32> session_id, bit<14> acl_stats_index, bit<16> acl_meter_index, bit<2> nat_mode,
                      bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.i2e_metadata.mirror_session_id = (bit<16>)session_id;
        clone3(CloneType.I2E, (bit<32>)session_id, {
                                        meta.i2e_metadata.ingress_tstamp,
                                        meta.i2e_metadata.mirror_session_id
                                    });

        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action acl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index, bit<16> acl_meter_index,
                                bit<16> acl_copy_reason, bit<2> nat_mode,
                                bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = TRUE;
        meta.acl_metadata.acl_nexthop = nexthop_index;
        meta.acl_metadata.acl_nexthop_type = NEXTHOP_TYPE_SIMPLE;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action acl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index, bit<16> acl_meter_index,
                             bit<16> acl_copy_reason, bit<2> nat_mode,
                             bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_redirect = TRUE;
        meta.acl_metadata.acl_nexthop = ecmp_index;
        meta.acl_metadata.acl_nexthop_type = NEXTHOP_TYPE_ECMP;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.meter_metadata.meter_index = acl_meter_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
        meta.nat_metadata.ingress_nat_mode = nat_mode;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    /*****************************************************************************/
    /* IPv4 ACL                                                                  */
    /*****************************************************************************/
    #ifndef IPV4_DISABLE
    table ip_acl {
        key = {
            meta.acl_metadata.if_label : ternary;
            meta.acl_metadata.bd_label : ternary;

            meta.ipv4_metadata.lkp_ipv4_sa : ternary;
            meta.ipv4_metadata.lkp_ipv4_da : ternary;
            meta.l3_metadata.lkp_ip_proto : ternary;
            meta.acl_metadata.ingress_src_port_range_id : exact;
            meta.acl_metadata.ingress_dst_port_range_id : exact;

            hdr.tcp.flags : ternary;
            meta.l3_metadata.lkp_ip_ttl : ternary;
        }
        actions = {
            nop;
            acl_deny;
            acl_permit;
            acl_redirect_nexthop;
            acl_redirect_ecmp;
    #ifndef MIRROR_DISABLE
            acl_mirror;
    #endif /* MIRROR_DISABLE */
        }
        size = INGRESS_IP_ACL_TABLE_SIZE;
    }
    #endif /* IPV4_DISABLE */


    /*****************************************************************************/
    /* IPv6 ACL                                                                  */
    /*****************************************************************************/
    #ifndef IPV6_DISABLE
    table ipv6_acl {
        key = {
            meta.acl_metadata.if_label : ternary;
            meta.acl_metadata.bd_label : ternary;

            meta.ipv6_metadata.lkp_ipv6_sa : ternary;
            meta.ipv6_metadata.lkp_ipv6_da : ternary;
            meta.l3_metadata.lkp_ip_proto : ternary;
            meta.acl_metadata.ingress_src_port_range_id : exact;
            meta.acl_metadata.ingress_dst_port_range_id : exact;

            hdr.tcp.flags : ternary;
            meta.l3_metadata.lkp_ip_ttl : ternary;
        }
        actions = {
            nop;
            acl_deny;
            acl_permit;
            acl_redirect_nexthop;
            acl_redirect_ecmp;
    #ifndef MIRROR_DISABLE
            acl_mirror;
    #endif /* MIRROR_DISABLE */
        }
        size = INGRESS_IPV6_ACL_TABLE_SIZE;
    }
    #endif /* IPV6_DISABLE */


    apply{
        if (DO_LOOKUP(ACL)) {
                if (meta.l3_metadata.lkp_ip_type == IPTYPE_IPV4) {
#ifndef IPV4_DISABLE
                    ip_acl.apply();
#endif /* IPV4_DISABLE */
                } 
                else {
                    if (meta.l3_metadata.lkp_ip_type == IPTYPE_IPV6) {
#ifndef IPV6_DISABLE
                        ipv6_acl.apply();
#endif /* IPV6_DISABLE */
                    }
                }
            }        
    }
    
}

    

control process_ipv4_racl (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
#ifndef IPV4_DISABLE
    /*****************************************************************************/
    /* RACL actions                                                              */
    /*****************************************************************************/
    action racl_deny(bit<14> acl_stats_index, bit<16> acl_copy_reason,
                     bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_deny = TRUE;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action racl_permit(bit<14> acl_stats_index, bit<16> acl_copy_reason,
                       bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action racl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index,
                                 bit<16> acl_copy_reason,
                                 bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_redirect = TRUE;
        meta.acl_metadata.racl_nexthop = nexthop_index;
        meta.acl_metadata.racl_nexthop_type = NEXTHOP_TYPE_SIMPLE;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action racl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index,
                              bit<16> acl_copy_reason,
                              bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_redirect = TRUE;
        meta.acl_metadata.racl_nexthop = ecmp_index;
        meta.acl_metadata.racl_nexthop_type = NEXTHOP_TYPE_ECMP;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }


    /*****************************************************************************/
    /* IPv4 RACL                                                                 */
    /*****************************************************************************/
    #ifndef IPV4_DISABLE
    table ipv4_racl {
        key = {
            meta.acl_metadata.bd_label : ternary;

            meta.ipv4_metadata.lkp_ipv4_sa : ternary;
            meta.ipv4_metadata.lkp_ipv4_da : ternary;
            meta.l3_metadata.lkp_ip_proto : ternary;
            meta.acl_metadata.ingress_src_port_range_id : exact;
            meta.acl_metadata.ingress_dst_port_range_id : exact;
        }
        actions = {
            nop;
            racl_deny;
            racl_permit;
            racl_redirect_nexthop;
            racl_redirect_ecmp;
        }
        size = INGRESS_IP_RACL_TABLE_SIZE;
    }
    #endif /* IPV4_DISABLE */

    apply{
        ipv4_racl.apply();
    }
    
#endif /* IPV4_DISABLE */
}

    

control process_ipv6_racl (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
#ifndef IPV6_DISABLE
    /*****************************************************************************/
    /* RACL actions                                                              */
    /*****************************************************************************/
    action racl_deny(bit<14> acl_stats_index, bit<16> acl_copy_reason,
                     bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_deny = TRUE;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action racl_permit(bit<14> acl_stats_index, bit<16> acl_copy_reason,
                       bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action racl_redirect_nexthop(bit<16> nexthop_index, bit<14> acl_stats_index,
                                 bit<16> acl_copy_reason,
                                 bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_redirect = TRUE;
        meta.acl_metadata.racl_nexthop = nexthop_index;
        meta.acl_metadata.racl_nexthop_type = NEXTHOP_TYPE_SIMPLE;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }

    action racl_redirect_ecmp(bit<16> ecmp_index, bit<14> acl_stats_index,
                              bit<16> acl_copy_reason,
                              bit<3> ingress_cos, bit<8> tc, bit<2> color) {
        meta.acl_metadata.racl_redirect = TRUE;
        meta.acl_metadata.racl_nexthop = ecmp_index;
        meta.acl_metadata.racl_nexthop_type = NEXTHOP_TYPE_ECMP;
        meta.acl_metadata.acl_stats_index = acl_stats_index;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    #ifndef QOS_DISABLE
        meta.intrinsic_metadata.ingress_cos = ingress_cos;
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    #endif /* QOS_DISABLE */
    }
    /*****************************************************************************/
    /* IPv6 RACL                                                                 */
    /*****************************************************************************/
    #ifndef IPV6_DISABLE
    table ipv6_racl {
        key = {
            meta.acl_metadata.bd_label : ternary;

            meta.ipv6_metadata.lkp_ipv6_sa : ternary;
            meta.ipv6_metadata.lkp_ipv6_da : ternary;
            meta.l3_metadata.lkp_ip_proto : ternary;
            meta.acl_metadata.ingress_src_port_range_id : exact;
            meta.acl_metadata.ingress_dst_port_range_id : exact;
        }
        actions = {
            nop;
            racl_deny;
            racl_permit;
            racl_redirect_nexthop;
            racl_redirect_ecmp;
        }
        size = INGRESS_IPV6_RACL_TABLE_SIZE;
    }
    #endif /* IPV6_DISABLE */

    apply{
        ipv6_racl.apply();
    }
    
#endif /* IPV6_DISABLE */
}

/*****************************************************************************/
/* ACL stats                                                                 */
/*****************************************************************************/
#ifndef STATS_DISABLE

counter(ACL_STATS_TABLE_SIZE, CounterType.packets_and_bytes) acl_stats_counter;

    
#endif /* STATS_DISABLE */

control process_ingress_acl_stats (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#ifndef STATS_DISABLE
    action acl_stats_update() {
        acl_stats_counter.count((bit<32>)meta.acl_metadata.acl_stats_index);
    }

    table acl_stats {
        actions = {
            acl_stats_update;
        }
        // size = ACL_STATS_TABLE_SIZE;
    }

    apply{
        acl_stats.apply();
    }
    
#endif /* STATS_DISABLE */
}

/*****************************************************************************/
/* CoPP                                                                      */
/*****************************************************************************/


/*****************************************************************************/
/* System ACL                                                                */
/*****************************************************************************/
    

control process_system_acl(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    counter(DROP_STATS_TABLE_SIZE, CounterType.packets) drop_stats_counter;
    counter(DROP_STATS_TABLE_SIZE, CounterType.packets) drop_stats_2_counter;
    meter(COPP_TABLE_SIZE, MeterType.bytes) copp;

    action nop(){

    }

    action negative_mirror(bit<32> session_id) {
#ifndef __TARGET_BMV2__
        clone3(CloneType.I2E, (bit<32>)session_id, {
                                        meta.ingress_metadata.ifindex;
                                        meta.ingress_metadata.drop_reason;
                                            });
#endif
        mark_to_drop(standard_metadata);
    }

    action copy_to_cpu(bit<5> qid, bit<32> meter_id, bit<3> icos) {
        meta.intrinsic_metadata.qid = qid;
        meta.intrinsic_metadata.ingress_cos = icos; 
        clone3(CloneType.I2E, CPU_MIRROR_SESSION_ID, {
                                                        meta.ingress_metadata.bd,
                                                        meta.ingress_metadata.ifindex,
                                                        meta.fabric_metadata.reason_code,
                                                        meta.ingress_metadata.ingress_port,
                                                    #ifdef __TARGET_BMV2__
                                                        standard_metadata.instance_type
                                                    #endif
                                                    });

        copp.execute_meter(meter_id, meta.intrinsic_metadata.packet_color);
    }

    action copy_to_cpu_with_reason(bit<16> reason_code, bit<5> qid, bit<32> meter_id, bit<3> icos) {
        meta.fabric_metadata.reason_code = reason_code;
        copy_to_cpu(qid, meter_id, icos);
    }

    action redirect_to_cpu_with_reason(bit<16> reason_code, bit<5> qid, bit<32> meter_id, bit<3> icos) {
        copy_to_cpu_with_reason(reason_code, qid, meter_id, icos);
        mark_to_drop(standard_metadata);
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
    #endif /* FABRIC_ENABLE */
    }

    action redirect_to_cpu(bit<5> qid, bit<32> meter_id, bit<3> icos) {
        copy_to_cpu(qid, meter_id, icos);
        mark_to_drop(standard_metadata);
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
    #endif /* FABRIC_ENABLE */
    }

    action drop_packet() {
        mark_to_drop(standard_metadata);
    }

    action drop_packet_with_reason(bit<8> drop_reason) {
        drop_stats_counter.count((bit<32>)drop_reason);
        mark_to_drop(standard_metadata);
    }

    table system_acl {
        key = {
            meta.acl_metadata.if_label : ternary;
            meta.acl_metadata.bd_label : ternary;

            meta.ingress_metadata.ifindex : ternary;

            /* drop reasons */
            meta.l2_metadata.lkp_mac_type : ternary;
            meta.l2_metadata.port_vlan_mapping_miss : ternary;
            meta.security_metadata.ipsg_check_fail : ternary;
            meta.acl_metadata.acl_deny : ternary;
            meta.acl_metadata.racl_deny: ternary;
            meta.l3_metadata.urpf_check_fail : ternary;
            meta.ingress_metadata.drop_flag : ternary;

            meta.l3_metadata.l3_copy : ternary;

            meta.l3_metadata.rmac_hit : ternary;

            /*
             * other checks, routed link_local packet, l3 same if check,
             * expired ttl
             */
            meta.l3_metadata.routed : ternary;
            meta.ipv6_metadata.ipv6_src_is_link_local : ternary;
            meta.l2_metadata.same_if_check : ternary;
            meta.tunnel_metadata.tunnel_if_check : ternary;
            meta.l3_metadata.same_bd_check : ternary;
            meta.l3_metadata.lkp_ip_ttl : ternary;
            meta.l2_metadata.stp_state : ternary;
            meta.ingress_metadata.control_frame: ternary;
            meta.ipv4_metadata.ipv4_unicast_enabled : ternary;
            meta.ipv6_metadata.ipv6_unicast_enabled : ternary;

            /* egress information */
            meta.ingress_metadata.egress_ifindex : ternary;

            meta.fabric_metadata.reason_code : ternary;

        }
        actions = {
            nop;
            redirect_to_cpu;
            redirect_to_cpu_with_reason;
            copy_to_cpu;
            copy_to_cpu_with_reason;
            drop_packet;
            drop_packet_with_reason;
            negative_mirror;
        }
        size = SYSTEM_ACL_SIZE;
    }

    action drop_stats_update() {
        drop_stats_2_counter.count((bit<32>)meta.ingress_metadata.drop_reason);
    }

    table drop_stats {
        actions = {
            drop_stats_update;
        }
        // size = DROP_STATS_TABLE_SIZE;
    }

    apply{
        if (DO_LOOKUP(SYSTEM_ACL)) {
            system_acl.apply();
            if (meta.ingress_metadata.drop_flag == TRUE) {
                drop_stats.apply();
            }
        }        
    }
    
}

/*****************************************************************************/
/* Egress ACL                                                                */
/*****************************************************************************/


control process_egress_acl (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }

#ifdef EGRESS_ACL_ENABLE
    /*****************************************************************************/
    /* Egress ACL Actions                                                        */
    /*****************************************************************************/
    action egress_acl_deny(bit<16> acl_copy_reason) {
        meta.acl_metadata.acl_deny = TRUE;
        meta.fabric_metadata.reason_code = acl_copy_reason;
    }

    action egress_acl_permit(bit<16> acl_copy_reason) {
        meta.fabric_metadata.reason_code = acl_copy_reason;
    }

    /*****************************************************************************/
    /* Egress Mac ACL                                                            */
    /*****************************************************************************/

    #ifndef L2_DISABLE
    table egress_mac_acl {
        key = {
            meta.acl_metadata.egress_if_label : ternary;
            meta.acl_metadata.egress_bd_label : ternary;

            hdr.ethernet.srcAddr : ternary;
            hdr.ethernet.dstAddr : ternary;
            hdr.ethernet.etherType: ternary;
        }
        actions = {
            nop;
            egress_acl_deny;
            egress_acl_permit;
        }
        size = EGRESS_MAC_ACL_TABLE_SIZE;
    }
    #endif /* L2_DISABLE */

    /*****************************************************************************/
    /* Egress IPv4 ACL                                                           */
    /*****************************************************************************/
    #ifndef IPV4_DISABLE
    table egress_ip_acl {
        key = {
            meta.acl_metadata.egress_if_label : ternary;
            meta.acl_metadata.egress_bd_label : ternary;

            hdr.ipv4.srcAddr : ternary;
            hdr.ipv4.dstAddr : ternary;
            hdr.ipv4.protocol : ternary;
            meta.acl_metadata.egress_src_port_range_id : exact;
            meta.acl_metadata.egress_dst_port_range_id : exact;
        }
        actions = {
            nop;
            egress_acl_deny;
            egress_acl_permit;
        }
        size = EGRESS_IP_ACL_TABLE_SIZE;
    }
    #endif /* IPV4_DISABLE */

    /*****************************************************************************/
    /* Egress IPv6 ACL                                                           */
    /*****************************************************************************/
    #ifndef IPV6_DISABLE
    table egress_ipv6_acl {
        key = {
            meta.acl_metadata.egress_if_label : ternary;
            meta.acl_metadata.egress_bd_label : ternary;

            hdr.ipv6.srcAddr : ternary;
            hdr.ipv6.dstAddr : ternary;
            hdr.ipv6.nextHdr : ternary;
            meta.acl_metadata.egress_src_port_range_id : exact;
            meta.acl_metadata.egress_dst_port_range_id : exact;
        }
        actions = {
            nop;
            egress_acl_deny;
            egress_acl_permit;
        }
        size = EGRESS_IPV6_ACL_TABLE_SIZE;
    }

    #endif /* IPV6_DISABLE */


    apply{
        if (hdr.ipv4.isValid()) {
#ifndef IPV4_DISABLE
            egress_ip_acl.apply();
#endif /* IPV4_DISABLE */
        } 
        else {
            if (hdr.ipv6.isValid()) {
#ifndef IPV6_DISABLE
                egress_ipv6_acl.apply();
#endif /* IPV6_DISABLE */
            } 
            else {
                egress_mac_acl.apply();
            }
        }        
    }
    
#endif /* EGRESS_ACL_ENABLE */
}

    

control process_egress_system_acl (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }

    action drop_packet() {
        mark_to_drop(standard_metadata);
    }
    
    action egress_mirror(bit<32> session_id) {
        meta.i2e_metadata.mirror_session_id = (bit<16>)session_id;
        clone3(CloneType.E2E, (bit<32>)session_id, {
                                        meta.i2e_metadata.ingress_tstamp,
                                        meta.i2e_metadata.mirror_session_id
                                    });
    }

    action egress_mirror_drop(bit<32> session_id) {
        egress_mirror(session_id);
        mark_to_drop(standard_metadata);
    }

    action egress_copy_to_cpu() {
        clone3(CloneType.E2E, CPU_MIRROR_SESSION_ID, 
                                    {
                                        meta.ingress_metadata.bd,
                                        meta.ingress_metadata.ifindex,
                                        meta.fabric_metadata.reason_code,
                                        meta.ingress_metadata.ingress_port,
                                    #ifdef __TARGET_BMV2__
                                        standard_metadata.instance_type
                                    #endif
                                    });
    }

    action egress_redirect_to_cpu() {
        egress_copy_to_cpu();
        mark_to_drop(standard_metadata);
    }

    action egress_copy_to_cpu_with_reason(bit<16> reason_code) {
        meta.fabric_metadata.reason_code = reason_code;
        egress_copy_to_cpu();
    }

    action egress_redirect_to_cpu_with_reason(bit<16> reason_code) {
        egress_copy_to_cpu_with_reason(reason_code);
        mark_to_drop(standard_metadata);
    }
    table egress_system_acl {
        key = {
            meta.fabric_metadata.reason_code : ternary;
            standard_metadata.egress_port : ternary;
            meta.intrinsic_metadata.deflection_flag : ternary;
            meta.l3_metadata.l3_mtu_check : ternary;
            meta.acl_metadata.acl_deny : ternary;
        }
        actions = {
            nop;
            drop_packet;
            egress_copy_to_cpu;
            egress_redirect_to_cpu;
            egress_copy_to_cpu_with_reason;
            egress_redirect_to_cpu_with_reason;
            egress_mirror;
            egress_mirror_drop;
        }
        size = EGRESS_ACL_TABLE_SIZE;
    }

    apply{
       if (meta.egress_metadata.bypass == FALSE) {
            egress_system_acl.apply();
        } 
    }
    
}
