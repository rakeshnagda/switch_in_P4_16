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

#ifndef __IPV6__
#define __IPV6__

/*
 * IPv6 processing
 */

/*
 * IPv6 Metadata
 */



/*****************************************************************************/
/* Validate outer IPv6 header                                                */
/*****************************************************************************/

control validate_outer_ipv6_header (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#if !defined(L3_DISABLE) && !defined(IPV6_DISABLE)
    action set_valid_outer_ipv6_packet() {
        meta.l3_metadata.lkp_ip_type = IPTYPE_IPV6;
        meta.l3_metadata.lkp_dscp = hdr.ipv6.trafficClass;
        meta.l3_metadata.lkp_ip_version = hdr.ipv6.version;
    }

    action set_malformed_outer_ipv6_packet(bit<8> drop_reason) {
        meta.ingress_metadata.drop_flag = TRUE;
        meta.ingress_metadata.drop_reason = drop_reason;
    }

    /*
     * Table: Validate ipv6 packet
     * Lookup: Ingress
     * Validate and extract ipv6 header
     */
    table validate_outer_ipv6_packet {
        key = {
            hdr.ipv6.version : ternary;
            hdr.ipv6.hopLimit : ternary;
            // TODO
            hdr.ipv6.srcAddr & 0xFFFF0000000000000000000000000000 : ternary;
        }
        actions = {
            set_valid_outer_ipv6_packet;
            set_malformed_outer_ipv6_packet;
        }
        size = VALIDATE_PACKET_TABLE_SIZE;
    }
    apply{
        validate_outer_ipv6_packet.apply();
    }
    
#endif /* L3_DISABLE && IPV6_DISABLE */
}

/*****************************************************************************/
/* IPv6 FIB lookup                                                           */
/*****************************************************************************/
control process_ipv6_fib (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#if !defined(L3_DISABLE) && !defined(IPV6_DISABLE)
    action on_miss() {
    }
    action fib_hit_nexthop(bit<16> nexthop_index) {
        meta.l3_metadata.fib_hit= TRUE;
        meta.l3_metadata.fib_nexthop= nexthop_index;
        meta.l3_metadata.fib_nexthop_type= NEXTHOP_TYPE_SIMPLE;
    }

    action fib_hit_ecmp(bit<16> ecmp_index) {
        meta.l3_metadata.fib_hit= TRUE;
        meta.l3_metadata.fib_nexthop= ecmp_index;
        meta.l3_metadata.fib_nexthop_type= NEXTHOP_TYPE_ECMP;
    }
    /*
     * Actions are defined in l3.p4 since they are
     * common for both ipv4 and ipv6
     */

    /*
     * Table: Ipv6 LPM Lookup
     * Lookup: Ingress
     * Ipv6 route lookup for longest prefix match entries
     */
    table ipv6_fib_lpm {
        key = {
            meta.l3_metadata.vrf : exact;
            meta.ipv6_metadata.lkp_ipv6_da : lpm;
        }
        actions = {
            on_miss;
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        size = IPV6_LPM_TABLE_SIZE;
    }

    /*
     * Table: Ipv6 Host Lookup
     * Lookup: Ingress
     * Ipv6 route lookup for /128 entries
     */
    table ipv6_fib {
        key = {
            meta.l3_metadata.vrf : exact;
            meta.ipv6_metadata.lkp_ipv6_da : exact;
        }
        actions = {
            on_miss;
            fib_hit_nexthop;
            fib_hit_ecmp;
        }
        size = IPV6_HOST_TABLE_SIZE;
    }
    /* fib lookup */
    apply{
        switch(ipv6_fib.apply().action_run){
            on_miss:{
                ipv6_fib_lpm.apply();
            }
        }
    }

#endif /* L3_DISABLE && IPV6_DISABLE */
}

/*****************************************************************************/
/* IPv6 uRPF lookup                                                          */
/*****************************************************************************/

control process_ipv6_urpf (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#if !defined(L3_DISABLE) && !defined(IPV6_DISABLE) && !defined(URPF_DISABLE)
    action on_miss() {
    }
    action urpf_miss() {
        meta.l3_metadata.urpf_check_fail= TRUE;
    }
    action ipv6_urpf_hit(bit<BD_BIT_WIDTH> urpf_bd_group) {
        meta.l3_metadata.urpf_hit = TRUE;
        meta.l3_metadata.urpf_bd_group = urpf_bd_group;
        meta.l3_metadata.urpf_mode = meta.ipv6_metadata.ipv6_urpf_mode;
    }

    table ipv6_urpf_lpm {
        key = {
            meta.l3_metadata.vrf : exact;
            meta.ipv6_metadata.lkp_ipv6_sa : lpm;
        }
        actions = {
            ipv6_urpf_hit;
            urpf_miss;
        }
        size = IPV6_LPM_TABLE_SIZE;
    }

    table ipv6_urpf {
        key = {
            meta.l3_metadata.vrf : exact;
            meta.ipv6_metadata.lkp_ipv6_sa : exact;
        }
        actions = {
            on_miss;
            ipv6_urpf_hit;
        }
        size = IPV6_HOST_TABLE_SIZE;
    }

    /* unicast rpf lookup */
    apply{
        if (meta.ipv6_metadata.ipv6_urpf_mode != URPF_MODE_NONE) {
            switch(ipv6_urpf.apply().action_run){
                on_miss:{
                    ipv6_urpf_lpm.apply();
                }
            }
        }
    }
    
#endif /* L3_DISABLE && IPV6_DISABLE && URPF_DISABLE */
}

#endif