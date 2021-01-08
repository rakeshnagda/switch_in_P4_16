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
 * Layer-3 processing
 */

/*
 * L3 Metadata
 */

/*****************************************************************************/
/* FIB hit actions for nexthops and ECMP                                     */
/*****************************************************************************/


control process_urpf_bd (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){
        
    }

#if !defined(L3_DISABLE) && !defined(URPF_DISABLE)
    /*****************************************************************************/
    /* uRPF BD check                                                             */
    /*****************************************************************************/
    action urpf_bd_miss() {
        meta.l3_metadata.urpf_check_fail= TRUE;
    }

    table urpf_bd {
        key = {
            meta.l3_metadata.urpf_bd_group : exact;
            meta.ingress_metadata.bd : exact;
        }
        actions = {
            nop;
            urpf_bd_miss;
        }
        size = URPF_GROUP_TABLE_SIZE;
    }
    apply{
        if ((meta.l3_metadata.urpf_mode == URPF_MODE_STRICT) && (meta.l3_metadata.urpf_hit == TRUE)) {
            urpf_bd.apply();
        }
    }
    
#endif /* L3_DISABLE && URPF_DISABLE */
}


/*****************************************************************************/
/* Egress L3 rewrite                                                         */
/*****************************************************************************/


#if !defined(L3_DISABLE)
control process_mac_rewrite (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }

    action rewrite_smac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }

    table smac_rewrite {
        key = {
            meta.egress_metadata.smac_idx : exact;
        }
        actions = {
            rewrite_smac;
        }
        size = MAC_REWRITE_TABLE_SIZE;
    }


    action ipv4_unicast_rewrite() {
        hdr.ethernet.dstAddr= meta.egress_metadata.mac_da;
        hdr.ipv4.ttl = 0xff;
    #ifndef QOS_DISABLE
        hdr.ipv4.diffserv= meta.l3_metadata.lkp_dscp;
    #endif /* QOS_DISABLE */
    }

    action ipv4_multicast_rewrite() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr | 0x01005E000000;
        hdr.ipv4.ttl = 0xff;
    #ifndef QOS_DISABLE
        hdr.ipv4.diffserv= meta.l3_metadata.lkp_dscp;
    #endif /* QOS_DISABLE */
    }

    action ipv6_unicast_rewrite() {
        hdr.ethernet.dstAddr= meta.egress_metadata.mac_da;
        hdr.ipv6.hopLimit = 0xff;
    #ifndef QOS_DISABLE
        hdr.ipv6.trafficClass= meta.l3_metadata.lkp_dscp;
    #endif /* QOS_DISABLE */
    }

    action ipv6_multicast_rewrite() {
        hdr.ethernet.dstAddr = hdr.ethernet.dstAddr | 0x333300000000;
        hdr.ipv6.hopLimit = 0xff;
    #ifndef QOS_DISABLE
        hdr.ipv6.trafficClass= meta.l3_metadata.lkp_dscp;
    #endif /* QOS_DISABLE */
    }

    action mpls_rewrite() {
        hdr.ethernet.dstAddr= meta.egress_metadata.mac_da;
        hdr.mpls[0].ttl = 0xff;
    }

    table l3_rewrite {
        key = {
            hdr.ipv4.isValid() : exact;
#ifndef IPV6_DISABLE
            hdr.ipv6.isValid() : exact;
#endif /* IPV6_DISABLE */
#ifndef MPLS_DISABLE
            hdr.mpls[0].isValid() : exact;
 #endif /* MPLS_DISABLE */
            hdr.ipv4.dstAddr & 0xF0000000 : ternary;
 #ifndef IPV6_DISABLE
            hdr.ipv6.dstAddr & 0xFF000000000000000000000000000000 : ternary;
#endif /* IPV6_DISABLE */
        }
        actions = {
            nop;
            ipv4_unicast_rewrite;
#ifndef L3_MULTICAST_DISABLE
            ipv4_multicast_rewrite;
#endif /* L3_MULTICAST_DISABLE */
#ifndef IPV6_DISABLE
            ipv6_unicast_rewrite;
#ifndef L3_MULTICAST_DISABLE
            ipv6_multicast_rewrite;
#endif /* L3_MULTICAST_DISABLE */
#endif /* IPV6_DISABLE */
#ifndef MPLS_DISABLE
            mpls_rewrite;
#endif /* MPLS_DISABLE */
        }
    }
    apply{
        if (meta.egress_metadata.routed == TRUE) {
            l3_rewrite.apply();
            smac_rewrite.apply();
        } 
    }
#endif /* L3_DISABLE */
}


/*****************************************************************************/
/* Egress MTU check                                                          */
/*****************************************************************************/
#if !defined(L3_DISABLE)

#endif /* L3_DISABLE */

control process_mtu(inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
#if !defined(L3_DISABLE)
    action ipv4_mtu_check(bit<16> l3_mtu) {
        meta.l3_metadata.l3_mtu_check = l3_mtu - hdr.ipv4.totalLen;
    }

    action ipv6_mtu_check(bit<16> l3_mtu) {
        meta.l3_metadata.l3_mtu_check = l3_mtu - hdr.ipv6.payloadLen;
    }

    action mtu_miss() {
        meta.l3_metadata.l3_mtu_check = 0xFFFF;
    }

    table mtu {
        key = {
            meta.l3_metadata.mtu_index : exact;
            hdr.ipv4.isValid() : exact;
            hdr.ipv6.isValid() : exact;
        }
        actions = {
            mtu_miss;
            ipv4_mtu_check;
            ipv6_mtu_check;
        }
        size = L3_MTU_TABLE_SIZE;
    }
    apply{
        mtu.apply();
    }
    
#endif /* L3_DISABLE */
}
