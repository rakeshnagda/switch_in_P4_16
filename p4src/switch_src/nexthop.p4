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
 * Nexthop related processing
 */

/*
 * nexthop metadata
 */


/*****************************************************************************/
/* Forwarding result lookup and decisions                                    */
/*****************************************************************************/
    

control process_fwd_results  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    action set_l2_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.l2_metadata.l2_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.l2_metadata.l2_nexthop_type;
        meta.ingress_metadata.egress_ifindex = 0;
        meta.intrinsic_metadata.mcast_grp = 0;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
    #endif /* FABRIC_ENABLE */
    }

    action set_acl_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.acl_metadata.acl_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.acl_metadata.acl_nexthop_type;
        meta.ingress_metadata.egress_ifindex = 0;
        meta.intrinsic_metadata.mcast_grp = 0;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
    #endif /* FABRIC_ENABLE */
    }

    action set_racl_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.acl_metadata.racl_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.acl_metadata.racl_nexthop_type;
        meta.l3_metadata.routed = TRUE;
        meta.ingress_metadata.egress_ifindex = 0;
        meta.intrinsic_metadata.mcast_grp = 0;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
    #endif /* FABRIC_ENABLE */
    }

    action set_fib_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.l3_metadata.fib_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.l3_metadata.fib_nexthop_type;
        meta.l3_metadata.routed = TRUE;
        meta.intrinsic_metadata.mcast_grp = 0;
        /* set the reason code incase packet is redirected to cpu */
        meta.fabric_metadata.reason_code = CPU_REASON_CODE_L3_REDIRECT;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
    #endif /* FABRIC_ENABLE */
    }

    action set_nat_redirect_action() {
        meta.l3_metadata.nexthop_index = meta.nat_metadata.nat_nexthop;
        meta.nexthop_metadata.nexthop_type = meta.nat_metadata.nat_nexthop_type;
        meta.l3_metadata.routed = TRUE;
        meta.intrinsic_metadata.mcast_grp = 0;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
    #endif /* FABRIC_ENABLE */
    }

    action set_cpu_redirect_action() {
        meta.l3_metadata.routed = FALSE;
        meta.intrinsic_metadata.mcast_grp = 0;
        standard_metadata.egress_spec = CPU_PORT_ID;
        meta.ingress_metadata.egress_ifindex = 0;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = 0;
    #endif /* FABRIC_ENABLE */
    }

    action set_multicast_route_action() {
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
    #endif /* FABRIC_ENABLE */
        meta.ingress_metadata.egress_ifindex = 0;
        meta.intrinsic_metadata.mcast_grp = meta.multicast_metadata.multicast_route_mc_index;
        meta.l3_metadata.routed = TRUE;
        meta.l3_metadata.same_bd_check = 0xFFFF;
    }

    action set_multicast_bridge_action() {
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
    #endif /* FABRIC_ENABLE */
        meta.ingress_metadata.egress_ifindex = 0;
        meta.intrinsic_metadata.mcast_grp = meta.multicast_metadata.multicast_bridge_mc_index;
    }

    action set_multicast_flood() {
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
    #endif /* FABRIC_ENABLE */
        meta.ingress_metadata.egress_ifindex = IFINDEX_FLOOD;
    }

    action set_multicast_drop() {
        meta.ingress_metadata.drop_flag = TRUE;
        meta.ingress_metadata.drop_reason = DROP_MULTICAST_SNOOPING_ENABLED;
    }

    table fwd_result {
        key = {
            meta.l2_metadata.l2_redirect : ternary;
            meta.acl_metadata.acl_redirect : ternary;
            meta.acl_metadata.racl_redirect : ternary;
            meta.l3_metadata.rmac_hit : ternary;
            meta.l3_metadata.fib_hit : ternary;
            meta.nat_metadata.nat_hit : ternary;
            meta.l2_metadata.lkp_pkt_type : ternary;
            meta.l3_metadata.lkp_ip_type : ternary;
            meta.multicast_metadata.igmp_snooping_enabled : ternary;
            meta.multicast_metadata.mld_snooping_enabled : ternary;
            meta.multicast_metadata.mcast_route_hit : ternary;
            meta.multicast_metadata.mcast_bridge_hit : ternary;
            meta.multicast_metadata.mcast_rpf_group : ternary;
            meta.multicast_metadata.mcast_mode : ternary;
        }
        actions = {
            nop;
            set_l2_redirect_action;
            set_fib_redirect_action;
            set_cpu_redirect_action;
            set_acl_redirect_action;
            set_racl_redirect_action;
    #ifndef NAT_DISABLE
            set_nat_redirect_action;
    #endif /* NAT_DISABLE */
    #ifndef MULTICAST_DISABLE
            set_multicast_route_action;
            set_multicast_bridge_action;
            set_multicast_flood;
            set_multicast_drop;
    #endif /* MULTICAST_DISABLE */
        }
        size = FWD_RESULT_TABLE_SIZE;
    }

    apply{
        if (!BYPASS_ALL_LOOKUPS) {
            fwd_result.apply();
        }
    }
        
}


/*****************************************************************************/
/* ECMP lookup                                                               */
/*****************************************************************************/



control process_nexthop  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    /*
     * If dest mac is not know, then unicast packet needs to be flooded in
     * egress BD
     */
    action set_ecmp_nexthop_details_for_post_routed_flood(bit<BD_BIT_WIDTH> bd, bit<16> uuc_mc_index,
                                                          bit<16> nhop_index) {
        meta.intrinsic_metadata.mcast_grp = uuc_mc_index;
        meta.l3_metadata.nexthop_index = nhop_index;
        meta.ingress_metadata.egress_ifindex = 0;
        meta.l3_metadata.same_bd_check = meta.ingress_metadata.bd ^ bd;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
    #endif /* FABRIC_ENABLE */
    }

    action set_ecmp_nexthop_details(bit<IFINDEX_BIT_WIDTH> ifindex, bit<BD_BIT_WIDTH> bd, bit<16> nhop_index, bit<1> tunnel) {
        meta.ingress_metadata.egress_ifindex = ifindex;
        meta.l3_metadata.nexthop_index = nhop_index;
        meta.l3_metadata.same_bd_check = meta.ingress_metadata.bd ^ bd;
        meta.l2_metadata.same_if_check = meta.l2_metadata.same_if_check ^ ifindex;
        meta.tunnel_metadata.tunnel_if_check = meta.tunnel_metadata.tunnel_terminate ^ tunnel;
    }


    table ecmp_group {
        key = {
            meta.hash_metadata.hash1 : selector;
            meta.l3_metadata.nexthop_index : exact;
        }

        actions = {
            nop;
            set_ecmp_nexthop_details;
            set_ecmp_nexthop_details_for_post_routed_flood;
        }
        size = ECMP_GROUP_TABLE_SIZE;
        implementation = action_selector(HashAlgorithm.identity, ECMP_SELECT_TABLE_SIZE, ECMP_BIT_WIDTH);
        

    }


    /*****************************************************************************/
    /* Nexthop lookup                                                            */
    /*****************************************************************************/
    /*
     * If dest mac is not know, then unicast packet needs to be flooded in
     * egress BD
     */
    action set_nexthop_details_for_post_routed_flood(bit<BD_BIT_WIDTH> bd, bit<16> uuc_mc_index) {
        meta.intrinsic_metadata.mcast_grp = uuc_mc_index;
        meta.ingress_metadata.egress_ifindex = 0;
        meta.l3_metadata.same_bd_check = meta.ingress_metadata.bd ^ bd;
    #ifdef FABRIC_ENABLE
        meta.fabric_metadata.dst_device = FABRIC_DEVICE_MULTICAST;
    #endif /* FABRIC_ENABLE */
    }

    action set_nexthop_details(bit<IFINDEX_BIT_WIDTH> ifindex, bit<BD_BIT_WIDTH> bd, bit<1> tunnel) {
        meta.ingress_metadata.egress_ifindex = ifindex;
        meta.l3_metadata.same_bd_check = meta.ingress_metadata.bd ^ bd;
        meta.l2_metadata.same_if_check = meta.l2_metadata.same_if_check ^ ifindex;
        meta.tunnel_metadata.tunnel_if_check = meta.tunnel_metadata.tunnel_terminate ^ tunnel;
    }

    table nexthop {
        key = {
            meta.l3_metadata.nexthop_index : exact;
        }
        actions = {
            nop;
            set_nexthop_details;
            set_nexthop_details_for_post_routed_flood;
        }
        size = NEXTHOP_TABLE_SIZE;
    }

    apply{
        if (meta.nexthop_metadata.nexthop_type == NEXTHOP_TYPE_ECMP) {
            /* resolve ecmp */
            ecmp_group.apply();
        } 
        else {
            /* resolve nexthop */
            nexthop.apply();
        }
    }     
}
