
/*****************************************************************************/
/* Qos Processing                                                            */
/*****************************************************************************/



/*****************************************************************************/
/* Ingress QOS Map                                                           */
/*****************************************************************************/
    

control process_ingress_qos_map (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    #ifndef QOS_DISABLE
    action set_ingress_tc_and_color(bit<8> tc, bit<2> color) {
        meta.qos_metadata.lkp_tc = tc;
        meta.meter_metadata.packet_color = color;
    }

    action set_ingress_tc(bit<8> tc) {
        meta.qos_metadata.lkp_tc = tc;
    }

    action set_ingress_color(bit<2> color) {
        meta.meter_metadata.packet_color = color;
    }

    table ingress_qos_map_dscp {
        key = {
            meta.qos_metadata.ingress_qos_group: ternary;
            meta.l3_metadata.lkp_dscp: ternary;
        }

        actions = {
            nop;
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }

        size = DSCP_TO_TC_AND_COLOR_TABLE_SIZE;
    }

    table ingress_qos_map_pcp {
        key = {
            meta.qos_metadata.ingress_qos_group: ternary;
            meta.l2_metadata.lkp_pcp: ternary;
        }

        actions = {
            nop;
            set_ingress_tc;
            set_ingress_color;
            set_ingress_tc_and_color;
        }

        size = PCP_TO_TC_AND_COLOR_TABLE_SIZE;
    }

    #endif /* QOS_DISABLE */

    apply{
#ifndef QOS_DISABLE
        if (DO_LOOKUP(QOS)) {
            if (meta.qos_metadata.trust_dscp == TRUE) {
                ingress_qos_map_dscp.apply();
            } else {
                if (meta.qos_metadata.trust_pcp == TRUE) {
                    ingress_qos_map_pcp.apply();
                }
            }
        }
#endif /* QOS_DISABLE */
    }
}


/*****************************************************************************/
/* Queuing                                                                   */
/*****************************************************************************/

    

control process_traffic_class (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    #ifndef QOS_DISABLE
    action set_icos(bit<3> icos) {
        meta.intrinsic_metadata.ingress_cos = icos;
    }

    action set_queue(bit<5> qid) {
        meta.intrinsic_metadata.qid = qid; 
    }

    action set_icos_and_queue(bit<3> icos, bit<5> qid) {
        meta.intrinsic_metadata.ingress_cos = icos;
        meta.intrinsic_metadata.qid = qid;
    }

    table traffic_class {
        key = {
            meta.qos_metadata.tc_qos_group: ternary;
            meta.qos_metadata.lkp_tc: ternary;
        }

        actions = {
            nop;
            set_icos;
            set_queue;
            set_icos_and_queue;
        }
        size = QUEUE_TABLE_SIZE;
    }
    #endif /* QOS_DISABLE */

    apply{
#ifndef QOS_DISABLE
        traffic_class.apply();
#endif /* QOS_DISABLE */
    }
}

/*****************************************************************************/
/* Egress QOS Map                                                            */
/*****************************************************************************/
    

control process_egress_qos_map (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    #ifndef QOS_DISABLE
    action set_mpls_exp_marking(bit<8> exp) {
        meta.l3_metadata.lkp_dscp = exp;
    }

    action set_ip_dscp_marking(bit<8> dscp) {
        meta.l3_metadata.lkp_dscp = dscp;
    }

    action set_vlan_pcp_marking(bit<3> pcp) {
        meta.l2_metadata.lkp_pcp = pcp;
    }

    table egress_qos_map {
        key = {
            meta.qos_metadata.egress_qos_group: ternary;
            meta.qos_metadata.lkp_tc: ternary;
            //meta.meter_metadata.packet_color : ternary;
        }
        actions = {
            nop;
            set_mpls_exp_marking;
            set_ip_dscp_marking;
            set_vlan_pcp_marking;
        }
        size = EGRESS_QOS_MAP_TABLE_SIZE;
    }
    #endif /* QOS_DISABLE */
    
    apply{
#ifndef QOS_DISABLE
        if (DO_LOOKUP(QOS)) {
            egress_qos_map.apply();
        }
#endif /* QOS_DISABLE */
    }
}
