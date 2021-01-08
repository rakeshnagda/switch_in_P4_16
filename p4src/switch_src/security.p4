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
 * Security related processing - Storm control, IPSG, etc.
 */

/*
 * security metadata
 */


#ifndef STORM_CONTROL_DISABLE
/*****************************************************************************/
/* Storm control                                                             */
/*****************************************************************************/

meter(STORM_CONTROL_METER_TABLE_SIZE, MeterType.bytes) mtr;
    

control process_storm_control  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
    action set_storm_control_meter(bit<16> meter_idx) {
#ifndef METER_DISABLE
        mtr.execute_meter((bit<32>)meter_idx, meta.meter_metadata.packet_color);
        meta.meter_metadata.meter_index = meter_idx;
#endif /* METER_DISABLE */
    }

    table storm_control {
        key = {
            standard_metadata.ingress_port : exact;
            meta.l2_metadata.lkp_pkt_type : ternary;
        }
        actions = {
            nop;
            set_storm_control_meter;
        }
        size = STORM_CONTROL_TABLE_SIZE;
    }
    #endif /* STORM_CONTROL_DISABLE */

    apply{
#ifndef STORM_CONTROL_DISABLE
        if (meta.ingress_metadata.port_type == PORT_TYPE_NORMAL) {
            storm_control.apply();
        }
#endif /* STORM_CONTROL_DISABLE */       
    }

}

control process_storm_control_stats  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }
#ifndef STORM_CONTROL_DISABLE
#ifndef STATS_DISABLE
    table storm_control_stats {
        key = {
            meta.meter_metadata.packet_color: exact;
            standard_metadata.ingress_port : exact;
        }
        actions = {
            nop;
        }
        size = STORM_CONTROL_STATS_TABLE_SIZE;
        counters = direct_counter(CounterType.packets);
    }
#endif /* STATS_DISABLE */
#endif /* STORM_CONTROL_DISABLE */   

    apply{
#ifndef STORM_CONTROL_DISABLE
#ifndef STATS_DISABLE
        storm_control_stats.apply();
#endif /* STATS_DISABLE */
#endif /* STORM_CONTROL_DISABLE */   
    }

}


/*****************************************************************************/
/* IP Source Guard                                                           */
/*****************************************************************************/
    
control process_ip_sourceguard  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action on_miss(){
        
    }
    action ipsg_miss() {
        meta.security_metadata.ipsg_check_fail = TRUE;
    }

    table ipsg_permit_special {
        key = {
            meta.l3_metadata.lkp_ip_proto : ternary;
            meta.l3_metadata.lkp_l4_dport : ternary;
            meta.ipv4_metadata.lkp_ipv4_da : ternary;
        }
        actions = {
            ipsg_miss;
        }
        size = IPSG_PERMIT_SPECIAL_TABLE_SIZE;
    }

    table ipsg {
        key = {
            meta.ingress_metadata.ifindex : exact;
            meta.ingress_metadata.bd : exact;
            meta.l2_metadata.lkp_mac_sa : exact;
            meta.ipv4_metadata.lkp_ipv4_sa : exact;
        }
        actions = {
            on_miss;
        }
        size = IPSG_TABLE_SIZE;
    }
    apply{
#ifndef IPSG_DISABLE
        /* l2 security features */
        if ((meta.ingress_metadata.port_type == PORT_TYPE_NORMAL) &&
            (meta.security_metadata.ipsg_enabled == TRUE)) {
            switch(ipsg.apply().action_run){
                on_miss:{
                    ipsg_permit_special.apply();
                }
            }
        }
#endif /* IPSG_DISABLE */    
    }

}
