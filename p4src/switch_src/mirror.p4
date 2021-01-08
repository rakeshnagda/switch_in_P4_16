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
 * Mirror processing
 */

    
control process_mirroring (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }

        /* ----- egress processing ----- */
#ifdef SFLOW_ENABLE
    action sflow_pkt_to_cpu(bit<16> reason_code) {
        /* This action is called from the mirror table in the egress pipeline */
        /* Add hdr.sflow header to the packet */
        /* hdr.sflow header sits between cpu header and the rest of the original packet */
        /* The reasonCode in the cpu header is used to identify the */
        /* presence of the cpu header */
        /* pkt_count(sample_pool) on a given hdr.sflow session is read directly by CPU */
        /* using counter read mechanism */
        hdr.fabric_header_sflow.setValid();
        hdr.fabric_header_sflow.sflow_session_id=
                     meta.sflow_metadata.sflow_session_id;
        hdr.fabric_header_sflow.sflow_egress_ifindex=
                     meta.ingress_metadata.egress_ifindex;
        meta.fabric_metadata.reason_code= reason_code;
    }
#endif

    action set_mirror_nhop(bit<16> nhop_idx) {
        meta.l3_metadata.nexthop_index = nhop_idx;
    }

    action set_mirror_bd(bit<BD_BIT_WIDTH> bd) {
        meta.egress_metadata.bd = bd;
    }

    table mirror {
        key = {
            meta.i2e_metadata.mirror_session_id : exact;
        }
        actions = {
            nop;
            set_mirror_nhop;
            set_mirror_bd;
    #ifdef SFLOW_ENABLE
            sflow_pkt_to_cpu;
    #endif
        }
        size = MIRROR_SESSIONS_TABLE_SIZE;
    }

    apply{
#ifndef MIRROR_DISABLE
        mirror.apply();
#endif /* MIRROR_DISABLE */    
    }

}
