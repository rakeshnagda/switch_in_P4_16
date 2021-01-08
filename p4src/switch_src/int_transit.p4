/*
Copyright 2015 Barefoot Networks, Inc.

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
 * INT transit device implementation
 * This example implements INT transit functionality using VxLAN-GPE as
 * underlay protocol. The hdr.udp port# for vxlan-gpe is assume to be 4790
 * Only IPv4 is supported as underlay protocol in this example.
 */
    

/*
 * Check if this switch needs to act as INT source or sink
 */
control process_int_endpoint  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){
        
    }

    #ifdef INT_EP_ENABLE
    action int_set_src () {
        meta.int_metadata_i2e.source = 1;
    }

    action int_set_no_src () {
        meta.int_metadata_i2e.source = 0;
    }

    table int_source {
        // Decide to initiate INT based on client IP address pair
        // lkp_src, lkp_dst addresses are either outer or inner based
        // on if this switch is VTEP src or not respectively.
        //
        // {hdr.int_header, lkp_src, lkp_dst}
        //      0, src, dst => int_src=1
        //      1, x, x => mis-config, transient error, int_src=0
        //      miss => int_src=0
        key = {
            hdr.int_header.isValid() : exact;
            // use outer hdr.ipv4/6 header when VTEP src
            hdr.ipv4.isValid() : exact;
            meta.ipv4_metadata.lkp_ipv4_da   : ternary;
            meta.ipv4_metadata.lkp_ipv4_sa   : ternary;

            // use meta.inner_ipv4 header when not VTEP src
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv4.dstAddr          : ternary;
            hdr.inner_ipv4.srcAddr          : ternary;
        }
        actions = {
            int_set_src;
            int_set_no_src;
        }
        size = INT_SOURCE_TABLE_SIZE;
    }

    action int_sink (bit<32> mirror_id) {
        meta.int_metadata_i2e.sink = 1;

        // If this is sink, need to send the INT information to the
        // pre-processor/monitor. This is done via mirroring
        meta.i2e_metadata.mirror_session_id = (bit<16>)mirror_id;
        clone3(CloneType.I2E, (bit<32>)mirror_id,{
                                            meta.int_metadata_i2e.sink,
                                            meta.i2e_metadata.mirror_session_id
                                        }
                                    );

        // remove all the INT information from the packet
        // max 24 headers are supported
        hdr.int_header.setInvalid();
        hdr.int_val[0].setInvalid();
        hdr.int_val[1].setInvalid();
        hdr.int_val[2].setInvalid();
        hdr.int_val[3].setInvalid();
        hdr.int_val[4].setInvalid();
        hdr.int_val[5].setInvalid();
        hdr.int_val[6].setInvalid();
        hdr.int_val[7].setInvalid();
        hdr.int_val[8].setInvalid();
        hdr.int_val[9].setInvalid();
        hdr.int_val[10].setInvalid();
        hdr.int_val[11].setInvalid();
        hdr.int_val[12].setInvalid();
        hdr.int_val[13].setInvalid();
        hdr.int_val[14].setInvalid();
        hdr.int_val[15].setInvalid();
        hdr.int_val[16].setInvalid();
        hdr.int_val[17].setInvalid();
        hdr.int_val[18].setInvalid();
        hdr.int_val[19].setInvalid();
        hdr.int_val[20].setInvalid();
        hdr.int_val[21].setInvalid();
        hdr.int_val[22].setInvalid();
        hdr.int_val[23].setInvalid();
    }

    action int_sink_gpe (bit<32> mirror_id) {
        // convert the word len from gpe-shim header to byte_cnt
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.gpe_int_hdr_len << 2;
        int_sink(mirror_id);

    }

    action int_no_sink() {
        meta.int_metadata_i2e.sink = 0;
    }

    table int_terminate {
        /* REMOVE after discussion
         * It would be nice to keep this encap un-aware. But this is used
         * to compute byte count of INT info from shim headers from outer
         * protocols (vxlan_gpe_shim, geneve_tlv etc)
         * That make hdr.vxlan_gpe_int_header.valid as part of the key
         */

        // This table is used to decide if this node is INT sink
        // lkp_dst addr can be outer or inner ip addr, depending on how
        // user wants to configure.
        // {hdr.int_header, gpe, lkp_dst}
        //  1, 1, dst => int_gpe_sink(remove/update headers), int_sink=1
        //  (one entry per dst_addr)
        //  miss => no_sink
        key = {
            hdr.int_header.isValid() : exact;
            hdr.vxlan_gpe_int_header.isValid() : exact;
            // when configured based on tunnel IPs
            hdr.ipv4.isValid() : exact;
            meta.ipv4_metadata.lkp_ipv4_da   : ternary;
            // when configured based on client IPs
            hdr.inner_ipv4.isValid() : exact;
            hdr.inner_ipv4.dstAddr          : ternary;
        }
        actions = {
            int_sink_gpe;
            int_no_sink;
        }
        size = INT_TERMINATE_TABLE_SIZE;
    }

    action int_sink_update_vxlan_gpe_v4() {
        hdr.vxlan_gpe.next_proto = hdr.vxlan_gpe_int_header.next_proto;
        hdr.vxlan_gpe_int_header.setInvalid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - meta.int_metadata.insert_byte_cnt;
        hdr.udp.length_ = hdr.udp.length_ - meta.int_metadata.insert_byte_cnt;
    }

    table int_sink_update_outer {
        // This table is used to update the outer(underlay) headers on int_sink
        // to reflect removal of INT headers
        // Add more entries as other underlay protocols are added
        // {sink, gpe}
        // 1, 1 => update hdr.ipv4 and hdr.udp headers
        // miss => nop
        key = {
            hdr.vxlan_gpe_int_header.isValid() : exact;
            hdr.ipv4.isValid() : exact;
            meta.int_metadata_i2e.sink       : exact;
        }
        actions = {
            int_sink_update_vxlan_gpe_v4;
            nop;
        }
        size = 2;
    }
    #endif

    apply{
#ifdef INT_EP_ENABLE
        if (!hdr.int_header.isValid()) {
            int_source.apply();
        } 
        else {
            int_terminate.apply();
            int_sink_update_outer.apply();
        }
#endif
    }
}

control process_int_insertion  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){

    }

        /* Instr Bit 0 */
    action int_set_header_0() { //switch_id
        hdr.int_switch_id_header.setValid();
        hdr.int_switch_id_header.switch_id = (bit<31>)meta.int_metadata.switch_id;
    }
    /* Instr Bit 1 */
    action int_set_header_1() { //ingress_port_id
        hdr.int_ingress_port_id_header.setValid();
        hdr.int_ingress_port_id_header.ingress_port_id_1 = 0;
        hdr.int_ingress_port_id_header.ingress_port_id_0 = meta.ingress_metadata.ifindex;
    }
    /* Instr Bit 2 */
    action int_set_header_2() { //hop_latency
        hdr.int_hop_latency_header.setValid();
        hdr.int_hop_latency_header.hop_latency = (bit<31>)meta.queueing_metadata.deq_timedelta;
    }
    /* Instr Bit 3 */
    action int_set_header_3() { //q_occupancy
        hdr.int_q_occupancy_header.setValid();
        hdr.int_q_occupancy_header.q_occupancy1 = 0;
        hdr.int_q_occupancy_header.q_occupancy0 = (bit<24>)meta.queueing_metadata.enq_qdepth;
    }
    /* Instr Bit 4 */
    action int_set_header_4() { //ingress_tstamp
        hdr.int_ingress_tstamp_header.setValid();
        hdr.int_ingress_tstamp_header.ingress_tstamp = (bit<31>)meta.i2e_metadata.ingress_tstamp;
    }
    /* Instr Bit 5 */
    action int_set_header_5() { //egress_port_id
        hdr.int_egress_port_id_header.setValid();
        hdr.int_egress_port_id_header.egress_port_id = (bit<31>)standard_metadata.egress_port;
    }

    /* Instr Bit 6 */
    action int_set_header_6() { //q_congestion
        hdr.int_q_congestion_header.setValid();
        hdr.int_q_congestion_header.q_congestion = 0x7FFFFFFF;
    }
    /* Instr Bit 7 */
    action int_set_header_7() { //egress_port_tx_utilization
        hdr.int_egress_port_tx_utilization_header.setValid();
        hdr.int_egress_port_tx_utilization_header.egress_port_tx_utilization = 0x7FFFFFFF;
    }

    /* action function for bits 0-3 combinations, 0 is msb, 3 is lsb */
    /* Each bit set indicates that corresponding INT header should be added */
    action int_set_header_0003_i0() {
    }
    action int_set_header_0003_i1() {
        int_set_header_3();
    }
    action int_set_header_0003_i2() {
        int_set_header_2();
    }
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
    }
    action int_set_header_0003_i4() {
        int_set_header_1();
    }
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
    }
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
    }
    action int_set_header_0003_i8() {
        int_set_header_0();
    }
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
    }
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
    }
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
    }

    /* Table to process instruction bits 0-3 */
    table int_inst_0003 {
        key = {
            hdr.int_header.instruction_mask_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        size = 17;
    }

    /* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
    action int_set_header_0407_i0() {
    }
    action int_set_header_0407_i1() {
        int_set_header_7();
    }
    action int_set_header_0407_i2() {
        int_set_header_6();
    }
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
    }
    action int_set_header_0407_i4() {
        int_set_header_5();
    }
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
    }
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
    }
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
    }
    action int_set_header_0407_i8() {
        int_set_header_4();
    }
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
    }
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
    }
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
    }
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
    }
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
    }

    /* Table to process instruction bits 4-7 */
    table int_inst_0407 {
        key = {
            hdr.int_header.instruction_mask_0407 : exact;
        }
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
            nop;
        }
        size = 17;
    }

     /* instruction mask bits 8-15 are not defined in the current spec */
    table int_inst_0811 {
        key = {
            hdr.int_header.instruction_mask_0811 : exact;
        }
        actions = {
            nop;
        }
        size = 16;
    }

    table int_inst_1215 {
        key = {
            hdr.int_header.instruction_mask_1215 : exact;
        }
        actions = {
            nop;
        }
        size = 17;
    }

    /* BOS bit - set for the bottom most header added by INT src device */
    action int_set_header_0_bos() { //switch_id
        hdr.int_switch_id_header.bos = 1;
    }
    action int_set_header_1_bos() { //ingress_port_id
        hdr.int_ingress_port_id_header.bos = 1;
    }
    action int_set_header_2_bos() { //hop_latency
        hdr.int_hop_latency_header.bos = 1;
    }
    action int_set_header_3_bos() { //q_occupancy
        hdr.int_q_occupancy_header.bos = 1;
    }
    action int_set_header_4_bos() { //ingress_tstamp
        hdr.int_ingress_tstamp_header.bos = 1;
    }
    action int_set_header_5_bos() { //egress_port_id
        hdr.int_egress_port_id_header.bos = 1;
    }
    action int_set_header_6_bos() { //q_congestion
        hdr.int_q_congestion_header.bos = 1;
    }
    action int_set_header_7_bos() { //egress_port_tx_utilization
        hdr.int_egress_port_tx_utilization_header.bos = 1;
    }

    table int_bos {
        key = {
            hdr.int_header.total_hop_cnt            : ternary;
            hdr.int_header.instruction_mask_0003    : ternary;
            hdr.int_header.instruction_mask_0407    : ternary;
            hdr.int_header.instruction_mask_0811    : ternary;
            hdr.int_header.instruction_mask_1215    : ternary;
        }
        actions = {
            int_set_header_0_bos;
            int_set_header_1_bos;
            int_set_header_2_bos;
            int_set_header_3_bos;
            int_set_header_4_bos;
            int_set_header_5_bos;
            int_set_header_6_bos;
            int_set_header_7_bos;
            nop;
        }
        size = 17;       // number of instruction bits
    }

    // update the INT metadata header
    action int_set_e_bit() {
        hdr.int_header.e = 1;
    }

    action int_update_total_hop_cnt() {
        hdr.int_header.total_hop_cnt = 1;
    }

    table int_meta_header_update {
        // This table is applied only if int_insert table is a hit, which
        // computes insert_cnt
        // E bit is set if insert_cnt == 0
        // Else total_hop_cnt is incremented by one
        key = {
            meta.int_metadata.insert_cnt : ternary;
        }
        actions = {
            int_set_e_bit;
            int_update_total_hop_cnt;
        }
        size = 2;
    }

    #ifdef INT_ENABLE
    #ifdef INT_TRANSIT_ENABLE
    action int_transit(bit<32> switch_id) {
        meta.int_metadata.insert_cnt = hdr.int_header.max_hop_cnt - hdr.int_header.total_hop_cnt;
        meta.int_metadata.switch_id = switch_id;
        meta.int_metadata.insert_byte_cnt = meta.int_metadata.instruction_cnt << 2;
        meta.int_metadata.gpe_int_hdr_len8 = (bit<8>)hdr.int_header.ins_cnt;
    }
    #endif

    action int_reset() {
        meta.int_metadata.switch_id = 0;
        meta.int_metadata.insert_byte_cnt = 0;
        meta.int_metadata.insert_cnt = 0;
        meta.int_metadata.gpe_int_hdr_len8 = 0;
        meta.int_metadata.gpe_int_hdr_len = 0;
        meta.int_metadata.instruction_cnt = 0;
    }

    #ifdef INT_EP_ENABLE
    action int_src(bit<32> switch_id, bit<8> hop_cnt, bit<5> ins_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407, bit<16> ins_byte_cnt, bit<8> total_words) {
        meta.int_metadata.insert_cnt = hop_cnt;
        meta.int_metadata.switch_id = switch_id;
        meta.int_metadata.insert_byte_cnt = ins_byte_cnt;
        meta.int_metadata.gpe_int_hdr_len8 = total_words;
        hdr.int_header.setValid();
        hdr.int_header.ver = 0;
        hdr.int_header.rep = 0;
        hdr.int_header.c = 0;
        hdr.int_header.e = 0;
        hdr.int_header.rsvd1 = 0;
        hdr.int_header.ins_cnt = ins_cnt;
        hdr.int_header.max_hop_cnt = hop_cnt;
        hdr.int_header.total_hop_cnt = 0;
        hdr.int_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_header.instruction_mask_0811 = 0; // not supportd
        hdr.int_header.instruction_mask_1215 = 0; // not supportd
        hdr.int_header.rsvd2 = 0;
    }
    #endif

    table int_insert {
        /* REMOVE - changed src/sink bits to ternary to use TCAM
         * keep hdr.int_header.valid in the key to force reset on error condition
         */

        // int_sink takes precedence over int_src
        // {int_src, int_sink, hdr.int_header} :
        //      0, 0, 1 => transit  => insert_cnt = max-total
        //      1, 0, 0 => insert (src) => insert_cnt = max
        //      x, 1, x => nop (reset) => insert_cnt = 0
        //      1, 0, 1 => nop (error) (reset) => insert_cnt = 0
        //      miss (0,0,0) => nop (reset)
        key = {
            meta.int_metadata_i2e.source       : ternary;
            meta.int_metadata_i2e.sink         : ternary;
            hdr.int_header.isValid() : exact;
        }
        actions = {
    #ifdef INT_TRANSIT_ENABLE
            int_transit;
    #endif
    #ifdef INT_EP_ENABLE
            int_src;
    #endif
            int_reset;
        }
        size = 3;
    }
    #endif

    apply{
#ifdef INT_ENABLE
        switch(int_insert.apply().action_run) {
            int_transit : {
                // int_transit | int_src
                // insert_cnt = max_hop_cnt - total_hop_cnt
                // (cannot be -ve, not checked)
                if (meta.int_metadata.insert_cnt != 0) {
                    int_inst_0003.apply();
                    int_inst_0407.apply();
                    int_inst_0811.apply();
                    int_inst_1215.apply();
                    int_bos.apply();
                }
                int_meta_header_update.apply();
            }
        }
#endif
    }
}

    

control process_int_outer_encap  (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action nop(){
        
    }
    #ifdef INT_ENABLE
    action int_update_vxlan_gpe_ipv4() {
        hdr.ipv4.totalLen = meta.int_metadata.insert_byte_cnt;
        hdr.udp.length_ = meta.int_metadata.insert_byte_cnt;
        hdr.vxlan_gpe_int_header.len = meta.int_metadata.gpe_int_hdr_len8;
    }

    action int_add_update_vxlan_gpe_ipv4() {
        // INT source - vxlan gpe header is already added (or present)
        // Add the INT shim header for vxlan GPE
        hdr.vxlan_gpe_int_header.setValid();
        hdr.vxlan_gpe_int_header.int_type = 0x01;
        hdr.vxlan_gpe_int_header.next_proto = 3; // Ethernt
        hdr.vxlan_gpe.next_proto = 5; // Set proto = IT
        hdr.vxlan_gpe_int_header.len = meta.int_metadata.gpe_int_hdr_len8;
        hdr.ipv4.totalLen = meta.int_metadata.insert_byte_cnt;
        hdr.udp.length_ = meta.int_metadata.insert_byte_cnt;
    }

    table int_outer_encap {
        /* REMOVE from open-srouce version -
         * hdr.ipv4 and gpe valid bits are used as key so that other outer protocols
         * can be added in future. Table size
         */
        // This table is applied only if it is decided to add INT info
        // as part of transit or source functionality
        // based on outer(underlay) encap, vxlan-GPE, Geneve, .. update
        // outer headers, options, IP total len etc.
        // {int_src, hdr.vxlan_gpe, egr_tunnel_type} :
        //      0, 0, X : nop (error)
        //      0, 1, X : update_vxlan_gpe_int (transit case)
        //      1, 0, tunnel_gpe : add_update_vxlan_gpe_int
        //      1, 1, X : add_update_vxlan_gpe_int
        //      miss => nop
        key = {
            hdr.ipv4.isValid() : exact;
            hdr.vxlan_gpe.isValid() : exact;
            meta.int_metadata_i2e.source             : exact;
            meta.tunnel_metadata.egress_tunnel_type  : ternary;
        }
        actions = {
    #ifdef INT_TRANSIT_ENABLE
            int_update_vxlan_gpe_ipv4;
    #endif
    #ifdef INT_EP_ENABLE
            int_add_update_vxlan_gpe_ipv4;
    #endif
            nop;
        }
        size = INT_UNDERLAY_ENCAP_TABLE_SIZE;
    }
    #endif
    
    apply{
#ifdef INT_ENABLE
        if (meta.int_metadata.insert_cnt != 0) {
            int_outer_encap.apply();
        }
#endif
    }
}
