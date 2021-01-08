/*
 * Meter processing
 */

/*
 * Meter metadata
 */


/*****************************************************************************/
/* Meters                                                                    */
/*****************************************************************************/



control process_meter_index (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    
    direct_meter<bit<2>>(MeterType.bytes) dm;
    action nop0() {
        dm.read(meta.meter_metadata.packet_color);
    }

    table meter_index {
        key = {
            meta.meter_metadata.meter_index: exact;
        }
        actions = { 
            nop0;
        }
        size = METER_INDEX_TABLE_SIZE;
        meters = dm;
    }

    apply{
#ifndef METER_DISABLE
        if (DO_LOOKUP(METER)) {
            meter_index.apply();
        }
#endif /* METER_DISABLE */
    }
}

control process_meter_action (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action meter_deny() {
        mark_to_drop(standard_metadata);
    }

    action meter_permit() {
    }


    table meter_action {
        key = {
            meta.meter_metadata.packet_color : exact;
            meta.meter_metadata.meter_index : exact;
        }

        actions = {
            meter_permit;
            meter_deny;
        }
        size = METER_ACTION_TABLE_SIZE;
    #ifndef STATS_DISABLE
        counters = direct_counter(CounterType.packets);
    #endif /* STATS_DISABLE */
    }

    apply{
#ifndef METER_DISABLE
        if (DO_LOOKUP(METER)) {
            meter_action.apply();
        }
#endif /* METER_DISABLE */
    }
}
