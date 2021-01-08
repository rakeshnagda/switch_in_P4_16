/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law || agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express || implied.
See the License for the specific language governing permissions &&
limitations under the License.
*/

/*****************************************************************************/
/* Egress filtering logic                                                    */
/*****************************************************************************/

control process_egress_filter (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
    action egress_filter_check() {
        meta.egress_filter_metadata.ifindex_check = meta.ingress_metadata.ifindex ^ meta.egress_metadata.ifindex;
        meta.egress_filter_metadata.bd = meta.ingress_metadata.outer_bd ^ meta.egress_metadata.outer_bd;
        meta.egress_filter_metadata.inner_bd = meta.ingress_metadata.bd ^ meta.egress_metadata.bd;
    }

    action set_egress_filter_drop() {
        mark_to_drop(standard_metadata);
    }

    table egress_filter_drop {
        actions = {
            set_egress_filter_drop;
        }
    }

    table egress_filter {
        actions = {
            egress_filter_check;
        }
    }

    apply{
#ifdef EGRESS_FILTER
        egress_filter.apply();
        if (meta.multicast_metadata.inner_replica == TRUE) {
            if (((meta.tunnel_metadata.ingress_tunnel_type == INGRESS_TUNNEL_TYPE_NONE) &&
                 (meta.tunnel_metadata.egress_tunnel_type == EGRESS_TUNNEL_TYPE_NONE) &&
                 (meta.egress_filter_metadata.bd == 0) &&
                 (meta.egress_filter_metadata.ifindex_check == 0)) ||
                ((meta.tunnel_metadata.ingress_tunnel_type != INGRESS_TUNNEL_TYPE_NONE) &&
                 (meta.tunnel_metadata.egress_tunnel_type != EGRESS_TUNNEL_TYPE_NONE)) &&
                 (meta.egress_filter_metadata.inner_bd == 0)) {
                egress_filter_drop.apply();
            }
        }
#endif /* EGRESS_FILTER */    
    }

}
