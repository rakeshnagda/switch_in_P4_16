#include <core.p4>
#include <v1model.p4>

#define MASK &&&
#define VLAN_DEPTH 2
#define MPLS_DEPTH 3
#define MAX_INT_INFO    24


struct headers_t{
    ethernet_t ethernet;
    llc_header_t llc_header;
    snap_header_t snap_header;
    roce_header_t roce;
    fcoe_header_t fcoe;
    vlan_tag_t[VLAN_DEPTH] vlan_tag_;
    mpls_t[MPLS_DEPTH] mpls;
    ipv4_t ipv4;
    ipv6_t ipv6;
    icmp_t icmp;
    tcp_t tcp;
    udp_t udp;

    roce_v2_header_t roce_v2;
// #ifdef INT_ENABLE
    int_header_t                             int_header;
    int_switch_id_header_t                   int_switch_id_header;
    int_ingress_port_id_header_t             int_ingress_port_id_header;
    int_hop_latency_header_t                 int_hop_latency_header;
    int_q_occupancy_header_t                 int_q_occupancy_header;
    int_ingress_tstamp_header_t              int_ingress_tstamp_header;
    int_egress_port_id_header_t              int_egress_port_id_header;
    int_q_congestion_header_t                int_q_congestion_header;
    int_egress_port_tx_utilization_header_t  int_egress_port_tx_utilization_header;
    vxlan_gpe_int_header_t                   vxlan_gpe_int_header;

// #ifdef INT_EP_ENABLE
    int_value_t[MAX_INT_INFO] int_val;
// #endif
// #endif
    sctp_t sctp;
    gre_t gre;
    nvgre_t nvgre;
    ethernet_t inner_ethernet;
    ipv4_t inner_ipv4;
    ipv6_t inner_ipv6;
    udp_t outer_udp;
    erspan_header_t3_t erspan_t3_header;
    eompls_t eompls;
    vxlan_t vxlan;
// #ifdef INT_ENABLE
    vxlan_gpe_t vxlan_gpe;
// #endif
    genv_t genv;
    nsh_t nsh;
    nsh_context_t nsh_context;
    lisp_t lisp;
    icmp_t inner_icmp;
    tcp_t inner_tcp;
    udp_t inner_udp;
    sctp_t inner_sctp;
    trill_t trill;
    vntag_t vntag;
    bfd_t bfd;
// #ifdef SFLOW_ENABLE
    sflow_hdr_t sflow;
    sflow_sample_t sflow_sample;
    sflow_raw_hdr_record_t sflow_raw_hdr_record;
// #endif
    fabric_header_t                  fabric_header;
    fabric_header_unicast_t          fabric_header_unicast;
    fabric_header_multicast_t        fabric_header_multicast;
    fabric_header_mirror_t           fabric_header_mirror;
    fabric_header_cpu_t              fabric_header_cpu;
    fabric_header_sflow_t            fabric_header_sflow;
    fabric_payload_header_t          fabric_payload_header;

}

struct metadata_t{
    // intrinsic.p4
    ingress_intrinsic_metadata_t intrinsic_metadata;
    queueing_metadata_t queueing_metadata;
    // switch.p4
    ingress_metadata_t ingress_metadata;
    egress_metadata_t egress_metadata;
    global_config_metadata_t global_config_metadata;
    // acl.p4
    acl_metadata_t acl_metadata;
    i2e_metadata_t i2e_metadata;
    // l2.p4
    l2_metadata_t l2_metadata;
    // ipv4.p4
    ipv4_metadata_t ipv4_metadata;
    // qos.p4
    qos_metadata_t qos_metadata;
    // meter.p4
    meter_metadata_t meter_metadata;
    // fabric.p4
    fabric_metadata_t fabric_metadata;
    // ipv6.p4
    ipv6_metadata_t ipv6_metadata;
    // l3.p4
    l3_metadata_t l3_metadata;
    // nat.p4
    nat_metadata_t nat_metadata;
    // tunnel.p4
    tunnel_metadata_t tunnel_metadata;

    multicast_metadata_t multicast_metadata;
    // nexthop.p4
    nexthop_metadata_t nexthop_metadata;
    // security.p4
    security_metadata_t security_metadata;
    // openflow.p4
    openflow_metadata_t openflow_metadata;
    // hashs.p4
    hash_metadata_t hash_metadata;
    // egress_filter.p4
    egress_filter_metadata_t egress_filter_metadata;
    // int_transit.p4
    int_metadata_t int_metadata;
    int_metadata_i2e_t int_metadata_i2e;
    // sflow.p4
    sflow_meta_t sflow_metadata;

}

// (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
// hdr, meta, standard_metadata