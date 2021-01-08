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

/* enable all advanced features */
//#define ADV_FEATURES


#define ETHERTYPE_BF_FABRIC    0x9000
#define ETHERTYPE_VLAN         0x8100
#define ETHERTYPE_QINQ         0x9100
#define ETHERTYPE_MPLS         0x8847
#define ETHERTYPE_IPV4         0x0800
#define ETHERTYPE_IPV6         0x86dd
#define ETHERTYPE_ARP          0x0806
#define ETHERTYPE_RARP         0x8035
#define ETHERTYPE_NSH          0x894f
#define ETHERTYPE_ETHERNET     0x6558
#define ETHERTYPE_ROCE         0x8915
#define ETHERTYPE_FCOE         0x8906
#define ETHERTYPE_TRILL        0x22f3
#define ETHERTYPE_VNTAG        0x8926
#define ETHERTYPE_LLDP         0x88cc
#define ETHERTYPE_LACP         0x8809

#define IPV4_MULTICAST_MAC 0x01005E
#define IPV6_MULTICAST_MAC 0x3333

/* Tunnel types */
#define INGRESS_TUNNEL_TYPE_NONE               0
#define INGRESS_TUNNEL_TYPE_VXLAN              1
#define INGRESS_TUNNEL_TYPE_GRE                2
#define INGRESS_TUNNEL_TYPE_IP_IN_IP           3
#define INGRESS_TUNNEL_TYPE_GENEVE             4
#define INGRESS_TUNNEL_TYPE_NVGRE              5
#define INGRESS_TUNNEL_TYPE_MPLS_L2VPN         6
#define INGRESS_TUNNEL_TYPE_MPLS_L3VPN         9
#define INGRESS_TUNNEL_TYPE_VXLAN_GPE          12

// #ifndef ADV_FEATURES
#define PARSE_ETHERTYPE                                    \
        ETHERTYPE_VLAN : parse_vlan;                       \
        ETHERTYPE_QINQ : parse_qinq;                       \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        default: accept

#define PARSE_ETHERTYPE_MINUS_VLAN                         \
        ETHERTYPE_MPLS : parse_mpls;                       \
        ETHERTYPE_IPV4 : parse_ipv4;                       \
        ETHERTYPE_IPV6 : parse_ipv6;                       \
        ETHERTYPE_ARP : parse_arp_rarp;                    \
        ETHERTYPE_LLDP  : parse_set_prio_high;             \
        ETHERTYPE_LACP  : parse_set_prio_high;             \
        default: accept
// #else
// #define PARSE_ETHERTYPE                                    \
//         ETHERTYPE_VLAN : parse_vlan;                       \
//         ETHERTYPE_QINQ : parse_qinq;                       \
//         ETHERTYPE_MPLS : parse_mpls;                       \
//         ETHERTYPE_IPV4 : parse_ipv4;                       \
//         ETHERTYPE_IPV6 : parse_ipv6;                       \
//         ETHERTYPE_ARP : parse_arp_rarp;                    \
//         ETHERTYPE_RARP : parse_arp_rarp;                   \
//         ETHERTYPE_NSH : parse_nsh;                         \
//         ETHERTYPE_ROCE : parse_roce;                       \
//         ETHERTYPE_FCOE : parse_fcoe;                       \
//         ETHERTYPE_TRILL : parse_trill;                     \
//         ETHERTYPE_VNTAG : parse_vntag;                     \
//         ETHERTYPE_LLDP  : parse_set_prio_high;             \
//         ETHERTYPE_LACP  : parse_set_prio_high;             \
//         default: accept

// #define PARSE_ETHERTYPE_MINUS_VLAN                         \
//         ETHERTYPE_MPLS : parse_mpls;                       \
//         ETHERTYPE_IPV4 : parse_ipv4;                       \
//         ETHERTYPE_IPV6 : parse_ipv6;                       \
//         ETHERTYPE_ARP : parse_arp_rarp;                    \
//         ETHERTYPE_RARP : parse_arp_rarp;                   \
//         ETHERTYPE_NSH : parse_nsh;                         \
//         ETHERTYPE_ROCE : parse_roce;                       \
//         ETHERTYPE_FCOE : parse_fcoe;                       \
//         ETHERTYPE_TRILL : parse_trill;                     \
//         ETHERTYPE_VNTAG : parse_vntag;                     \
//         ETHERTYPE_LLDP  : parse_set_prio_high;             \
//         ETHERTYPE_LACP  : parse_set_prio_high;             \
//         default: accept
// #endif

#define IP_PROTOCOLS_ICMP              1
#define IP_PROTOCOLS_IGMP              2
#define IP_PROTOCOLS_IPV4              4
#define IP_PROTOCOLS_TCP               6
#define IP_PROTOCOLS_UDP               17
#define IP_PROTOCOLS_IPV6              41
#define IP_PROTOCOLS_GRE               47
#define IP_PROTOCOLS_IPSEC_ESP         50
#define IP_PROTOCOLS_IPSEC_AH          51
#define IP_PROTOCOLS_ICMPV6            58
#define IP_PROTOCOLS_EIGRP             88
#define IP_PROTOCOLS_OSPF              89
#define IP_PROTOCOLS_PIM               103
#define IP_PROTOCOLS_VRRP              112



#define IP_PROTOCOLS_IPHL_ICMP         0x501
#define IP_PROTOCOLS_IPHL_IPV4         0x504
#define IP_PROTOCOLS_IPHL_TCP          0x506
#define IP_PROTOCOLS_IPHL_UDP          0x511
#define IP_PROTOCOLS_IPHL_IPV6         0x529
#define IP_PROTOCOLS_IPHL_GRE          0x52f


// Vxlan header decoding for INT
// flags.p == 1 && next_proto == 5
#ifndef __TARGET_BMV2__
#define VXLAN_GPE_NEXT_PROTO_INT        0x0805 MASK 0x08ff
#else
#define VXLAN_GPE_NEXT_PROTO_INT        0x05 MASK 0xff
#endif

#define UDP_PORT_BOOTPS                67
#define UDP_PORT_BOOTPC                68
#define UDP_PORT_RIP                   520
#define UDP_PORT_RIPNG                 521
#define UDP_PORT_DHCPV6_CLIENT         546
#define UDP_PORT_DHCPV6_SERVER         547
#define UDP_PORT_HSRP                  1985
#define UDP_PORT_BFD                   3785
#define UDP_PORT_LISP                  4341
#define UDP_PORT_VXLAN                 4789
#define UDP_PORT_VXLAN_GPE             4790
#define UDP_PORT_ROCE_V2               4791
#define UDP_PORT_GENV                  6081
#define UDP_PORT_SFLOW                 6343

#define TCP_PORT_BGP                   179
#define TCP_PORT_MSDP                  639

#define GRE_PROTOCOLS_NVGRE            0x20006558
#define GRE_PROTOCOLS_ERSPAN_T3        0x22EB   /* Type III version 2 */

#define copy_tcp_header(dst_tcp, src_tcp) copy_header(dst_tcp, src_tcp)

#define CONTROL_TRAFFIC_PRIO_0         0
#define CONTROL_TRAFFIC_PRIO_1         1
#define CONTROL_TRAFFIC_PRIO_2         2
#define CONTROL_TRAFFIC_PRIO_3         3
#define CONTROL_TRAFFIC_PRIO_4         4
#define CONTROL_TRAFFIC_PRIO_5         5
#define CONTROL_TRAFFIC_PRIO_6         6
#define CONTROL_TRAFFIC_PRIO_7         7

// parser Parser<H, M>(packet_in b,
//                     out H parsedHdr,
//                     inout M meta,
//                     inout standard_metadata_t standard_metadata
// parser SwitchParser (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata, packet_in pkt) {
parser SwitchParser (packet_in pkt, out headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {  
    
    state start {
        // LOG1("---------------Hello Parser----------------------");
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0 MASK 0xfe00: parse_llc_header;
            0 MASK 0xfa00: parse_llc_header;
            ETHERTYPE_BF_FABRIC : parse_fabric_header;
            PARSE_ETHERTYPE;
        }
    }

    state parse_llc_header{
        pkt.extract(hdr.llc_header);
        transition select(hdr.llc_header.dsap, hdr.llc_header.ssap) {
            (0xAA, 0xAA) : parse_snap_header;
            (0xFE, 0xFE) : parse_set_prio_med;
            default: accept;
        }
    }

    state parse_snap_header{
        pkt.extract(hdr.snap_header);
        transition select(hdr.snap_header.type_) {
            PARSE_ETHERTYPE;
        }
    }

    state parse_roce {
        pkt.extract(hdr.roce);
        transition accept;
    }

    state parse_fcoe {
        pkt.extract(hdr.fcoe);
        transition accept;
    }



    state parse_vlan {
        pkt.extract(hdr.vlan_tag_[0]);
        transition select(hdr.vlan_tag_[0].etherType) {
            PARSE_ETHERTYPE_MINUS_VLAN;
        }
    }

    state parse_qinq {
        pkt.extract(hdr.vlan_tag_[0]);
        transition select(hdr.vlan_tag_[0].etherType) {
            ETHERTYPE_VLAN : parse_qinq_vlan;
            default : accept;
        }
    }

    state parse_qinq_vlan {
        pkt.extract(hdr.vlan_tag_[1]);
        transition select(hdr.vlan_tag_[1].etherType) {
            PARSE_ETHERTYPE_MINUS_VLAN;
        }
    }

    state parse_mpls {
        pkt.extract(hdr.mpls.next);
        transition select(hdr.mpls.last.bos) {
            0 : parse_mpls;
            1 : parse_mpls_bos;
            default: accept;
        }
    }

    state parse_mpls_bos {
        transition select((pkt.lookahead<bit<4>>())[3:0]) {
            0x4 : parse_mpls_inner_ipv4;
            0x6 : parse_mpls_inner_ipv6;
            default: parse_eompls;
        }
    }

    state parse_mpls_inner_ipv4 {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_MPLS_L3VPN;
        transition parse_inner_ipv4;
    }

    state parse_mpls_inner_ipv6 {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_MPLS_L3VPN;
        transition parse_inner_ipv6;
    }

    state parse_vpls {
        transition accept;
    }

    state parse_pw {
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.fragOffset, hdr.ipv4.ihl, hdr.ipv4.protocol) {         
            (13w0x00, 4w0x5, 8w0x01) : parse_icmp;
            (13w0x00, 4w0x5, 8w0x06) : parse_tcp;
            (13w0x00, 4w0x5, 8w0x11) : parse_udp;
            (13w0x00, 4w0x5, 8w0x2f) : parse_gre;
            (13w0x00, 4w0x5, 8w0x04) : parse_ipv4_in_ip;
            (13w0x00, 4w0x5, 8w0x29) : parse_ipv6_in_ip;
            (13w0x00, 4w0x00, 8w0x02) : parse_set_prio_med;
            (13w0x00, 4w0x00, 8w0x58) : parse_set_prio_med;
            (13w0x00, 4w0x00, 8w0x59) : parse_set_prio_med;
            (13w0x00, 4w0x00, 8w0x67) : parse_set_prio_med;
            (13w0x00, 4w0x00, 8w0x70) : parse_set_prio_med;
            default: accept;
        }
    }

    state parse_ipv4_in_ip {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_IP_IN_IP;
        transition parse_inner_ipv4;
    }

    state parse_ipv6_in_ip {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_IP_IN_IP;
        transition parse_inner_ipv6;
    }


    state parse_udp_v6 {
        pkt.extract(hdr.udp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.udp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.udp.dstPort;
        transition select(hdr.udp.dstPort) {
            UDP_PORT_BOOTPS : parse_set_prio_med;
            UDP_PORT_BOOTPC : parse_set_prio_med;
            UDP_PORT_DHCPV6_CLIENT : parse_set_prio_med;
            UDP_PORT_DHCPV6_SERVER : parse_set_prio_med;
            UDP_PORT_RIP : parse_set_prio_med;
            UDP_PORT_RIPNG : parse_set_prio_med;
            UDP_PORT_HSRP : parse_set_prio_med;
            default: accept;
        }
    }

    state parse_gre_v6 {
        pkt.extract(hdr.gre);
        transition select(hdr.gre.C, hdr.gre.R, hdr.gre.K, hdr.gre.S, hdr.gre.s,
                      hdr.gre.recurse, hdr.gre.flags, hdr.gre.ver, hdr.gre.proto) {
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x00, 3w0x0, 16w0x800) : parse_gre_ipv4;
            default: accept;
        }
    }

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            IP_PROTOCOLS_ICMPV6 : parse_icmp;
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_IPV4 : parse_ipv4_in_ip;
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_GRE : parse_gre;
            IP_PROTOCOLS_IPV6 : parse_ipv6_in_ip;
            IP_PROTOCOLS_EIGRP : parse_set_prio_med;
            IP_PROTOCOLS_OSPF : parse_set_prio_med;
            IP_PROTOCOLS_PIM : parse_set_prio_med;
            IP_PROTOCOLS_VRRP : parse_set_prio_med;

            default: accept;
        }
    }



    state parse_icmp {
        pkt.extract(hdr.icmp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.icmp.typeCode;
        transition select(hdr.icmp.typeCode) {
            /* MLD and ND, 130-136 */
            16w0x8200 MASK 16w0xfe00 : parse_set_prio_med;
            16w0x8400 MASK 16w0xfc00 : parse_set_prio_med;
            16w0x8800 MASK 16w0xff00 : parse_set_prio_med;
            default: accept;
        }
    }



    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.tcp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.tcp.dstPort;
        transition select(hdr.tcp.dstPort) {
            TCP_PORT_BGP : parse_set_prio_med;
            TCP_PORT_MSDP : parse_set_prio_med;
            default: accept;
        }
    }


    state parse_roce_v2 {
        pkt.extract(hdr.roce_v2);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.l3_metadata.lkp_outer_l4_sport = hdr.udp.srcPort;
        meta.l3_metadata.lkp_outer_l4_dport = hdr.udp.dstPort;
        transition select(hdr.udp.dstPort) {
            UDP_PORT_VXLAN : parse_vxlan;
            UDP_PORT_GENV: parse_geneve;
            // vxlan-gpe is only supported in the context of INT at this time
            UDP_PORT_VXLAN_GPE : parse_vxlan_gpe;
            UDP_PORT_BOOTPS : parse_set_prio_med;
            UDP_PORT_BOOTPC : parse_set_prio_med;
            UDP_PORT_DHCPV6_CLIENT : parse_set_prio_med;
            UDP_PORT_DHCPV6_SERVER : parse_set_prio_med;
            UDP_PORT_RIP : parse_set_prio_med;
            UDP_PORT_RIPNG : parse_set_prio_med;
            UDP_PORT_HSRP : parse_set_prio_med;
            UDP_PORT_SFLOW : parse_sflow;
            default: accept;
        }
    }

    state parse_gpe_int_header {
        // GPE uses a shim header to preserve the next_protocol field
        pkt.extract(hdr.vxlan_gpe_int_header);
        // P4 14 - 15.7 Field Value Conversions
        // https://github.com/p4lang/p4c/issues/2023
        meta.int_metadata.gpe_int_hdr_len = (bit<16>)hdr.vxlan_gpe_int_header.len;
        transition parse_int_header;
    }
    state parse_int_header {
        pkt.extract(hdr.int_header);
        meta.int_metadata.instruction_cnt = (bit<16>)hdr.int_header.ins_cnt;
        transition select (hdr.int_header.rsvd1, hdr.int_header.total_hop_cnt) {
            // reserved bits = 0 and total_hop_cnt == 0
            // no int_values are added by upstream
            (5w0x00, 8w0x00) : accept;
            // parse INT val headers added by upstream devices (total_hop_cnt != 0)
            // reserved bits must be 0
            (5w0x00 MASK 5w0xf, 8w0x00 MASK 8w0x00) : parse_int_val;
            default: accept;
            // never transition to the following state
            default: parse_all_int_meta_value_heders;
        }
    }


    state parse_int_val {
        pkt.extract(hdr.int_val.next);
        transition select(hdr.int_val.last.bos) {
            0 : parse_int_val;
            1 : parse_inner_ethernet;
        }
    }

    state parse_all_int_meta_value_heders {
        // bogus state.. just extract all possible int headers in the
        // correct order to build
        // the correct parse graph for deparser (while adding headers)
        pkt.extract(hdr.int_switch_id_header);
        pkt.extract(hdr.int_ingress_port_id_header);
        pkt.extract(hdr.int_hop_latency_header);
        pkt.extract(hdr.int_q_occupancy_header);
        pkt.extract(hdr.int_ingress_tstamp_header);
        pkt.extract(hdr.int_egress_port_id_header);
        pkt.extract(hdr.int_q_congestion_header);
        pkt.extract(hdr.int_egress_port_tx_utilization_header);
        transition parse_int_val;
    }



    state parse_sctp {
        pkt.extract(hdr.sctp);
        transition accept;
    }


    state parse_gre {
        pkt.extract(hdr.gre);
        transition select(hdr.gre.C, hdr.gre.R, hdr.gre.K, hdr.gre.S, hdr.gre.s,
                      hdr.gre.recurse, hdr.gre.flags, hdr.gre.ver, hdr.gre.proto) {
            (1w0x0, 1w0x0, 1w0x1, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x6558): parse_nvgre;
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x800): parse_gre_ipv4;
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x86dd): parse_gre_ipv6;
            (1w0x0, 1w0x0, 1w0x0, 1w0x0, 1w0x0, 3w0x0, 5w0x0, 3w0x0, 16w0x22eb): parse_erspan_t3;
            default: accept;
        }
    }

    state parse_gre_ipv4 {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_GRE;
        transition parse_inner_ipv4;
    }

    state parse_gre_ipv6 {
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_GRE;
        transition parse_inner_ipv6;
    }


    state parse_nvgre {
        pkt.extract(hdr.nvgre);
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_NVGRE;
        meta.tunnel_metadata.tunnel_vni = hdr.nvgre.tni;
        transition parse_inner_ethernet;
    }



    state parse_erspan_t3 {
        pkt.extract(hdr.erspan_t3_header);
        transition parse_inner_ethernet;
    }

    state parse_arp_rarp {
        transition parse_set_prio_med;
    }



    state parse_eompls {
        //extract(eompls);
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_MPLS_L2VPN;
        transition parse_inner_ethernet;
    }



    state parse_vxlan {
        pkt.extract(hdr.vxlan);
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_VXLAN;
        meta.tunnel_metadata.tunnel_vni = hdr.vxlan.vni;
        transition parse_inner_ethernet;
    }

    state parse_vxlan_gpe {
        pkt.extract(hdr.vxlan_gpe);
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_VXLAN_GPE;
        meta.tunnel_metadata.tunnel_vni = hdr.vxlan_gpe.vni;
        transition select(hdr.vxlan_gpe.flags, hdr.vxlan_gpe.next_proto)
        {
            (8w0x8 &&& 8w0x8, 8w0x5 &&& 8w0xff) : parse_gpe_int_header;
            default : parse_inner_ethernet;
        }
    }



    state parse_geneve {
        pkt.extract(hdr.genv);
        meta.tunnel_metadata.tunnel_vni = hdr.genv.vni;
        meta.tunnel_metadata.ingress_tunnel_type = INGRESS_TUNNEL_TYPE_GENEVE;
        transition select(hdr.genv.ver, hdr.genv.optLen, hdr.genv.protoType) {
            (2w0x0, 6w0x0, 16w0x6558) : parse_inner_ethernet;
            (2w0x0, 6w0x0, 16w0x800): parse_inner_ipv4;
            (2w0x0, 6w0x0, 16w0x86dd): parse_inner_ipv6;
            default: accept;
        }
    }



    state parse_nsh {
        pkt.extract(hdr.nsh);
        pkt.extract(hdr.nsh_context);
        transition select(hdr.nsh.protoType) {
            ETHERTYPE_IPV4 : parse_inner_ipv4;
            ETHERTYPE_IPV6 : parse_inner_ipv6;
            ETHERTYPE_ETHERNET : parse_inner_ethernet;
            default : accept;
        }
    }



    state parse_lisp {
        pkt.extract(hdr.lisp);
        transition select((pkt.lookahead<bit<4>>())[3:0]) {
            0x4 : parse_inner_ipv4;
            0x6 : parse_inner_ipv6;
            default : accept;
        }
    }

    state parse_inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
        meta.ipv4_metadata.lkp_ipv4_sa = hdr.inner_ipv4.srcAddr;
        meta.ipv4_metadata.lkp_ipv4_da = hdr.inner_ipv4.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.inner_ipv4.protocol;
        meta.l3_metadata.lkp_ip_ttl = hdr.inner_ipv4.ttl;
        transition select(hdr.inner_ipv4.fragOffset, hdr.inner_ipv4.ihl, hdr.inner_ipv4.protocol) {
            (13w0x0, 4w0x5, 8w0x1): parse_inner_icmp;
            (13w0x0, 4w0x5, 8w0x6): parse_inner_tcp;
            (13w0x0, 4w0x5, 8w0x11): parse_inner_udp;
            default: accept;
        }
    }



    state parse_inner_icmp {
        pkt.extract(hdr.inner_icmp);
        meta.l3_metadata.lkp_l4_sport = hdr.inner_icmp.typeCode;
        transition accept;
    }


    state parse_inner_tcp {
        pkt.extract(hdr.inner_tcp);
        meta.l3_metadata.lkp_l4_sport = hdr.inner_tcp.srcPort;
        meta.l3_metadata.lkp_l4_dport = hdr.inner_tcp.dstPort;
        transition accept;
    }



    state parse_inner_udp {
        pkt.extract(hdr.inner_udp);
        meta.l3_metadata.lkp_l4_sport = hdr.inner_udp.srcPort;
        meta.l3_metadata.lkp_l4_dport = hdr.inner_udp.dstPort;
        transition accept;
    }



    state parse_inner_sctp {
        pkt.extract(hdr.inner_sctp);
        transition accept;
    }

    state parse_inner_ipv6 {
        pkt.extract(hdr.inner_ipv6);
        meta.ipv6_metadata.lkp_ipv6_sa = hdr.inner_ipv6.srcAddr;
        meta.ipv6_metadata.lkp_ipv6_da = hdr.inner_ipv6.dstAddr;
        meta.l3_metadata.lkp_ip_proto = hdr.inner_ipv6.nextHdr;
        meta.l3_metadata.lkp_ip_ttl = hdr.inner_ipv6.hopLimit;
        transition select(hdr.inner_ipv6.nextHdr) {
            IP_PROTOCOLS_ICMPV6 : parse_inner_icmp;
            IP_PROTOCOLS_TCP : parse_inner_tcp;
            IP_PROTOCOLS_UDP : parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_ethernet {
        pkt.extract(hdr.inner_ethernet);
        meta.l2_metadata.lkp_mac_sa = hdr.inner_ethernet.srcAddr;
        meta.l2_metadata.lkp_mac_da = hdr.inner_ethernet.dstAddr;
        transition select(hdr.inner_ethernet.etherType) {
            ETHERTYPE_IPV4 : parse_inner_ipv4;
            ETHERTYPE_IPV6 : parse_inner_ipv6;
            default: accept;
        }
    }



    state parse_trill {
        pkt.extract(hdr.trill);
        transition parse_inner_ethernet;
    }



    state parse_vntag {
        pkt.extract(hdr.vntag);
        transition parse_inner_ethernet;
    }



    state parse_bfd {
        pkt.extract(hdr.bfd);
        transition parse_set_prio_max;
    }



    state parse_sflow {
        pkt.extract(hdr.sflow);
        transition accept;
    }



    state parse_fabric_header {
        pkt.extract(hdr.fabric_header);
        transition select(hdr.fabric_header.packetType) {
            FABRIC_HEADER_TYPE_UNICAST : parse_fabric_header_unicast;
            FABRIC_HEADER_TYPE_MULTICAST : parse_fabric_header_multicast;
            FABRIC_HEADER_TYPE_MIRROR : parse_fabric_header_mirror;
            FABRIC_HEADER_TYPE_CPU : parse_fabric_header_cpu;
            default : accept;
        }
    }

    state parse_fabric_header_unicast {
        pkt.extract(hdr.fabric_header_unicast);
        transition parse_fabric_payload_header;
    }

    state parse_fabric_header_multicast {
        pkt.extract(hdr.fabric_header_multicast);
        transition parse_fabric_payload_header;
    }

    state parse_fabric_header_mirror {
        pkt.extract(hdr.fabric_header_mirror);
        transition parse_fabric_payload_header;
    }

    state parse_fabric_header_cpu {
        pkt.extract(hdr.fabric_header_cpu);
        meta.ingress_metadata.bypass_lookups = hdr.fabric_header_cpu.reasonCode;
        transition select(hdr.fabric_header_cpu.reasonCode) {
            CPU_REASON_CODE_SFLOW: parse_fabric_sflow_header;
            default : parse_fabric_payload_header;
        }
    }

    state parse_fabric_sflow_header {
        pkt.extract(hdr.fabric_header_sflow);
        transition parse_fabric_payload_header;
    }

    state parse_fabric_payload_header {
        pkt.extract(hdr.fabric_payload_header);
        transition select(hdr.fabric_payload_header.etherType) {
            0 MASK 16w0xfe00: parse_llc_header;
            0 MASK 16w0xfa00: parse_llc_header;
            PARSE_ETHERTYPE;
        }
    }

    state parse_set_prio_med {
        meta.intrinsic_metadata.priority = CONTROL_TRAFFIC_PRIO_3;
        transition accept;
    }

    state parse_set_prio_high {
        meta.intrinsic_metadata.priority = CONTROL_TRAFFIC_PRIO_5;
        transition accept;
    }

    state parse_set_prio_max {
        meta.intrinsic_metadata.priority = CONTROL_TRAFFIC_PRIO_7;
        transition accept;
    }

}

// extern Checksum16 {  
//     bit<16> get<D>(in D data); 
// }

// control ComputeChecksum<H, M>(inout H hdr,
//                               inout M meta);



control updateChecksum (inout headers_t hdr, inout metadata_t meta) { 
    apply{
        update_checksum(hdr.inner_ipv4.ihl == 5, 
                        { 
                            hdr.ipv4.version,
                            hdr.ipv4.ihl,
                            hdr.ipv4.diffserv,
                            hdr.ipv4.totalLen,
                            hdr.ipv4.identification,
                            hdr.ipv4.flags,
                            hdr.ipv4.fragOffset,
                            hdr.ipv4.ttl,
                            hdr.ipv4.protocol,
                            hdr.ipv4.srcAddr,
                            hdr.ipv4.dstAddr 
                        }, 
                        hdr.ipv4.hdrChecksum, 
                        HashAlgorithm.csum16);
    } 
}

// control VerifyChecksum<H, M>(inout H hdr,
//                              inout M meta);

// control verifyChecksum (inout headers_t hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) { 
control verifyChecksum(inout headers_t hdr, inout metadata_t meta){
    // TODO check the condition ihl==5
    apply{
        // verify_checksum(hdr.inner_ipv4.ihl == 5, 
        //             { 
        //                 hdr.ipv4.version,
        //                 hdr.ipv4.ihl,
        //                 hdr.ipv4.diffserv,
        //                 hdr.ipv4.totalLen,
        //                 hdr.ipv4.identification,
        //                 hdr.ipv4.flags,
        //                 hdr.ipv4.fragOffset,
        //                 hdr.ipv4.ttl,
        //                 hdr.ipv4.protocol,
        //                 hdr.ipv4.srcAddr,
        //                 hdr.ipv4.dstAddr 
        //             }, 
        //             hdr.ipv4.hdrChecksum, 
        //             HashAlgorithm.csum16);
    
        // * Verifies the checksum of the supplied data.  If this method detects
        // * that a checksum of the data is not correct, then the value of the
        // * standard_metadata checksum_error field will be equal to 1 when the
        // * packet begins ingress processing.
    } 
}

// // from v1model
// control VerifyChecksum(inout headers_t hdr) {
//     apply {
//         // Verify ipv4 checsum
//         if(hdr.ipv4.ihl==5){
//             verify_checksum(
//                 hdr.ipv4.isValid(),
//                 { 
//                     hdr.ipv4.version,
//                     hdr.ipv4.ihl,
//                     hdr.ipv4.diffserv,
//                     hdr.ipv4.totalLen,
//                     hdr.ipv4.identification,
//                     hdr.ipv4.flags,
//                     hdr.ipv4.fragOffset,
//                     hdr.ipv4.ttl,
//                     hdr.ipv4.protocol,
//                     hdr.ipv4.srcAddr,
//                     hdr.ipv4.dstAddr 
//                 },
//                 hdr.ipv4.hdrChecksum,
//                 HashAlgorithm.csum16
//             );
//         }

//         if(hdr.inner_ipv4.ihl==5){
//             // Verify checksum
//             verify_checksum(
//                 hdr.inner_ipv4.isValid(),
//                 { 
//                     hdr.inner_ipv4.version,
//                     hdr.inner_ipv4.ihl,
//                     hdr.inner_ipv4.diffserv,
//                     hdr.inner_ipv4.totalLen,
//                     hdr.inner_ipv4.identification,
//                     hdr.inner_ipv4.flags,
//                     hdr.inner_ipv4.fragOffset,
//                     hdr.inner_ipv4.ttl,
//                     hdr.inner_ipv4.protocol,
//                     hdr.inner_ipv4.srcAddr,
//                     hdr.inner_ipv4.dstAddr
//                 },
//                 hdr.inner_ipv4.hdrChecksum, 
//                 HashAlgorithm.csum16
//             );
//         }
//     }
// }

// control ComputeChecksum(inout headers_t hdr) {
//     apply {
//         if(hdr.ipv4.ihl==5){
//             // Update ipv4 checksum
//             update_checksum(
//                 hdr.ipv4.isValid(),
//                 { 
//                     hdr.ipv4.version,
//                     hdr.ipv4.ihl,
//                     hdr.ipv4.diffserv,
//                     hdr.ipv4.totalLen,
//                     hdr.ipv4.identification,
//                     hdr.ipv4.flags,
//                     hdr.ipv4.fragOffset,
//                     hdr.ipv4.ttl,
//                     hdr.ipv4.protocol,
//                     hdr.ipv4.srcAddr,
//                     hdr.ipv4.dstAddr
//                 },
//                 hdr.ipv4.hdrChecksum, 
//                 HashAlgorithm.csum16
//             );
//         }

//         if(hdr.inner_ipv4.ihl==5){
//             // Update checksum
//             update_checksum(
//                 hdr.inner_ipv4.isValid(),
//                 { 
//                     hdr.inner_ipv4.version,
//                     hdr.inner_ipv4.ihl,
//                     hdr.inner_ipv4.diffserv,
//                     hdr.inner_ipv4.totalLen,
//                     hdr.inner_ipv4.identification,
//                     hdr.inner_ipv4.flags,
//                     hdr.inner_ipv4.fragOffset,
//                     hdr.inner_ipv4.ttl,
//                     hdr.inner_ipv4.protocol,
//                     hdr.inner_ipv4.srcAddr,
//                     hdr.inner_ipv4.dstAddr
//                 },
//                 hdr.inner_ipv4.hdrChecksum, 
//                 HashAlgorithm.csum16
//             );
//         }
//     }
// }

