#include <core.p4>
#include <v1model.p4>
#include "defines.p4"

// intrinsic.p4
header ingress_intrinsic_metadata_t {
        bit<1> resubmit_flag;              // flag distinguishing original packets
                                        // from resubmitted packets.

        bit<48> ingress_global_timestamp;     // global timestamp (ns) taken upon
                                        // arrival at ingress.

        bit<16> mcast_grp;                 // multicast group id (key for the
                                        // mcast replication table)

        bit<1> deflection_flag;            // flag indicating whether a packet is
                                        // deflected due to deflect_on_drop.
        bit<1> deflect_on_drop;            // flag indicating whether a packet can
                                        // be deflected by TM on congestion drop

        bit<2> enq_congest_stat;           // queue congestion status at the packet
                                        // enqueue time.

        bit<2> deq_congest_stat;           // queue congestion status at the packet
                                        // dequeue time.

        bit<13> mcast_hash;                // multicast hashing

        bit<16> egress_rid;                // Replication ID for multicast

        bit<32> lf_field_list;             // Learn filter field list

        bit<3> priority;                   // set packet priority

        bit<3> ingress_cos;                 // ingress cos

        bit<2> packet_color;                // packet color

        bit<5> qid;                         // queue id

        bit<7> pad;
}

header queueing_metadata_t {
        bit<48> enq_timestamp;
        bit<16> enq_qdepth;                // queue depth at the packet enqueue
                                        // time.
        bit<32> deq_timedelta;
        bit<16> deq_qdepth;
}

// ACL metadata
header acl_metadata_t {
    bit<1> acl_deny;                          /* ifacl/vacl deny action */
    bit<1> racl_deny;                         /* racl deny action */
    bit<16> acl_nexthop;                      /* next hop from ifacl/vacl */
    bit<16> racl_nexthop;                     /* next hop from racl */
    bit<2> acl_nexthop_type;                  /* ecmp or nexthop */
    bit<2> racl_nexthop_type;                 /* ecmp or nexthop */
    bit<1> acl_redirect;                    /* ifacl/vacl redirect action */
    bit<1> racl_redirect;                     /* racl redirect action */
    bit<16> if_label;                         /* if label for acls */
    bit<16> bd_label;                         /* bd label for acls */
    bit<14> acl_stats_index;                  /* acl stats index */
    bit<16> egress_if_label;                  /* if label for egress acls */
    bit<16> egress_bd_label;                  /* bd label for egress acls */
    bit<8> ingress_src_port_range_id;         /* ingress src port range id */
    bit<8>ingress_dst_port_range_id;          /* ingress dst port range id */
    bit<8> egress_src_port_range_id;          /* egress src port range id */
    bit<8> egress_dst_port_range_id;          /* egress dst port range id */
    bit<2> pad;
}

header i2e_metadata_t {
    bit<32> ingress_tstamp;
    bit<16> mirror_session_id;
}

// switch.p4

header ingress_metadata_t {
        bit<9> ingress_port;                      /* input physical port */
        bit<IFINDEX_BIT_WIDTH> ifindex;           /* input interface index */
        bit<IFINDEX_BIT_WIDTH> egress_ifindex;    /* egress interface index */
        bit<2> port_type;                        /* ingress port type */

        bit<BD_BIT_WIDTH> outer_bd;               /* outer BD */
        bit<BD_BIT_WIDTH> bd;                     /* BD */

        bit<1> drop_flag;                         /* if set, drop the packet */
        bit<8> drop_reason;                       /* drop reason */
        bit<1> control_frame;                      /* control frame */
        bit<16> bypass_lookups;                   /* list of lookups to skip */
        bit<32> sflow_take_sample;
        bit<3> pad;

}

header egress_metadata_t {
        bit<1> bypass;                            /* bypass egress pipeline */
        bit<2> port_type;                        /* egress port type */
        bit<16> payload_length;                   /* payload length for tunnels */
        bit<9> smac_idx;                          /* index into source mac table */
        bit<BD_BIT_WIDTH> bd;                     /* egress inner bd */
        bit<BD_BIT_WIDTH> outer_bd;               /* egress inner bd */
        bit<48> mac_da;                           /* final mac da */
        bit<1> routed;                            /* is this replica routed */
        bit<BD_BIT_WIDTH> same_bd_check;          /* ingress bd xor egress bd */
        bit<8> drop_reason;                       /* drop reason */
        bit<IFINDEX_BIT_WIDTH> ifindex;           /* egress interface index */
        bit<3> pad;
}

/* Global config information */
header global_config_metadata_t {
    bit<1> enable_dod;                        /* Enable Deflection-on-Drop */
    bit<7> pad;
        /* Add more global parameters such as switch_id.. */
}

// l2
header l2_metadata_t {
    bit<48> lkp_mac_sa;
    bit<48> lkp_mac_da;
    bit<3> lkp_pkt_type;
    bit<16> lkp_mac_type;
    bit<3> lkp_pcp;

    bit<16> l2_nexthop;                       /* next hop from l2 */
    bit<2> l2_nexthop_type;                   /* ecmp or nexthop */
    bit<1> l2_redirect;                       /* l2 redirect action */
    bit<1> l2_src_miss;                       /* l2 source miss */
    bit<IFINDEX_BIT_WIDTH> l2_src_move;       /* l2 source interface mis-match */
    bit<10> stp_group;                         /* spanning tree group id */
    bit<3> stp_state;                         /* spanning tree port state */
    bit<16> bd_stats_idx;                     /* ingress BD stats index */
    bit<1> learning_enabled;                  /* is learning enabled */
    bit<1> port_vlan_mapping_miss;            /* port vlan mapping miss */
    bit<IFINDEX_BIT_WIDTH> same_if_check;     /* same interface check */
    bit<7> pad;
}

// ipv4
header ipv4_metadata_t {
    bit<32> lkp_ipv4_sa;
    bit<32> lkp_ipv4_da;
    bit<1> ipv4_unicast_enabled;      /* is ipv4 unicast routing enabled */
    bit<2> ipv4_urpf_mode;            /* 0: none, 1: strict, 3: loose */
    bit<5> pad;
}

// qos
header qos_metadata_t {
    bit<5> ingress_qos_group;
    bit<5> tc_qos_group;
    bit<5> egress_qos_group;
    bit<8> lkp_tc;
    bit<1> trust_dscp;
    bit<1> trust_pcp;
    bit<7> pad;
}

// meter
header meter_metadata_t {
    bit<2> packet_color;               /* packet color */
    bit<16> meter_index;               /* meter index */
    bit<6> pad;
}

// fabric.p4
header fabric_metadata_t {
        bit<3> packetType;
        bit<1> fabric_header_present;
        bit<16> reason_code;              /* cpu reason code */
        bit<4> pad;

// #ifdef FABRIC_ENABLE
        bit<8> dst_device;                /* destination device id */
        bit<16> dst_port;                 /* destination port id */
// #endif /* FABRIC_ENABLE */
}

// ipv6.p4
header ipv6_metadata_t {
    bit<128> lkp_ipv6_sa;                     /* ipv6 source address */
    bit<128> lkp_ipv6_da;                     /* ipv6 destination address*/

    bit<1> ipv6_unicast_enabled;              /* is ipv6 unicast routing enabled on BD */
    bit<1> ipv6_src_is_link_local;            /* source is link local address */
    bit<2> ipv6_urpf_mode;                    /* 0: none, 1: strict, 3: loose */
    bit<4> pad;
}

// l3.p4
header l3_metadata_t {
        bit<2> lkp_ip_type;
        bit<4> lkp_ip_version;
        bit<8> lkp_ip_proto;
        bit<8> lkp_dscp;
        bit<8> lkp_ip_ttl;
        bit<16> lkp_l4_sport;
        bit<16> lkp_l4_dport;
        bit<16> lkp_outer_l4_sport;
        bit<16> lkp_outer_l4_dport;

        bit<VRF_BIT_WIDTH> vrf;                   /* VRF */
        bit<10> rmac_group;                       /* Rmac group, for rmac indirection */
        bit<1> rmac_hit;                          /* dst mac is the router's mac */
        bit<2> urpf_mode;                         /* urpf mode for current lookup */
        bit<1> urpf_hit;                          /* hit in urpf table */
        bit<1> urpf_check_fail;                    /* urpf check failed */
        bit<BD_BIT_WIDTH> urpf_bd_group;          /* urpf bd group */
        bit<1> fib_hit;                           /* fib hit */
        bit<16> fib_nexthop;                      /* next hop from fib */
        bit<2> fib_nexthop_type;                  /* ecmp or nexthop */
        bit<BD_BIT_WIDTH> same_bd_check;          /* ingress bd xor egress bd */
        bit<16> nexthop_index;                    /* nexthop/rewrite index */
        bit<1> routed;                            /* is packet routed? */
        bit<1> outer_routed;                      /* is outer packet routed? */
        bit<8> mtu_index;                         /* index into mtu table */
        bit<1> l3_copy;                           /* copy packet to CPU */
        bit<16> l3_mtu_check;        /* result of mtu check */

        bit<16> egress_l4_sport;
        bit<16> egress_l4_dport;
        bit<5> pad;
}

// nat.p4
header nat_metadata_t {
    bit<2> ingress_nat_mode;          /* 0: none, 1: inside, 2: outside */
    bit<2> egress_nat_mode;           /* nat mode of egress_bd */
    bit<16> nat_nexthop;              /* next hop from nat */
    bit<2> nat_nexthop_type;          /* ecmp or nexthop */
    bit<1> nat_hit;                   /* fwd and rewrite info from nat */
    bit<14> nat_rewrite_index;        /* NAT rewrite index */
    bit<1> update_checksum;           /* update tcp/udp checksum */
    bit<1> update_inner_checksum;     /* update inner tcp/udp checksum */
    bit<16> l4_len;                   /* l4 length */
    bit<1> pad;
}

// tunnel.p4
header tunnel_metadata_t {
    bit<5> ingress_tunnel_type;               /* tunnel type from parser */
    bit<24> tunnel_vni;                       /* tunnel id */
    bit<1> mpls_enabled;                      /* is mpls enabled on BD */
    bit<20> mpls_label;                        /* Mpls label */
    bit<3> mpls_exp;                           /* Mpls Traffic Class */
    bit<8> mpls_ttl;                           /* Mpls Ttl */
    bit<5> egress_tunnel_type;                /* type of tunnel */
    bit<14> tunnel_index;                      /* tunnel index */
    bit<9> tunnel_src_index;                  /* index to tunnel src ip */
    bit<9> tunnel_smac_index;                 /* index to tunnel src mac */
    bit<14> tunnel_dst_index ;                 /* index to tunnel dst ip */
    bit<14> tunnel_dmac_index ;                /* index to tunnel dst mac */
    bit<24> vnid;                             /* tunnel vnid */
    bit<1> tunnel_terminate;                  /* is tunnel being terminated? */
    bit<1> tunnel_if_check;                   /* tun terminate xor originate */
    bit<4> egress_header_count;                /* number of mpls header stack */
    bit<8> inner_ip_proto ;                    /* Inner IP protocol */
    bit<1> skip_encap_inner;                  /* skip encap_process_inner */
    bit<3> pad;
}

// multicast.p4
header multicast_metadata_t {
        bit<1> ipv4_mcast_key_type;               /* 0 bd, 1 vrf */
        bit<BD_BIT_WIDTH> ipv4_mcast_key;         /* bd or vrf value */
        bit<1> ipv6_mcast_key_type;               /* 0 bd, 1 vrf */
        bit<BD_BIT_WIDTH> ipv6_mcast_key;         /* bd or vrf value */
        bit<1> outer_mcast_route_hit;             /* hit in the outer multicast table */
        bit<2> outer_mcast_mode;                  /* multicast mode from route */
        bit<1> mcast_route_hit;                   /* hit in the multicast route table */
        bit<1> mcast_bridge_hit;                  /* hit in the multicast bridge table */
        bit<1> ipv4_multicast_enabled;            /* is ipv4 multicast enabled on BD */
        bit<1> ipv6_multicast_enabled;            /* is ipv6 multicast enabled on BD */
        bit<1> igmp_snooping_enabled;             /* is IGMP snooping enabled on BD */
        bit<1> mld_snooping_enabled;              /* is MLD snooping enabled on BD */
        bit<BD_BIT_WIDTH> bd_mrpf_group;          /* rpf group from bd lookup */
        bit<BD_BIT_WIDTH> mcast_rpf_group;        /* rpf group from mcast lookup */
        bit<2> mcast_mode;                        /* multicast mode from route */
        bit<16> multicast_route_mc_index;         /* multicast index from mfib */
        bit<16> multicast_bridge_mc_index;        /* multicast index from igmp/mld snoop */
        bit<1> inner_replica;                     /* is copy is due to inner replication */
        bit<1> replica;                           /* is this a replica */
// #ifdef FABRIC_ENABLE
        bit<16> mcast_grp;
// #endif /* FABRIC_ENABLE */
        bit<1> pad;
}

// nexthop.p4
header nexthop_metadata_t {
    bit<2> nexthop_type;                        /* final next hop index type */
    bit<6> pad;
}

// security.p4
header security_metadata_t {
    bit<1> ipsg_enabled;                      /* is ip source guard feature enabled */
    bit<1> ipsg_check_fail;                   /* ipsg check failed */
    bit<6> pad;
}

// openflow.p4
header openflow_metadata_t {
    bit<32> index;
    bit<32> bmap;
    bit<32> group_id;
    bit<1> ofvalid;
    bit<7> pad;
}

// hashes.p4
header hash_metadata_t {
    bit<16> hash1;
    bit<16> hash2;
    bit<16> entropy_hash;
}

// egress_filter.p4
header egress_filter_metadata_t {
    bit<IFINDEX_BIT_WIDTH> ifindex_check;     /* src port filter */
    bit<BD_BIT_WIDTH> bd;                     /* bd for src port filter */
    bit<BD_BIT_WIDTH> inner_bd;               /* split horizon filter */
}

// int_transit.p4
header int_metadata_t {
    bit<32> switch_id ;
    bit<8> insert_cnt;
    bit<16> insert_byte_cnt;
    bit<16> gpe_int_hdr_len;
    bit<8> gpe_int_hdr_len8;
    bit<16> instruction_cnt;
}

header int_metadata_i2e_t {
        bit<1> sink;
        bit<1> source;
        bit<6> pad;
}

// sflow.p4
header sflow_meta_t {
    bit<16> sflow_session_id;
}