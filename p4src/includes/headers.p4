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
#include <core.p4>
#include <v1model.p4>
#include "defines.p4"

header ethernet_t {    
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}


header llc_header_t {    
    bit<8> dsap;
    bit<8> ssap;
    bit<8> control_;
}

header snap_header_t {    
    bit<24> oui;
    bit<16> type_;
}

header roce_header_t {    
    bit<320> ib_grh;
    bit<96> ib_bth;
}

header roce_v2_header_t {   
        bit<96> ib_bth;
    }

header fcoe_header_t {    
    bit<4> version;
    bit<4> type_;
    bit<8> sof;
    bit<32> rsvd1;
    bit<32> ts_upper;
    bit<32> ts_lower;
    bit<32> size_;
    bit<8> eof;
    bit<24> rsvd2;
}

header vlan_tag_t {    
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> etherType;
}

header ieee802_1ah_t {    
    bit<3> pcp;
    bit<1> dei;
    bit<1> uca;
    bit<3> reserved;
    bit<24> i_sid;
}

header mpls_t {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4> version;
    bit<8> trafficClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHdr;
    bit<8> hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header icmp_t {
    bit<16> typeCode;
    bit<16> hdrChecksum;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header sctp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> verifTag;
    bit<32> checksum;
}

header gre_t {
    bit<1> C;
    bit<1> R;
    bit<1> K;
    bit<1> S;
    bit<1> s;
    bit<3> recurse;
    bit<5> flags;
    bit<3> ver;
    bit<16> proto;
}

header nvgre_t {
    bit<24> tni;
    bit<8> flow_id;
}

/* erspan III header - 12 bytes */
header erspan_header_t3_t {
    bit<4> version;
    bit<12> vlan;
    bit<6> priority;
    bit<10> span_id;
    bit<32> timestamp;
    bit<16> sgt;
    bit<16> ft_d_other;
}

header ipsec_esp_t {
    bit<32> spi;
    bit<32> seqNo;
}

header ipsec_ah_t {
    bit<8> nextHdr;
    bit<8> length_;
    bit<16> zero;
    bit<32> spi;
    bit<32> seqNo;
}

header arp_rarp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
}

header arp_rarp_ipv4_t {
    bit<48> srcHwAddr;
    bit<32> srcProtoAddr;
    bit<48> dstHwAddr;
    bit<32> dstProtoAddr;
}

header eompls_t {
    bit<4> zero;
    bit<12> reserved;
    bit<16> seqNo;
}

header vxlan_t {
    bit<8> flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8> reserved2;
}

header vxlan_gpe_t {
    bit<8> flags;
    bit<16> reserved;
    bit<8> next_proto;
    bit<24> vni;
    bit<8> reserved2;
}

header nsh_t {
    bit<1> oam;
    bit<1> context;
    bit<6> flags;
    bit<8> reserved;
    bit<16> protoType;
    bit<24> spath;
    bit<8> sindex;
}

header nsh_context_t {
    bit<32> network_platform;
    bit<32> network_shared;
    bit<32> service_platform;
    bit<32> service_shared;
}

header vxlan_gpe_int_header_t {
    bit<8> int_type;
    bit<8> rsvd;
    bit<8> len;
    bit<8> next_proto;
}

/* GENEVE HEADERS
3 possible options with known type, known length */

header genv_t {
    bit<2> ver;
    bit<6> optLen;
    bit<1> oam;
    bit<1> critical;
    bit<6> reserved;
    bit<16> protoType;
    bit<24> vni;
    bit<8> reserved2;
}

#define GENV_OPTION_A_TYPE 0x000001
/* TODO: Would it be convenient to have some kind of sizeof macro ? */
#define GENV_OPTION_A_LENGTH 2 /* in bytes */

header genv_opt_A_t {
    bit<16> optClass;
    bit<8> optType;
    bit<3> reserved;
    bit<5> optLen;
    bit<32> data;
}


#define GENV_OPTION_B_TYPE 0x000002
#define GENV_OPTION_B_LENGTH 3 /* in bytes */

header genv_opt_B_t {
    bit<16> optClass;
    bit<8> optType;
    bit<3> reserved;
    bit<5> optLen;
    bit<64> data;
}

#define GENV_OPTION_C_TYPE 0x000003
#define GENV_OPTION_C_LENGTH 2 /* in bytes */

header genv_opt_C_t {
    bit<16> optClass;
    bit<8> optType;
    bit<3> reserved;
    bit<5> optLen;
    bit<32> data;
}

header trill_t {
    bit<2> version;
    bit<2> reserved;
    bit<1> multiDestination;
    bit<5> optLength;
    bit<6> hopCount;
    bit<16> egressRbridge;
    bit<16> ingressRbridge;
}

header lisp_t {
    bit<8> flags;
    bit<24> nonce;
    bit<32> lsbsInstanceId;
}

header vntag_t {
    bit<1> direction;
    bit<1> pointer;
    bit<14> destVif;
    bit<1> looped;
    bit<1> reserved;
    bit<2> version;
    bit<12> srcVif;
}

header bfd_t {
    bit<3> version;
    bit<5> diag;
    bit<2> state;
    bit<1> p;
    bit<1> f;
    bit<1> c;
    bit<1> a;
    bit<1> d;
    bit<1> m;
    bit<8> detectMult;
    bit<8> len;
    bit<32> myDiscriminator;
    bit<32> yourDiscriminator;
    bit<32> desiredMinTxInterval;
    bit<32> requiredMinRxInterval;
    bit<32> requiredMinEchoRxInterval;
}

header sflow_hdr_t {
    bit<32> version;
    bit<32> addrType;
    bit<32> ipAddress;
    bit<32> subAgentId;
    bit<32> seqNumber;
    bit<32> uptime;
    bit<32> numSamples;
}

header sflow_sample_t {
    bit<20> enterprise;
    bit<12> format;
    bit<32> sampleLength;
    bit<32> seqNumer;
    bit<8> srcIdType;
    bit<24> srcIdIndex;
    bit<32> samplingRate;
    bit<32> samplePool;
    bit<32> numDrops;
    bit<32> inputIfindex;
    bit<32> outputIfindex;
    bit<32> numFlowRecords;
}

header sflow_raw_hdr_record_t {// this header is attached to each pkt sample (flow_record)

    bit<20> enterprise;
    bit<12> format;
    bit<32> flowDataLength;
    bit<32> headerProtocol;
    bit<32> frameLength;
    bit<32> bytesRemoved;
    bit<32> headerSize;
}


header sflow_sample_cpu_t {
    bit<16> sampleLength;
    bit<32> samplePool;
    bit<16> inputIfindex;
    bit<16> outputIfindex;
    bit<8> numFlowRecords;
    bit<3> sflow_session_id;
    bit<2> pipe_id;
}

#define FABRIC_HEADER_TYPE_NONE        0
#define FABRIC_HEADER_TYPE_UNICAST     1
#define FABRIC_HEADER_TYPE_MULTICAST   2
#define FABRIC_HEADER_TYPE_MIRROR      3
#define FABRIC_HEADER_TYPE_CONTROL     4
#define FABRIC_HEADER_TYPE_CPU         5

header fabric_header_t {
    bit<3> packetType;
    bit<2> headerVersion;
    bit<2> packetVersion;
    bit<1> pad1;

    bit<3> fabricColor;
    bit<5> fabricQos;

    bit<8> dstDevice;
    bit<16> dstPortOrGroup;
}

header fabric_header_unicast_t {
    bit<1> routed;
    bit<1> outerRouted;
    bit<1> tunnelTerminate;
    bit<5> ingressTunnelType;

    bit<16> nexthopIndex;
}

header fabric_header_multicast_t {
    bit<1> routed;
    bit<1> outerRouted;
    bit<1> tunnelTerminate;
    bit<5> ingressTunnelType;

    bit<16> ingressIfindex;
    bit<16> ingressBd;

    bit<16> mcastGrp;
}

header fabric_header_mirror_t {
    bit<16> rewriteIndex;
    bit<10> egressPort;
    bit<5> egressQueue;
    bit<1> pad;
}

header fabric_header_cpu_t {
    bit<5> egressQueue;
    bit<1> txBypass;
    bit<2> reserved;

    bit<16> ingressPort;
    bit<16> ingressIfindex;
    bit<16> ingressBd;

    bit<16> reasonCode;
    bit<16> mcast_grp;
}

header fabric_header_sflow_t {
    bit<16> sflow_session_id;
    bit<16> sflow_egress_ifindex;
}

header fabric_payload_header_t {
    bit<16> etherType;
}

// INT headers
header int_header_t {
    bit<2> ver;
    bit<2> rep;
    bit<1> c;
    bit<1> e;
    bit<5> rsvd1;
    bit<5> ins_cnt;
    bit<8> max_hop_cnt;
    bit<8> total_hop_cnt;
    bit<4> instruction_mask_0003;   // split the bits for lookup
    bit<4> instruction_mask_0407;
    bit<4> instruction_mask_0811;
    bit<4> instruction_mask_1215;
    bit<16> rsvd2;
}
// INT meta-value headers - different header for each value type
header int_switch_id_header_t {
    bit<1> bos;
    bit<31> switch_id;
}
header int_ingress_port_id_header_t {
    bit<1> bos;
    bit<15> ingress_port_id_1;
    bit<16> ingress_port_id_0;
}
header int_hop_latency_header_t {
    bit<1> bos;
    bit<31> hop_latency;
}
header int_q_occupancy_header_t {
    bit<1> bos;
    bit<7> q_occupancy1;
    bit<24> q_occupancy0;
}
header int_ingress_tstamp_header_t {
    bit<1> bos;
    bit<31> ingress_tstamp;
}
header int_egress_port_id_header_t {
    bit<1> bos;
    bit<31> egress_port_id;
}
header int_q_congestion_header_t {
    bit<1> bos;
    bit<31> q_congestion;
}
header int_egress_port_tx_utilization_header_t {
    bit<1> bos;
    bit<31> egress_port_tx_utilization;
}

// generic int value (info) header for extraction
header int_value_t {    
    bit<1> bos;
    bit<31> val;
}

