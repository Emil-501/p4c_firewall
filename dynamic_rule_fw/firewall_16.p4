#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_ARP  = 0x806;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTOCOLS_IPHL_ICMP = 0x01;
const bit<8> IP_PROTOCOLS_IPHL_TCP  = 0x06;
const bit<8> IP_PROTOCOLS_IPHL_UDP  = 0x11;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
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
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
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

// Reason 1 is because nat int_ext_miss
// 8 bits just to test and maybe we need more 'reasons'
header controller_header_t { 
    bit<8> reason;
    bit<9> fromPort;
    bit<32> filler;
} 

struct meta_t {
    bit<16> tcpLength;
} 

struct metadata {
    meta_t meta;
}

struct headers {
    ethernet_t           ethernet;
    ipv4_t               ipv4;
    icmp_t               icmp;
    tcp_t                tcp;
    udp_t                udp;
    controller_header_t  controller_header;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser SwitchParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(packet.lookahead<bit<48>>()) {
            0 : parse_controller_header;
            default: parse_ethernet;
        }
    }

    state parse_controller_header {
        packet.extract(hdr.controller_header);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_IPHL_TCP:  parse_tcp;
            IP_PROTOCOLS_IPHL_UDP:  parse_udp;
            IP_PROTOCOLS_IPHL_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control SwitchVerifyChecksum(in headers hdr, inout metadata meta) {   
    apply {  } // TODO: IP and TCP verify
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    //NAT
    //nat and send out external port
    action nat_int_ext_hit(egressSpec_t port, ip4Addr_t srcAddr, bit<16> srcPort) {
        standard_metadata.egress_spec = port;

        hdr.ipv4.srcAddr = srcAddr;
        hdr.tcp.srcPort = srcPort;
    }

    //nat and allow in - send to port that original/outgoing request came from
    action nat_ext_int_hit(egressSpec_t port, ip4Addr_t dstAddr, bit<16> dstPort) {
        standard_metadata.egress_spec = port;    
        hdr.ipv4.dstAddr = dstAddr;
        hdr.tcp.dstPort = dstPort;
    }

    //update rule - port number is controller port
    action nat_int_ext_miss(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    //drop
    action nat_ext_int_miss() {
        mark_to_drop();
    }

    action controller_pkt(egressSpec_t port) {
        hdr.controller_header.setInvalid();
        standard_metadata.egress_spec = port; //set to external port
    }

    action drop() {
        mark_to_drop();
    }

    table nat {
        key = {
            standard_metadata.ingress_port : exact; 
            hdr.ipv4.isValid() : exact;
            hdr.tcp.isValid() : exact;
            hdr.ipv4.srcAddr : ternary;
            hdr.ipv4.dstAddr : ternary;
            hdr.tcp.srcPort : ternary;
            hdr.tcp.dstPort : ternary;
        }
        actions = {
            nat_int_ext_hit;
            nat_ext_int_hit;
            nat_int_ext_miss;
            nat_ext_int_miss; //make default
            controller_pkt;
        }
        support_timeout = true;
    }

    apply { 
        nat.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action do_add_header() {
        hdr.controller_header.setValid();
        hdr.controller_header.reason = 1; // Reason 1 is because nat int_ext_miss
        hdr.controller_header.fromPort = standard_metadata.ingress_port; //to remember which port to return request to
    }

    table to_controller {
        key = {
            standard_metadata.egress_port : exact;  //controller port number
        }
        actions = { 
            do_add_header; 
        }
        size = 1; // will there always only be one controller? size : 1;?
    }

    apply { 
        to_controller.apply();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control SwitchComputeChecksum(inout headers  hdr, inout metadata meta) {
    Checksum16() ipv4_checksum;

    apply {
        if (hdr.ipv4.isValid()) { 
            hdr.ipv4.hdrChecksum = ipv4_checksum.get(
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
            });
        }
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control SwitchDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
SwitchParser(),
SwitchVerifyChecksum(),
SwitchIngress(),
SwitchEgress(),
SwitchComputeChecksum(),
SwitchDeparser()
) main;
