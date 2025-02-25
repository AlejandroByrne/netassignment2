/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ipAddr_t;
header ethernet_t {
    /* TODO: define Ethernet header */ 
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16> etherType;
}

/* a basic ip header without options and pad */
header ipv4_t {
    /* TODO: define IP header */
    bit<4> version;
    bit<4> hdl;
    bit<8> TOS;
    bit<16> length;
    bit<8> TTL;
    bit<8> protocol;
    bit<16> checksum;
    ipAddr_t srcAddr;
    ipAddr_t dstAddr;
}

struct metadata {
    ipAddr_t next_hop;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

/*************************************************************************
*********************** M A C R O S  ***********************************
*************************************************************************/
#define ETHER_IPV4 0x0800

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }
    state parse_ethernet {
        /* TODO: do ethernet header parsing */
        packet.extract(hdr.ethernet);

        /* if the frame type is IPv4, go to IPv4 parsing */
        if (hdr.ethernet.etherType == ETHER_IPV4) {
            transition parse_ipv4;
        } else {
            transition accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        /* TODO: verify checksum using verify_checksum() extern */
        /* Use HashAlgorithm.csum16 as a hash algorithm */ 
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* define actions */
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward_to_port(bit<9> egress_port, macAddr_t egress_mac) {
        /* TODO: change the packet's source MAC address to egress_mac */
        hdr.ethernet.srcAddr = egress_mac;
        /* Then set the egress_spec in the packet's standard_metadata to egress_port */
        standard_metadata.egress_spec = egress_port; // now the metadata knows which port to send this packet to
    }
   
    action decrement_ttl() {
        /* TODO: decrement the IPv4 header's TTL field by one */
        hdr.ipv4.TTL = hdr.ipv4.TTL - 1;

        if (hdr.ipv4.TTL == 0) { // drop the packet if its TTL reaches zero
            mark_to_drop(standard_metadata);
        }
    }

    action forward_to_next_hop(ipAddr_t next_hop){
        /* TODO: write next_hop to metadata's next_hop field */
        meta.next_hop = next_hop;
    }

    action change_dst_mac (macAddr_t dst_mac) {
        /* TODO: change a packet's destination MAC address to dst_mac*/
        hdr.ethernet.dstAddr = dst_mac;
    }

    /* define routing table */
    table ipv4_route {
        /* TODO: define a static ipv4 routing table */
        key = {
            hdr.ipv4.dstAddr: lpm; // longest-prefix match
        }

        actions = {
            forward_to_next_hop;
            drop;
            NoAction;
        }
        /* Perform longest prefix matching on dstIP then */

        /* record the next hop IP address in the metadata's next_hop field*/
        size = 4;
        default_action = drop();
    }

    /* define static ARP table */
    table arp_table {
        /* TODO: define a static ARP table */
        key = {
            meta.next_hop: exact;
        }

        actions = {
            change_dst_mac;
            drop;
            NoAction;
        }
        /* Perform exact matching on metadata's next_hop field then */
        /* modify the packet's src and dst MAC addresses upon match */
        size = 4;
        default_action = drop();
    }


    /* define forwarding table */
    table dmac_forward {
        /* TODO: define a static forwarding table */
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            forward_to_port;
            drop;
            NoAction;
        }
        /* Perform exact matching on dstMAC then */
        /* forward to the corresponding egress port */ 
        size = 4;
        default_action = drop();
    }
   
    /* applying dmac */
    apply {
        /* TODO: Implement a routing logic */
        /* 1. Lookup IPv4 routing table */
        // At this exact point, it is not known if the packet's dest IP is recognized
        ipv4_route.apply();

        /* 2. Upon hit, lookup ARP table */
        if (!standard_metadata.drop_flag) { // IP addr had a match for the subnet
            arp_table.apply();

            if (!standard_metadata.drop_flag) { // IP addr had a match for routing to another router
                /* 3. Upon hit, Decrement ttl */
                decrement_ttl();

                if (!standard_metadata.drop_flag) { // The packet still has time to live: Next, find the exact port to send it to
                    /* 4. Then lookup forwarding table */ 
                    dmac_forward.apply();
                    // Then, ingress is done and egress should have all the relevant values for sending it off.
                }
            }
        } 
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        /* TODO: calculate the modified packet's checksum */
        /* using update_checksum() extern */
        /* Use HashAlgorithm.csum16 as a hash algorithm */
        
    } 
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
