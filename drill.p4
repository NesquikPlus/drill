#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

const bit<16> TYPE_IPV4 = 0x800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/** Determines the header fields for ethernet layer.**/
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/**Determines the header fields for network layer.**/
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

/**Determines the header fields for transport layer.**/
header ports_t{
    bit<16> src_port;
    bit<16> dst_port;
};

struct metadata {
    bit<2> randIdx1;
    bit<2> randIdx2;
    bit<2> prevIdx;
    bit<19> lenIdx1;
    bit<19> lenIdx2;
    bit<19> lenPrevIdx;
    bit<2> randGen;
}

/**The header fields are accessed based on the header types defined in here**/
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ports_t      ports;
}

register<bit<19>>(4) queue_lengths;//Standard metadata enq_qdepth is 19 bits long.
register<bit<2>>(1) prevIdx;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) 
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 
    {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) 
        {
            0x06: parse_layer4; /**TCP**/
            0x11: parse_layer4; /**UDP**/
            default: accept;
        }        
    }

    state parse_layer4
    {
        packet.extract(hdr.ports);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control IngressProcess(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }


    apply 
    {
        if(standard_metadata.ingress_port == 1) 
        {
            if (hdr.ipv4.isValid())
            {
            	/* Choose two random ports */
                random(meta.randIdx1, 0, 3); 
                random(meta.randIdx2, 0, 3);

                /* 
                Read the prevIdx register 
                holds the index of the minimum length port that a packet was sent.
                */
                prevIdx.read(meta.prevIdx, 0);


                /*Read queue_lengths registers into metadata.*/
                /*Randomly chosen 2 ports and previously known min len port*/
                queue_lengths.read(meta.lenIdx1, (bit<32>) meta.randIdx1);
                queue_lengths.read(meta.lenIdx2, (bit<32>) meta.randIdx2);
                queue_lengths.read(meta.lenPrevIdx, (bit<32>) meta.prevIdx);

                /*Compare the 3 queue_lengths read into metadata*/
                /* In the case of equality generate a random number*/
                if(meta.lenPrevIdx < meta.lenIdx1)
                {
                	if(meta.lenPrevIdx < meta.lenIdx2)
                	{
                		standard_metadata.egress_spec = (bit<9>) meta.prevIdx + 2;
                	}
                	else if(meta.lenPrevIdx == meta.lenIdx2)
                	{
                		random(meta.randGen, 0, 1); 
                		if(meta.randGen == 0){
                			standard_metadata.egress_spec = (bit<9>) meta.prevIdx + 2;
                		}
                		else{
                			standard_metadata.egress_spec = (bit<9>) meta.randIdx2 + 2;
                		}
                	}
                	else
                	{
                		standard_metadata.egress_spec = (bit<9>) meta.randIdx2 + 2;
                	}
                }
                else if(meta.lenPrevIdx == meta.lenIdx1)
                {
                	if(meta.lenPrevIdx < meta.lenIdx2)
                	{
                		standard_metadata.egress_spec = (bit<9>) meta.prevIdx + 2;
                	}
                	else if(meta.lenPrevIdx == meta.lenIdx2)
                	{
                		random(meta.randGen, 0, 2); 
                		if(meta.randGen == 0){
                			standard_metadata.egress_spec = (bit<9>) meta.prevIdx + 2;
                		}
                		else if(meta.randGen == 1){
                			standard_metadata.egress_spec = (bit<9>) meta.randIdx1 + 2;
                		}
                		else{
                			standard_metadata.egress_spec = (bit<9>) meta.randIdx2 + 2;
                		}
                	}
                	else
                	{
                		standard_metadata.egress_spec = (bit<9>) meta.randIdx2 + 2;
                	}
                }
                else
                {
                	if(meta.lenIdx1 < meta.lenIdx2)
                	{
                		standard_metadata.egress_spec = (bit<9>) meta.randIdx1 + 2;
                	}
                	else if(meta.lenIdx1 == meta.lenIdx2)
                	{
                		random(meta.randGen, 0, 1); 
                		if(meta.randGen == 0){
                			standard_metadata.egress_spec = (bit<9>) meta.randIdx1 + 2;
                		}
                		else{
                			standard_metadata.egress_spec = (bit<9>) meta.randIdx2 + 2;
                		}
                	}
                	else
                	{
                		standard_metadata.egress_spec = (bit<9>) meta.randIdx2 + 2;
                	}
                }
            }
        }  
        else 
        {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control EgressProcess(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) 
{
    /* Queue lengths are written to corresponding registers after each packet.
        The registers will be read by the controller.
    */

    apply
    {
        /*1 is the port packets arrive to the switch.
          6 is the CPU port.
          Rest are egress ports and written to registers.
        */
        if(standard_metadata.egress_port == 2)
        {
            queue_lengths.write(0, standard_metadata.enq_qdepth);
            prevIdx.write(0 , 0);
        }
        else if (standard_metadata.egress_port == 3)
        {
            queue_lengths.write(1, standard_metadata.enq_qdepth);
            prevIdx.write(0 , 1);
        }
        else if(standard_metadata.egress_port == 4)
        {
            queue_lengths.write(2, standard_metadata.enq_qdepth);
            prevIdx.write(0 , 2);
        }
        else if(standard_metadata.egress_port == 5)
        {
            queue_lengths.write(3, standard_metadata.enq_qdepth);
            prevIdx.write(0 , 3);
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ports);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
IngressProcess(),
EgressProcess(),
MyComputeChecksum(),
MyDeparser()
) main;
