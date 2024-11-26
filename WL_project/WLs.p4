#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#define MAX_REGISTER_ENTRIES 8192
#define FLOW_TIMEOUT 15000000 /*15 seconds: this timer is used because, since registers are limited
			       this timeout permits to erase the old values which have not been
			       seen since some time*/

#define PACKET_THR 50
#define CLASS_NOT_SET 7

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}


struct metadata {

    bit<8> feature0; 
    bit<8> feature1; 
    bit<32> feature2; 
    bit<32> feature3; 
    bit<32> feature4; 
    bit<32> feature5; 
    bit<32> feature6; 
    bit<32> feature7; 
    bit<32> feature8; 
    bit<32> feature9; 
    bit<1> feature10; 
    bit<1> feature11; 
    bit<1> feature12; 
    bit<1> feature13; 
    bit<1> feature14; 
    bit<1> feature15; 
    bit<1> feature16; 
    bit<32> feature17; 
    bit<32> feature18; 
    bit<32> feature19; 
    bit<16> feature20;
    bit<16> feature21;
    bit<16> feature22;
    bit<32> feature23;
    bit<32> feature24;
    bit<32> feature25; 
    bit<32> feature26;
    bit<32> feature27;
    bit<32> feature28;
    bit<32> feature29; 
    bit<32> feature30;
    bit<32> feature31; 
    bit<32> feature32; 
    bit<32> feature33; 
    bit<32> feature34; 
    bit<16> feature35; 
    bit<16> feature36; 
    bit<32> feature37; 
    bit<32> feature38; 
    bit<32> feature39; 
    bit<32> feature40; 
    bit<32> feature41; 
    bit<32> feature42; 


    bit<32> flow;

    bit<32> register_index;
    bit<32> register_index_inverse;

    bit<1> direction;
    bit<1> is_first;

    bit<32> src_ip;
    bit<32> dst_ip;
    bit<16> src_port;
    bit<16> dst_port;
    bit<8>  proto;

    bit<32> time_first_pkt;
    bit<32> time_last_pkt;
    bit<32> flow_duration;
    bit<8> packets; //this is used track the total amount of the packets, in order to evaluate the packet rate at the end

    bit<8> tot_fwd_pkts;
    bit<8> tot_bwd_pkts;

    bit<1> fin_flag_cnt;
    bit<1> syn_flag_cnt;
    bit<1> rst_flag_cnt;
    bit<1> psh_flag_cnt;
    bit<1> ack_flag_cnt;
    bit<1> urg_flag_cnt;
    bit<1> ece_flag_cnt;

    bit<32> len_fwd_pkts;
    bit<32> totlen_fwd_pkts;

    bit<32> len_bwd_pkts;
    bit<32> totlen_bwd_pkts;

    bit<32> totLen_pkts;   //this meta value is used for evaluating the total length mean
    bit<32> fwd_pkt_len_max;
    bit<32> fwd_pkt_len_min;
    bit<32> fwd_pkt_len_mean;
    bit<32> bwd_pkt_len_max;
    bit<32> bwd_pkt_len_min;
    bit<32> bwd_pkt_len_mean;
    bit<32> pkt_len_max;
    bit<32> pkt_len_min;
    bit<32> pkt_len_mean;
    bit<16> fwd_header_len;
    bit<16> bwd_header_len;
    bit<16> fwd_seg_size_min;
    bit<32> fwd_act_data_pkts;

    bit<32> iat;   // this is used to store the iat, so the mean can be evaluated
    bit<32> iat_tot;
    bit<32> flow_iat_mean;
    bit<32> flow_iat_max;
    bit<32> flow_iat_min;

    bit<32> fwd_iat;
    bit<32> fwd_iat_tot;
    bit<32> fwd_iat_mean;
    bit<32> fwd_iat_max;
    bit<32> fwd_iat_min;

    bit<32> bwd_iat;
    bit<32> bwd_iat_tot;
    bit<32> bwd_iat_mean;
    bit<32> bwd_iat_max;
    bit<32> bwd_iat_min;



    bit<16> init_fwd_win_byts;
    bit<16> init_bwd_win_byts;

    bit<32> active_vals;
    bit<32> active_tot;
    bit<32> active_mean;
    bit<32> active_max;
    bit<32> active_min;

    bit<32> idle_vals;
    bit<32> idle_tot;
    bit<32> idle_mean;
    bit<32> idle_max;
    bit<32> idle_min;

    bit<16> feature_id;
    bit<16> prevFeature;
    bit<16> isTrue;

    bit<3> class;
    //bit<3> class2;
    //bit<3> class3;

    bit<16> node_id;

}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
    udp_t	udp;
}

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
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

   // parse different types of packets ARP, ICMP etc.
   state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
	    17: parse_udp;
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //the following are the registers used to read and write the data written inside, in order to better manage the features
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_src_ip;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dst_ip;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_src_port;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_dst_port;
    register<bit<8>>(MAX_REGISTER_ENTRIES)  reg_protocol;

    //registers for the lifetime of the flow
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_time_first_pkt;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_time_last_pkt;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_duration;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_packets;

    //registers to count the total amount of packets in forwarding and backwarding directions
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_tot_fwd_pkts;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_tot_bwd_pkts;

    //the following registers allow to store the packets whose content inglobes the activation of the flags
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_fin_flag_cnt;
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_syn_flag_cnt;
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_rst_flag_cnt;
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_psh_flag_cnt;
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_ack_flag_cnt;
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_urg_flag_cnt;
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_ece_flag_cnt;

    // the following registers are for the length, its max and minimum values, the mean
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_len_fwd_pkts;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_totlen_fwd_pkts;

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_len_bwd_pkts;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_totlen_bwd_pkts;

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_totLen_pkts;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_pkt_len_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_pkt_len_min;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_pkt_len_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_pkt_len_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_pkt_len_min;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_pkt_len_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_pkt_len_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_pkt_len_min;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_pkt_len_mean;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_header_len;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_bwd_header_len;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_fwd_seg_size_min;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_act_data_pkts;

    //the following store features which concern the inter-arrival time (interval time between two packets in a flow)
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_iat;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_iat_tot;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_iat_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_iat_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_flow_iat_min;

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat_tot;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_fwd_iat_min;

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat_tot;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_bwd_iat_min;


    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_init_fwd_win_byts;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_init_bwd_win_byts;

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_vals;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_tot;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_active_min;

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_vals;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_tot;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_mean;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_max;
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_idle_min;




    action init_register() {
	//this action is in charge of intialising the registers to 0
	reg_src_ip.write(meta.register_index, 0);
	reg_dst_ip.write(meta.register_index, 0);
	reg_src_port.write(meta.register_index, 0);
	reg_dst_port.write(meta.register_index, 0);
	reg_protocol.write(meta.register_index, 0);

        reg_time_first_pkt.write(meta.register_index, 0);

        reg_time_last_pkt.write(meta.register_index, 0);

        reg_flow_duration.write(meta.register_index, 0);

        reg_packets.write(meta.register_index, 0);

        reg_tot_fwd_pkts.write(meta.register_index, 0);
        reg_tot_bwd_pkts.write(meta.register_index, 0);

        reg_fin_flag_cnt.write(meta.register_index, 0);
        reg_syn_flag_cnt.write(meta.register_index, 0);
        reg_rst_flag_cnt.write(meta.register_index, 0);
        reg_psh_flag_cnt.write(meta.register_index, 0);
        reg_ack_flag_cnt.write(meta.register_index, 0);
        reg_urg_flag_cnt.write(meta.register_index, 0);
        reg_ece_flag_cnt.write(meta.register_index, 0);

        reg_len_fwd_pkts.write(meta.register_index, 0);
        reg_totlen_fwd_pkts.write(meta.register_index, 0);

        reg_len_bwd_pkts.write(meta.register_index, 0);
        reg_totlen_bwd_pkts.write(meta.register_index, 0);

        reg_totLen_pkts.write(meta.register_index, 0);

        reg_fwd_pkt_len_max.write(meta.register_index, 0);
        reg_fwd_pkt_len_min.write(meta.register_index, 0);
        reg_fwd_pkt_len_mean.write(meta.register_index, 0);

        reg_bwd_pkt_len_max.write(meta.register_index, 0);
        reg_bwd_pkt_len_min.write(meta.register_index, 0);
        reg_bwd_pkt_len_mean.write(meta.register_index, 0);

        reg_pkt_len_max.write(meta.register_index, 0);
        reg_pkt_len_min.write(meta.register_index, 0);
        reg_pkt_len_mean.write(meta.register_index, 0);

        reg_fwd_header_len.write(meta.register_index, 0);

        reg_bwd_header_len.write(meta.register_index, 0);

        reg_fwd_seg_size_min.write(meta.register_index, 0);

        reg_fwd_act_data_pkts.write(meta.register_index, 0);

        reg_iat.write(meta.register_index, 0);
        reg_iat_tot.write(meta.register_index, 0);
        reg_flow_iat_mean.write(meta.register_index, 0);
        reg_flow_iat_max.write(meta.register_index, 0);
        reg_flow_iat_min.write(meta.register_index, 0);

        reg_fwd_iat.write(meta.register_index, 0);
        reg_fwd_iat_tot.write(meta.register_index, 0);
        reg_fwd_iat_mean.write(meta.register_index, 0);
        reg_fwd_iat_max.write(meta.register_index, 0);
        reg_fwd_iat_min.write(meta.register_index, 0);

        reg_bwd_iat.write(meta.register_index, 0);
        reg_bwd_iat_tot.write(meta.register_index, 0);
        reg_bwd_iat_mean.write(meta.register_index, 0);
        reg_bwd_iat_max.write(meta.register_index, 0);
        reg_bwd_iat_min.write(meta.register_index, 0);


        reg_init_fwd_win_byts.write(meta.register_index, 0);
        reg_init_bwd_win_byts.write(meta.register_index, 0);

        reg_active_vals.write(meta.register_index, 0);
        reg_active_tot.write(meta.register_index, 0);
        reg_active_mean.write(meta.register_index, 0);
        reg_active_max.write(meta.register_index, 0);
        reg_active_min.write(meta.register_index, 0);

        reg_idle_vals.write(meta.register_index, 0);
        reg_idle_tot.write(meta.register_index, 0);
        reg_idle_mean.write(meta.register_index, 0);
        reg_idle_max.write(meta.register_index, 0);
        reg_idle_min.write(meta.register_index, 0);

    }


    action init_features() {
	//they will be updated when needed
    	meta.feature0 = meta.tot_fwd_pkts;
    	meta.feature1 = meta.tot_bwd_pkts;
    	meta.feature2 = meta.totlen_fwd_pkts;
    	meta.feature3 = meta.totlen_bwd_pkts;
    	meta.feature4 = meta.fwd_pkt_len_max;
    	meta.feature5 = meta.fwd_pkt_len_min;
    	meta.feature6 = meta.fwd_pkt_len_mean;
    	meta.feature7 = meta.bwd_pkt_len_max;
    	meta.feature8 = meta.bwd_pkt_len_min;
    	meta.feature9 = meta.bwd_pkt_len_mean;
    	meta.feature10 = meta.fin_flag_cnt;
    	meta.feature11 = meta.syn_flag_cnt;
      meta.feature12 = meta.rst_flag_cnt;
    	meta.feature13 = meta.psh_flag_cnt;
    	meta.feature14 = meta.ack_flag_cnt;
    	meta.feature15 = meta.urg_flag_cnt;
    	meta.feature16 = meta.ece_flag_cnt;
    	meta.feature17 = meta.pkt_len_max;
    	meta.feature18 = meta.pkt_len_min;
    	meta.feature19 = meta.pkt_len_mean;
    	meta.feature20 = meta.fwd_header_len;
    	meta.feature21 = meta.bwd_header_len;
    	meta.feature22 = meta.fwd_seg_size_min;
    	meta.feature23 = meta.fwd_act_data_pkts;
    	meta.feature24 = meta.flow_iat_mean;
    	meta.feature25 = meta.flow_iat_max;
    	meta.feature26 = meta.flow_iat_min;
    	meta.feature27 = meta.fwd_iat_tot;
    	meta.feature28 = meta.fwd_iat_mean;
    	meta.feature29 = meta.fwd_iat_max;
    	meta.feature30 = meta.fwd_iat_min;
    	meta.feature31 = meta.bwd_iat_tot;
      meta.feature32 = meta.bwd_iat_mean;
    	meta.feature33 = meta.bwd_iat_max;
    	meta.feature34 = meta.bwd_iat_min;
    	meta.feature35 = meta.init_fwd_win_byts;
      meta.feature36 = meta.init_bwd_win_byts;
    	meta.feature37 = meta.active_mean;
     	meta.feature38 = meta.active_max;
    	meta.feature39 = meta.active_min;
    	meta.feature40 = meta.idle_mean;
      meta.feature41 = meta.idle_max;
      meta.feature42 = meta.idle_min;


			meta.class = CLASS_NOT_SET;
			//meta.class2 = CLASS_NOT_SET;
			//meta.class3 = CLASS_NOT_SET;
    }




    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
				hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }




     action get_register_index_tcp() {
    //Get register position through the 5-tuple
		hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
	                        hdr.ipv4.dstAddr,
				 hdr.tcp.srcPort,
	                        hdr.tcp.dstPort,
				 hdr.ipv4.protocol},
				 (bit<32>)MAX_REGISTER_ENTRIES);
    }

    action get_register_index_udp() {
 	        hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                hdr.ipv4.dstAddr,
                                hdr.udp.srcPort,
                                hdr.udp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
	}

    action get_register_index_inverse_tcp() {
    //Get register position for the same flow in another directon
    // just inverse the src and dst
                hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr,
                                hdr.tcp.dstPort,
                                hdr.tcp.srcPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
    }


    action get_register_index_inverse_udp() {
                hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr,
                                hdr.udp.dstPort,
                                hdr.udp.srcPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);

    }


    action drop() {
        mark_to_drop(standard_metadata);
    }


    action compute_shift(in bit<8> packets, out bit<8> bit_shifting) {
        if (packets == 0) {
            bit_shifting = 0;
        } else if (packets <= 2) {
            bit_shifting = 1;
        } else if (packets <= 4) {
            bit_shifting = 2;
        } else if (packets <= 8) {
            bit_shifting = 3;
        } else if (packets <= 16) {
            bit_shifting = 4;
        } else if (packets <= 32) {
            bit_shifting = 5;
        } else if (packets <= 64) {
            bit_shifting = 6;
        } else {
            bit_shifting = 7;
        }
    }



    action calculate_mean(in bit<32> value, in bit<8> packets, out bit<32> mean) {
        bit<8> bit_shifting;
        if (packets == 1) {
            mean = value;
        } else {
            // Calculate bit length of packets
            compute_shift(packets, bit_shifting);
            // Subtract 1 from bit length for correct shift amount
            mean = value >> bit_shifting;
        }
    }





    action initial_features() {
    /*this action reads and write in the relative registers, the source and destination IP addresses, as well as the ports and the protocol
    and it will be the first one to be triggered in the apply section*/

    	reg_src_ip.read(meta.src_ip, meta.register_index);
    	meta.src_ip = hdr.ipv4.srcAddr;
    	reg_src_ip.write(meta.register_index, meta.src_ip);

    	reg_dst_ip.read(meta.dst_ip, meta.register_index);
    	meta.dst_ip = hdr.ipv4.dstAddr;
    	reg_dst_ip.write(meta.register_index, meta.dst_ip);

    	reg_protocol.read(meta.proto, (bit<32>)meta.register_index);
    	meta.proto = hdr.ipv4.protocol;
    	reg_protocol.write((bit<32>)meta.register_index, meta.proto);

    }


    action calc_dur() {
    /*this action evaluates the lifetime of the flow*/

		reg_flow_duration.read(meta.flow_duration, meta.register_index);
		meta.flow_duration = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_first_pkt;
		reg_flow_duration.write(meta.register_index, meta.flow_duration);
    }




//forwarding actions

    action count_pkts_fwd() {
    //here it happens the same pattern of before, but this time, it is about the packets in forwarding direction
    	reg_tot_fwd_pkts.read(meta.tot_fwd_pkts, meta.register_index);
    	meta.tot_fwd_pkts = meta.tot_fwd_pkts + 1;
			reg_tot_fwd_pkts.write(meta.register_index, meta.tot_fwd_pkts);

    }



   action fwd_iat_tot() {
      reg_time_last_pkt.write(meta.register_index, (bit<32>)standard_metadata.ingress_global_timestamp);
   		reg_fwd_iat.read(meta.fwd_iat, meta.register_index);
   		reg_fwd_iat_tot.read(meta.fwd_iat_tot, meta.register_index);

   		//meta.fwd_iat_tot = (bit<32>) 0;
   		meta.fwd_iat = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt;
   		meta.fwd_iat_tot = meta.fwd_iat_tot + meta.fwd_iat;

   		reg_fwd_iat.write(meta.register_index, meta.fwd_iat);
   		reg_fwd_iat_tot.write(meta.register_index, meta.fwd_iat_tot);

   }

   action fwd_iat_mean() { // modificato 1 

   	 //evaluation of the inter-arrival time mean
   	reg_fwd_iat_mean.read(meta.fwd_iat_mean, meta.register_index);
   	reg_tot_fwd_pkts.read(meta.tot_fwd_pkts, meta.register_index);
   	
   	bit<8> total_fwd_pkts = meta.tot_fwd_pkts; 
   	bit<32> fwd_iat_total = meta.fwd_iat_tot;
   	
   	calculate_mean(fwd_iat_total, total_fwd_pkts, meta.fwd_iat_mean);
   	reg_fwd_iat_mean.write(meta.register_index, meta.fwd_iat_mean);

   }




   action fwd_iat_max() {
   	//finding the inter-arrival time max value
   	reg_fwd_iat_max.read(meta.fwd_iat_max, meta.register_index);
   	//reg_fwd_iat.read(meta.fwd_iat, meta.register_index);
   	//meta.fwd_iat_max = (bit<32>) 0;
   	if(meta.fwd_iat > meta.fwd_iat_max) {
   		meta.fwd_iat_max = meta.fwd_iat;

   	}
   	reg_fwd_iat_max.write(meta.register_index, meta.fwd_iat_max);
   }



   action fwd_iat_min() {
   	//finding the inter-arrival time max value
   	reg_fwd_iat_min.read(meta.fwd_iat_min, meta.register_index);
   	//reg_fwd_iat.read(meta.fwd_iat, meta.register_index);
   	meta.fwd_iat_min = meta.fwd_iat;
   	if(meta.fwd_iat < meta.fwd_iat_min) {
   		meta.fwd_iat_min = meta.fwd_iat;

   	}
   	reg_fwd_iat_min.write(meta.register_index, meta.fwd_iat_min);
   }



    /*for evaluating the length mean, the register of the forwarding packets are firstly red to be accessed, then through bit-shifting the value
    meta.totLen_bwd_pkts is bit-shifted to the right against meta.tot_fwd_pkts; at the end, the value is re-written
    in the relative register*/

    action calc_Length_fwd_tot() {
        reg_len_fwd_pkts.read(meta.len_fwd_pkts, meta.register_index);
        meta.len_fwd_pkts = standard_metadata.packet_length;

        reg_totlen_fwd_pkts.read(meta.totlen_fwd_pkts, (bit<32>)meta.register_index);

        //meta.totlen_fwd_pkts = (bit<16>) 0;
    	meta.totlen_fwd_pkts = meta.totlen_fwd_pkts + meta.len_fwd_pkts;//meta.tolLen_fwd_pkts + (bit<16>)standard_metadata.packet_length;

    	reg_len_fwd_pkts.write(meta.register_index, meta.len_fwd_pkts);
    	reg_totlen_fwd_pkts.write((bit<32>)meta.register_index, meta.totlen_fwd_pkts);

    }

    action calc_Length_fwd_mean() { //modificato 2

    	//reg_fwd_pkt_len_mean.read(meta.fwd_pkt_len_mean, (bit<32>)meta.register_index);
    	
    	reg_tot_fwd_pkts.read(meta.tot_fwd_pkts, meta.register_index); // io
    	reg_totlen_fwd_pkts.read(meta.totlen_fwd_pkts, (bit<32>)meta.register_index); //io
    	
    	bit<32> totlen_fwd_pkts_TMP = meta.totlen_fwd_pkts; // io 
    	bit<8> tot_fwd_pkts_TMP = meta.tot_fwd_pkts; //io
    	
    	
    	calculate_mean(totlen_fwd_pkts_TMP, tot_fwd_pkts_TMP, meta.fwd_pkt_len_mean);
    	reg_fwd_pkt_len_mean.write((bit<32>)meta.register_index, meta.fwd_pkt_len_mean);
    }


    /*the next two actions, when applied, marks the maximum and the minimum length value*/

    /*the approach adopted is quite simple, as always the register is red to access at the position of the feature in the flow and so to the 5-tuple,
    a metadata is initialised before to be put under condition:
    - for the max: if the value of the packet in the flow is higher than the previous one, then it will be the maximum one;
    - for the min: if the value of the packet in the flow is lower than the previous one, then it will be the minimum one;*/


    action calc_max_fwd() {
    	reg_fwd_pkt_len_max.read(meta.fwd_pkt_len_max, (bit<32>)meta.register_index);
    	//meta.bwd_pkt_len_max = hdr.ipv4.totalLen;

    	bit<32> max_f;
    	reg_len_fwd_pkts.read(max_f, meta.register_index);

    	if (max_f > meta.fwd_pkt_len_max) {
    		meta.fwd_pkt_len_max = max_f;
    	}
    	reg_fwd_pkt_len_max.write((bit<32>)meta.register_index, meta.fwd_pkt_len_max);
    }




    action calc_min_fwd() {
    	reg_fwd_pkt_len_min.read(meta.fwd_pkt_len_min, (bit<32>)meta.register_index);

    	bit<32> min_f;
    	reg_len_fwd_pkts.read(min_f, meta.register_index);

    	meta.fwd_pkt_len_min = meta.len_fwd_pkts;

    	if (min_f <= meta.fwd_pkt_len_min) {
    		meta.fwd_pkt_len_min = min_f;
    	}
    	reg_fwd_pkt_len_min.write((bit<32>)meta.register_index, meta.fwd_pkt_len_min);
    }



    action fwd_header() { ///MOD MATTIA

		reg_fwd_header_len.read(meta.fwd_header_len, (bit<32>)meta.register_index);

    	if (hdr.ipv4.protocol == 6) {
    		//meta.fwd_header_len = (bit<16>)hdr.ipv4.ihl*4;
			bit<16> tcp_header_length = (bit<16>)hdr.ipv4.ihl*4;
			meta.fwd_header_len = meta.fwd_header_len + tcp_header_length;

    	}
    	else{
    		//meta.fwd_header_len = (bit<16>)8;
			bit<16> udp_header_len = (bit<16>)8; //header udp è 8 byte
			meta.fwd_header_len = meta.fwd_header_len + udp_header_len;

    	}
        //meta.fwd_header_len = (meta.fwd_header_len)*((bit<16>)meta.tot_fwd_pkts);

    	reg_fwd_header_len.write((bit<32>)meta.register_index, meta.fwd_header_len);

    }


    action fwd_min_size() { //DA TOGLIERE
    	reg_fwd_seg_size_min.read(meta.fwd_seg_size_min, (bit<32>)meta.register_index);

    	if (hdr.ipv4.protocol == 6) {
    		meta.fwd_seg_size_min = (bit<16>)hdr.ipv4.ihl*4;
    	}
    	else{
    		meta.fwd_seg_size_min = (bit<16>)8;
    	}

        reg_fwd_seg_size_min.write((bit<32>)meta.register_index, meta.fwd_seg_size_min);
    }




    action count_payload() {
    	reg_fwd_act_data_pkts.read(meta.fwd_act_data_pkts, meta.register_index);
    	if(hdr.ethernet.etherType == 0x800 && hdr.ipv4.protocol == 6) { /*this is the case of count payload TCP packets, where
    									  the control is done on the dataOffset field of the header
    									  because dataOffset stands for the offset of the payload and if this
    									  value is higher than 5 (which is the minimum allowed value and it
    									  corresponds to an offset of five 32 bits words, in other words 20 bytes.)
    									  If the condition is true, this means that there are more features respect
    									  to the basic TCP header, furthermore this means that the payload begins further on in the packet.*/
    		if(hdr.tcp.dataOffset > 5) {
    			meta.fwd_act_data_pkts = meta.fwd_act_data_pkts + 1;
    		}
    	}
    	else if(hdr.ethernet.etherType == 0x800 && hdr.ipv4.protocol == 17)  {/* in this case, the the count concerns the UDP packets
    										since the UDP is has a simpler structure than the TCP one
    										the control is on the length of the packet itself: the
    										standard length of the packet is 8 byte, so if the length
    										is higher, the packet contains payload */
        	if(hdr.udp.length > 8) {
        		meta.fwd_act_data_pkts = meta.fwd_act_data_pkts + 1;
        	}

    	}

    	reg_fwd_act_data_pkts.write(meta.register_index, meta.fwd_act_data_pkts);
    }



    action window_fwd() {
    	reg_init_fwd_win_byts.read(meta.init_fwd_win_byts, (bit<32>)meta.register_index);
    	meta.init_fwd_win_byts = hdr.tcp.window;
    	reg_init_fwd_win_byts.write((bit<32>)meta.register_index, meta.init_fwd_win_byts);
    }




//backwarding operations

    action count_pkts_bwd() {
    //here it happens the same pattern of before, but this time, it is about the packets in backwarding direction
    	reg_tot_bwd_pkts.read(meta.tot_bwd_pkts, (bit<32>)meta.register_index);
    	meta.tot_bwd_pkts = meta.tot_bwd_pkts + 1;
    	reg_tot_bwd_pkts.write((bit<32>)meta.register_index, meta.tot_bwd_pkts);
    }



   action bwd_iat_tot() {
	 	reg_time_last_pkt.write(meta.register_index, (bit<32>)standard_metadata.ingress_global_timestamp);
   	reg_bwd_iat.read(meta.bwd_iat, meta.register_index);
   	reg_bwd_iat_tot.read(meta.bwd_iat_tot, meta.register_index);

   	//meta.bwd_iat_tot = (bit<32>) 0;
   	meta.bwd_iat = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt;
   	meta.bwd_iat_tot = meta.bwd_iat_tot + meta.bwd_iat;

   	reg_bwd_iat.write(meta.register_index, meta.bwd_iat);
   	reg_bwd_iat_tot.write(meta.register_index, meta.bwd_iat_tot);

   }

   action bwd_iat_mean() { //modificato 3 

	 //evaluation of the inter-arrival time mean
	 
	reg_tot_bwd_pkts.read(meta.tot_bwd_pkts, (bit<32>)meta.register_index); //io
	reg_bwd_iat_tot.read(meta.bwd_iat_tot, (bit<32>)meta.register_index); //io
	
   	//reg_bwd_iat_mean.read(meta.bwd_iat_mean, meta.register_index);
   	
   	bit<8> tot_bwd_pkts_TMP = meta.tot_bwd_pkts; //io
   	bit<32> bwd_iat_tot_TMP = meta.bwd_iat_tot; //io
   	
   	
   	
   	calculate_mean(bwd_iat_tot_TMP, tot_bwd_pkts_TMP, meta.bwd_iat_mean);
   	reg_bwd_iat_mean.write(meta.register_index, meta.bwd_iat_mean);

   }




   action bwd_iat_max() {
   	//finding the inter-arrival time max value
   	reg_bwd_iat_max.read(meta.bwd_iat_max, meta.register_index);
   	if(meta.bwd_iat > meta.bwd_iat_max) {
   		meta.bwd_iat_max = meta.bwd_iat;

   	}
   	reg_bwd_iat_max.write(meta.register_index, meta.bwd_iat_max);
   }



   action bwd_iat_min() {
   	//finding the inter-arrival time max value
   	reg_bwd_iat_min.read(meta.bwd_iat_min, meta.register_index);
   	//reg_bwd_iat.read(meta.bwd_iat, meta.register_index);
   	meta.bwd_iat_min = meta.bwd_iat;
   	if(meta.bwd_iat_min < meta.bwd_iat) {
   		meta.bwd_iat_min = meta.bwd_iat;

   	}
   	reg_bwd_iat_min.write(meta.register_index, meta.bwd_iat_min);
   }



    action calc_Length_bwd_tot() {
        reg_len_bwd_pkts.read(meta.len_bwd_pkts, meta.register_index);
        meta.len_bwd_pkts = standard_metadata.packet_length;

    	reg_totlen_bwd_pkts.read(meta.totlen_bwd_pkts, (bit<32>)meta.register_index);

    	//meta.totlen_bwd_pkts = (bit<16>) 0;
    	meta.totlen_bwd_pkts = meta.totlen_bwd_pkts + meta.len_bwd_pkts;//meta.totLen_bwd_pkts + (bit<16>)standard_metadata.packet_length;

    	reg_len_bwd_pkts.write(meta.register_index, meta.len_bwd_pkts);
    	reg_totlen_bwd_pkts.write((bit<32>)meta.register_index, meta.totlen_bwd_pkts);
    }

    action calc_Length_bwd_mean() { //modificato 4
	
    	//reg_bwd_pkt_len_mean.read(meta.bwd_pkt_len_mean, (bit<32>)meta.register_index);
    	
    	reg_totlen_bwd_pkts.read(meta.totlen_bwd_pkts, (bit<32>)meta.register_index); //io 
    	reg_tot_bwd_pkts.read(meta.tot_bwd_pkts, (bit<32>)meta.register_index); //io
    	
    	bit<32> totlen_bwd_pkts_TMP = meta.totlen_bwd_pkts;
    	bit<8> tot_bwd_pkts_TMP = meta.tot_bwd_pkts;
    	
    	calculate_mean(meta.totlen_bwd_pkts, tot_bwd_pkts_TMP, meta.bwd_pkt_len_mean);
    	
    	
    	reg_bwd_pkt_len_mean.write((bit<32>)meta.register_index, meta.bwd_pkt_len_mean);
    }


    /*the next two actions, when applied, marks the maximum and the minimum length value for backwarding operations as in the seen in the forwarding case*/

    action calc_max_bwd() {
    	reg_bwd_pkt_len_max.read(meta.bwd_pkt_len_max, (bit<32>)meta.register_index);
    	//meta.bwd_pkt_len_max = hdr.ipv4.totalLen;

    	bit<32> max_b;
    	reg_len_bwd_pkts.read(max_b, meta.register_index);

    	if (max_b > meta.bwd_pkt_len_max) {
    		meta.bwd_pkt_len_max = max_b;
    	}
    	reg_bwd_pkt_len_max.write((bit<32>)meta.register_index, meta.bwd_pkt_len_max);
    }



    action calc_min_bwd() {
    	reg_bwd_pkt_len_min.read(meta.bwd_pkt_len_min, (bit<32>)meta.register_index);

    	bit<32> min_b;
    	reg_len_bwd_pkts.read(min_b, meta.register_index);

    	meta.bwd_pkt_len_min = meta.len_bwd_pkts;

    	if (min_b <= meta.bwd_pkt_len_min) {
    		meta.bwd_pkt_len_min = min_b;
    	}
    	reg_bwd_pkt_len_min.write((bit<32>)meta.register_index, meta.bwd_pkt_len_min);
    }



    action bwd_header() {
    	reg_bwd_header_len.read(meta.bwd_header_len, (bit<32>)meta.register_index);

    	if (hdr.ipv4.protocol == 6){
		meta.bwd_header_len = (bit<16>)hdr.ipv4.ihl*4;
	}
	else{
    		meta.bwd_header_len = (bit<16>)8;
    	}
        meta.bwd_header_len = (meta.bwd_header_len)*((bit<16>)meta.tot_bwd_pkts);

    	reg_bwd_header_len.write((bit<32>)meta.register_index, meta.bwd_header_len);
    }



    action window_bwd() {
    	reg_init_bwd_win_byts.read(meta.init_bwd_win_byts, (bit<32>)meta.register_index);
    	meta.init_bwd_win_byts = hdr.tcp.window;
    	reg_init_bwd_win_byts.write((bit<32>)meta.register_index, meta.init_bwd_win_byts);
    }




//ending up with the evaluation of the standard traffic features
     action packet_len_tot() {
    	reg_totLen_pkts.read(meta.totLen_pkts, (bit<32>)meta.register_index);
    	//meta.totLen_pkts = (bit<16>) 0;
    	/*reg_totlen_fwd_pkts.read(meta.totlen_fwd_pkts, meta.register_index);
    	reg_totlen_bwd_pkts.read(meta.totlen_bwd_pkts, meta.register_index);*/

    	bit<32> len_f;
    	reg_totlen_fwd_pkts.read(len_f, meta.register_index);

    	bit<32> len_b;
    	reg_totlen_bwd_pkts.read(len_b, meta.register_index);

    	meta.totLen_pkts =  len_f + len_b;
    	reg_totLen_pkts.write((bit<32>)meta.register_index, meta.totLen_pkts);
    }


    action flow_pkts_tot () {
    /*this register saves the total amount of packets in the flow, it is a sum of both forwarding and backwarding case*/
    	reg_packets.read(meta.packets, (bit<32>)meta.register_index);

    	/*reg_tot_fwd_pkts.read(meta.tot_fwd_pkts, (bit<32>)meta.register_index);
    	reg_tot_bwd_pkts.read(meta.tot_bwd_pkts, (bit<32>)meta.register_index);*/

    	bit<8> pkt_f;
    	reg_tot_fwd_pkts.read(pkt_f, meta.register_index);

    	bit<8> pkt_b;
    	reg_tot_bwd_pkts.read(pkt_b, meta.register_index);

    	meta.packets = pkt_f + pkt_b;
    	reg_packets.write((bit<32>)meta.register_index, meta.packets);
    }


    //the following action evaluate the mean of the packet length, taking into account the total amount of packets for the average.
    action packet_len_mean() {

    	//reg_pkt_len_mean.read(meta.pkt_len_mean, (bit<32>)meta.register_index);
    	reg_totLen_pkts.read(meta.totLen_pkts, (bit<32>)meta.register_index);
    	bit<32> totLen_pkts_TMP = meta.totLen_pkts;
    	bit<8> packets_TMP = meta.packets;
    	
    	
    	calculate_mean(totLen_pkts_TMP, packets_TMP, meta.pkt_len_mean);
    	reg_pkt_len_mean.write((bit<32>)meta.register_index, meta.pkt_len_mean);
    }


    //the next two actions represent the maximum and the minimum value of the packet length
    action packet_len_max() {
    	reg_pkt_len_max.read(meta.pkt_len_max, (bit<32>)meta.register_index);

    	bit<32> len_f;
    	bit<32> len_b;

    	reg_fwd_pkt_len_min.read(len_f, meta.register_index);
    	reg_bwd_pkt_len_min.read(len_b, meta.register_index);

    	meta.pkt_len_max = 0;

    	if (len_f > meta.pkt_len_max) {
    		meta.pkt_len_max = len_f;
    	}
    	else if (len_b > meta.pkt_len_max) {
    		meta.pkt_len_max = len_b;
    	}
    	reg_pkt_len_max.write((bit<32>)meta.register_index, meta.pkt_len_max);
    }


    action packet_len_min() {
    	reg_pkt_len_min.read(meta.pkt_len_min, (bit<32>)meta.register_index);
    	/* here the registers are not red once again because the access has alreday happened in
    	the max length control (previous action)*/

    	bit<32> len_fwd;
    	bit<32> len_bwd;

    	reg_fwd_pkt_len_min.read(len_fwd, meta.register_index);
    	reg_bwd_pkt_len_min.read(len_bwd, meta.register_index);

    	meta.pkt_len_min = standard_metadata.packet_length;

    	if (len_fwd <= meta.pkt_len_min) {
    		meta.pkt_len_min = len_fwd;
    	}
    	else if (len_bwd <= meta.pkt_len_min) {
    		meta.pkt_len_min = len_bwd;
    	}
    	reg_pkt_len_min.write((bit<32>)meta.register_index, meta.pkt_len_min);
    }



   //the next actions concern the operations about the inter-arrival time (time between two consecutive packets)
   action iat_mean() { //modificato 5
   
        //reg_time_last_pkt.write(meta.register_index, (bit<32>)standard_metadata.ingress_global_timestamp);
   	reg_iat.read(meta.iat, meta.register_index);
   	reg_iat_tot.read(meta.iat_tot, meta.register_index);
	reg_time_last_pkt.read(meta.time_last_pkt, meta.register_index);
	
   	//after the iat register is red, register which stores the values
   	meta.iat = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt;

   	//meta.iat_tot = (bit<32>) 0;
   	meta.iat_tot = meta.iat_tot + meta.iat;

   	reg_iat.write(meta.register_index, meta.iat);
   	reg_iat_tot.write(meta.register_index, meta.iat_tot);

   	//reg_packets.read(meta.packets, (bit<32>)meta.register_index);
   	//reg_iat.read(meta.iat, meta.register_index);

   	 //evaluation of the inter-arrival time mean
   	bit<8> packets_TMP = meta.packets;
   	bit<32> iat_tot_TMP = meta.iat_tot;
   	
   	//reg_flow_iat_mean.read(meta.flow_iat_mean, meta.register_index);
   	
   	calculate_mean(iat_tot_TMP, packets_TMP, meta.flow_iat_mean);
   	
   	reg_flow_iat_mean.write(meta.register_index, meta.flow_iat_mean);

   }

   action iat_max() {
   	//finding the inter-arrival time max value
   	reg_flow_iat_max.read(meta.flow_iat_max, meta.register_index);
   	reg_iat.read(meta.iat, meta.register_index);
   	//meta.flow_iat_max = (bit<32>) 0;
   	if(meta.iat > meta.flow_iat_max) {
   		meta.flow_iat_max = meta.iat;
   	}
   	reg_flow_iat_max.write(meta.register_index, meta.flow_iat_max);
   }



   action iat_min() {
   	//finding the inter-arrival time max value
   	reg_flow_iat_min.read(meta.flow_iat_min, meta.register_index);
   	reg_iat.read(meta.iat, meta.register_index);
   	meta.flow_iat_min = meta.iat;
   	if(meta.iat < meta.flow_iat_min) {
   		meta.flow_iat_min = meta.iat;

   	}
   	reg_flow_iat_min.write(meta.register_index, meta.flow_iat_min);
   }



     action active_mean() { //modificato 6

    	//reg_time_last_pkt.write(meta.register_index, (bit<32>)standard_metadata.ingress_global_timestamp);
    	//reg_time_first_pkt.read(meta.time_first_pkt, meta.register_index);
    	
 
    	
    	reg_active_vals.read(meta.active_vals, meta.register_index);
    	reg_active_tot.read(meta.active_tot, meta.register_index);

    	meta.active_vals = meta.time_last_pkt - meta.time_first_pkt;
    	reg_active_vals.write(meta.register_index, meta.active_vals);

    	//meta.active_tot = (bit<32>) 0;
    	
    	meta.active_tot = meta.active_tot + meta.active_vals;
    	reg_active_tot.write(meta.register_index, meta.active_tot);
    	
    	
    	//reg_active_mean.read(meta.active_mean, meta.register_index);
    	
    	bit<8> packets_TMP = meta.packets;
    	bit<32> active_tot_TMP = meta.active_tot;
    	
    	calculate_mean(active_tot_TMP, packets_TMP, meta.active_mean);
    	reg_active_mean.write(meta.register_index, meta.active_mean);

    }



    action active_max() {

    	//reg_active_vals.read(meta.active_vals, meta.register_index);
	reg_active_max.read(meta.active_max, meta.register_index);

	if(meta.active_vals > meta.active_max) {
		meta.active_max = meta.active_vals;
	}
	reg_active_max.write(meta.register_index, meta.active_max);

    }



    action active_min() {


    	//reg_active_vals.read(meta.active_vals, meta.register_index);
			reg_active_min.read(meta.active_min, meta.register_index);

			meta.active_min = meta.active_vals;
			if(meta.active_vals < meta.active_min) {
				meta.active_min = meta.active_vals;
			}
			reg_active_min.write(meta.register_index, meta.active_min);

    }



    action idle_mean() { //modificato 7

    	//reg_time_last_pkt.write(meta.register_index, (bit<32>)standard_metadata.ingress_global_timestamp);
    	reg_idle_vals.read(meta.idle_vals, meta.register_index);
    	reg_idle_tot.read(meta.idle_tot, meta.register_index);

    	meta.idle_vals = (bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt;
    	reg_idle_vals.write(meta.register_index, meta.idle_vals);

    	//meta.idle_tot = (bit<32>) 0;
    	meta.idle_tot = meta.idle_tot + meta.idle_vals;
    	reg_idle_tot.write(meta.register_index, meta.idle_tot);

    	//reg_idle_mean.read(meta.idle_mean, meta.register_index);
    	
    	bit<8> packets_TMP = meta.packets;
    	bit<32> idle_tot_TMP = meta.idle_tot;
    	
    	calculate_mean(idle_tot_TMP, packets_TMP, meta.idle_mean);
    	reg_idle_mean.write(meta.register_index, meta.idle_mean);

    }



    action idle_max() {

    	//reg_idle_vals.read(meta.idle_vals, meta.register_index);
	reg_idle_max.read(meta.idle_max, meta.register_index);

	if(meta.idle_vals > meta.idle_max) {
		meta.idle_max = meta.idle_vals;
	}
	reg_idle_max.write(meta.register_index, meta.idle_max);

    }



    action idle_min() {

    	//reg_idle_vals.read(meta.idle_vals, meta.register_index);
	reg_idle_min.read(meta.idle_min, meta.register_index);

	meta.idle_min = meta.idle_vals;
	if(meta.idle_vals < meta.idle_min) {
		meta.idle_min = meta.idle_vals;
	}
	reg_idle_min.write(meta.register_index, meta.idle_min);

    }


    action f_fl() {
    
    
        reg_fin_flag_cnt.read(meta.fin_flag_cnt, (bit<32>)meta.register_index);
            
        //meta.fin_flag_cnt = (bit<1>) 0;
	if (hdr.tcp.fin == (bit<1>) 1) {
		meta.fin_flag_cnt = meta.fin_flag_cnt + (bit<1>) 1;
	}
	//else{
	//	meta.fin_flag_cnt = (bit<1>) 0;
	//}
	
	reg_fin_flag_cnt.write((bit<32>)meta.register_index, meta.fin_flag_cnt);
    }

    action s_fl() {
    
        reg_syn_flag_cnt.read(meta.syn_flag_cnt, (bit<32>)meta.register_index);
        
        //meta.syn_flag_cnt = (bit<1>) 0;
	if (hdr.tcp.syn == (bit<1>) 1) {
		meta.syn_flag_cnt = meta.syn_flag_cnt + (bit<1>) 1;
	}
	//else{
	//	meta.syn_flag_cnt = (bit<1>) 0;
	//}
	
	reg_syn_flag_cnt.write((bit<32>)meta.register_index, meta.syn_flag_cnt);
    }

    action e_fl() {
    
        reg_ece_flag_cnt.read(meta.ece_flag_cnt, (bit<32>)meta.register_index);
        
      
	if (hdr.tcp.ece == (bit<1>) 1) {
	    meta.ece_flag_cnt = meta.ece_flag_cnt+(bit<1>) 1;
	}
	//else{
	  //  meta.ece_flag_cnt = (bit<1>) 0;
	//}
	
	reg_ece_flag_cnt.write((bit<32>)meta.register_index, meta.ece_flag_cnt);
    }

    action ack_fl() {
    
        reg_ack_flag_cnt.read(meta.ack_flag_cnt, (bit<32>)meta.register_index);
        //meta.ack_flag_cnt = (bit<1>) 0;
        
        if (hdr.tcp.ack == (bit<1>) 1) {
        
	    meta.ack_flag_cnt = meta.ack_flag_cnt+(bit<1>) 1;
	}
	//else{
	  //  meta.ack_flag_cnt = (bit<1>) 0;
	//}
	
	reg_ack_flag_cnt.write((bit<32>)meta.register_index, meta.ack_flag_cnt);
    }

    action rst_fl() {
        reg_rst_flag_cnt.read(meta.rst_flag_cnt, (bit<32>)meta.register_index);
        
        //meta.rst_flag_cnt = (bit<1>) 0;
	if (hdr.tcp.rst == (bit<1>) 1) {
	    meta.rst_flag_cnt = meta.rst_flag_cnt + (bit<1>) 1;
	}
	//else{
	  //  meta.rst_flag_cnt = (bit<1>) 0;
	//}
	
        reg_rst_flag_cnt.write((bit<32>)meta.register_index, meta.rst_flag_cnt);
    }

    action psh_fl() {
        reg_psh_flag_cnt.read(meta.psh_flag_cnt, (bit<32>)meta.register_index);
        //meta.psh_flag_cnt = (bit<1>) 0;
	if (hdr.tcp.psh == (bit<1>) 1) {
	    meta.psh_flag_cnt = meta.psh_flag_cnt+(bit<1>) 1;
	}
	//else{
	  //  meta.psh_flag_cnt = (bit<1>) 0;
	//}
	
	reg_psh_flag_cnt.write((bit<32>)meta.register_index, meta.psh_flag_cnt);
    }

    action urg_fl() {
    
        reg_urg_flag_cnt.read(meta.urg_flag_cnt, (bit<32>)meta.register_index);
        //meta.urg_flag_cnt = (bit<1>) 0;
        
	if (hdr.tcp.urg == (bit<1>) 1) {
	    meta.urg_flag_cnt = meta.urg_flag_cnt+(bit<1>) 1;
	}
	//else{
	  //  meta.urg_flag_cnt = (bit<1>) 0;
	//}
	
	reg_urg_flag_cnt.write((bit<32>)meta.register_index, meta.urg_flag_cnt);
    }



    @suppress_warnings(unused)
    action CheckFeature(bit<16> node_id, bit<16> f_inout, bit<64> threshold) {

        bit<8> feature0 = 0; //tot_fwd_pkts
        bit<8> feature1 = 0; //tot_bwd_pkts
        bit<32> feature2 = 0; //totlen_fwd_pkts
        bit<32> feature3 = 0; //totlen_bwd_pkts
        bit<32> feature4 = 0; //fwd_pkt_len_max
        bit<32> feature5 = 0; //fwd_pkt_len_min
        bit<32> feature6 = 0; //fwd_pkt_len_mean
        bit<32> feature7 = 0; //bwd_pkt_len_max
        bit<32> feature8 = 0; //bwd_pkt_len_min
        bit<32> feature9 = 0; //bwd_pkt_len_mean
        bit<1> feature10 = 0; //fin_flag_count
        bit<1> feature11 = 0; //syn_flag_count
        bit<1> feature12 = 0; //rst_flag_count
        bit<1> feature13 = 0; //psh_flag_count
        bit<1> feature14 = 0; //ack_flag_count
        bit<1> feature15 = 0; //urg_flag_count
        bit<1> feature16 = 0; //ece_flag_count
        bit<32> feature17 = 0; //pkt_len_max
        bit<32> feature18 = 0; //pkt_len_min
        bit<32> feature19 = 0; //pkt_len_mean
        bit<16> feature20 = 0; //fwd_header_len
        bit<16> feature21 = 0; //bwd_header_len
        bit<16> feature22 = 0; //fwd_seg_size_min
        bit<32> feature23 = 0; //fwd_act_data_pkts
        bit<32> feature24 = 0; //flow_iat_mean
        bit<32> feature25 = 0; //flow_iat_max
        bit<32> feature26 = 0; //flow_iat_min
        bit<32> feature27 = 0; //fwd_iat_tot
        bit<32> feature28 = 0; //fwd_iat_mean
        bit<32> feature29 = 0; //fwd_iat_max
        bit<32> feature30 = 0; //fwd_iat_min
        bit<32> feature31 = 0; //bwd_iat_tot
        bit<32> feature32 = 0; //bwd_iat_mean
        bit<32> feature33 = 0; //bwd_iat_max
        bit<32> feature34 = 0; //bwd_iat_min
        bit<16> feature35 = 0; //init_fwd_win_byts
        bit<16> feature36 = 0; //init_bwd_win_byts
        bit<32> feature37 = 0; //active_mean
        bit<32> feature38 = 0; //active_max
        bit<32> feature39 = 0; //active_min
        bit<32> feature40 = 0; //idle_mean
        bit<32> feature41 = 0; //idle_max
        bit<32> feature42 = 0; //idle_min

        bit<64> th = threshold;
				bit<16> f = f_inout + 1;


        
	if (f == 0) {
	    feature0 = meta.feature0;
	}
	else if (f == 1) {
	    feature1 = meta.feature1;
	}
	else if (f == 2) {
	    feature2 = meta.feature2;
	}
	else if (f == 3) {
	    feature3 = meta.feature3;
	}
	else if (f == 4) {
	    feature4 = meta.feature4;
	}
	else if (f == 5) {
	    feature5 = meta.feature5;
	}
	else if (f == 6) {
	    feature6 = meta.feature6;
	}
	else if (f == 7) {
	    feature7 = meta.feature7;
	}
	else if (f == 8) {
	    feature8 = meta.feature9;
	}
	else if (f == 9) {
	    feature9 = meta.feature9;
	}
	else if (f == 10) {
	    feature10 = meta.feature10;
	}
	else if (f == 11) {
	    feature11 = meta.feature11;
	}
	else if (f == 12) {
	    feature12 = meta.feature12;
	}
	else if (f == 13) {
	    feature13 = meta.feature13;
	}
	else if (f == 14) {
	    feature14 = meta.feature14;
	}
	else if (f == 15) {
	    feature15 = meta.feature15;
	}
	else if (f == 16) {
	    feature16 = meta.feature16;
	}
	else if (f == 17) {
	    feature17 = meta.feature17;
	}
	else if (f == 18) {
	    feature18 = meta.feature18;
	}
	else if (f == 19) {
	    feature19 = meta.feature19;
	}
	else if (f == 20) {
	    feature20 = meta.feature20;
	}
	else if (f == 21) {
	    feature21 = meta.feature21;
	}
	else if (f == 22) {
	    feature22 = meta.feature22;
	}
	else if (f == 23) {
	    feature23 = meta.feature23;
	}
	else if (f == 24) {
	    feature24 = meta.feature24;
	}
	else if (f == 25) {
	    feature25 = meta.feature25;
	}
	else if (f == 26) {
	    feature26 = meta.feature26;
	}
	else if (f == 27) {
	    feature27 = meta.feature27;
	}
	else if (f == 28) {
	    feature28 = meta.feature28;
	}
	else if (f == 29) {
	    feature29 = meta.feature29;
	}
	else if (f == 30) {
	    feature30 = meta.feature30;
	}
	else if (f == 31) {
	    feature31 = meta.feature31;
	}
	else if (f == 32) {
	    feature32 = meta.feature32;
	}
	else if (f == 33) {
	    feature33 = meta.feature33;
	}
	else if (f == 34) {
	    feature34 = meta.feature34;
	}
	else if (f == 35) {
	    feature35 = meta.feature35;
	}
	else if (f == 36) {
	    feature36 = meta.feature36;
	}
	else if (f == 37) {
	    feature37 = meta.feature37;
	}
	else if (f == 38) {
	    feature38 = meta.feature38;
	}
	else if (f == 39) {
	    feature39 = meta.feature39;
	}
	else if (f == 40) {
	    feature40 = meta.feature40;
	}
	else if (f == 41) {
	    feature41 = meta.feature41;
	}
	else if (f == 42) {
	    feature42 = meta.feature42;
	}


	if (feature0 <= (bit<8>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature1 <= (bit<8>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature2 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature3 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature4 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature5 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature6 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature7 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature8 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature9 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature10 <= (bit<1>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature11 <= (bit<1>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature12 <= (bit<1>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature13 <= (bit<1>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature14 <= (bit<1>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature15 <= (bit<1>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature16 <= (bit<1>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature17 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature18 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature19 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature20 <= (bit<16>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature21 <= (bit<16>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature22 <= (bit<16>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature23 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature24 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature25 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature26 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature27 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature28 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature29 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature30 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature31 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature32 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature33 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature34 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature35 <= (bit<16>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature36 <= (bit<16>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature37 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature38 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature39 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature40 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature41 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	if (feature42 <= (bit<32>)th) meta.isTrue = 1;
	else meta.isTrue = 0;

	meta.prevFeature = f - 1;

	meta.node_id = node_id;
    }



    @suppress_warnings(unused)
    action SetClass(bit<16> node_id, bit<3> class) {
	meta.class = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }

    //@suppress_warnings(unused)
    //action SetClass2(bit<16> node_id, bit<3> class2) {
	//meta.class2 = class2;
	//meta.node_id = node_id; //just for debugging otherwise not needed
    //}

    //@suppress_warnings(unused)
    //action SetClass3(bit<16> node_id, bit<3> class3) {
	//meta.class3 = class3;
	//meta.node_id = node_id; //just for debugging otherwise not needed
    //}




    /* This will send the packet to a specifique port of the switch for output*/
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
	}
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    	table tot_f_pkts{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        count_pkts_fwd;
    	        drop;
    	    	NoAction;
    	    }
    	    size = 1024;
    	    default_action = NoAction;
    	}

    	table tot_b_pkts{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        count_pkts_bwd;
    	        drop;
    	    	NoAction;
    	    }
    	    size = 1024;
    	    default_action = NoAction;
    	}

    	table totlen_f_pkts{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        calc_Length_fwd_tot;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table totlen_b_pkts{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        calc_Length_bwd_tot;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_pkt_len_max{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        calc_max_fwd;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_pkt_len_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        calc_min_fwd;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_pkt_len_mean{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        calc_Length_fwd_mean;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table b_pkt_len_max{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        calc_max_bwd;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table b_pkt_len_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        calc_min_bwd;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table b_pkt_len_mean{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        calc_Length_bwd_mean;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table fin_flag{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        f_fl;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table syn_flag{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        s_fl;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table rst_flag{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        rst_fl;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table psh_flag{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        psh_fl;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table ack_flag{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        ack_fl;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table urg_flag{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        urg_fl;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table ece_flag{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        e_fl;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table packet_length_max{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        packet_len_max;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table packet_length_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        packet_len_min;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table packet_length_mean{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        packet_len_mean;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_header_len{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        fwd_header;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table b_header_len{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        bwd_header;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_seg_size_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        fwd_min_size;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_act_data_pkts{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        count_payload;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table fl_iat_mean{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        iat_mean;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table fl_iat_max{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        iat_max;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table fl_iat_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        iat_min;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_iat_tot{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	    	fwd_iat_tot;
    	    	drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_iat_mean{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        fwd_iat_mean;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_iat_max{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        fwd_iat_max;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table f_iat_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        fwd_iat_min;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table b_iat_tot{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	    	bwd_iat_tot;
    	    	drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table b_iat_mean{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        bwd_iat_mean;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table b_iat_max{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        bwd_iat_max;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table b_iat_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        bwd_iat_min;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table init_f_win_byts{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        window_fwd;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table init_b_win_byts{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        window_bwd;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table act_mean{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        active_mean;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table act_max{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        active_max;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table act_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        active_min;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table id_mean{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        idle_mean;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table id_max{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        idle_max;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

    	table id_min{
    	    key = {
    	    	meta.feature_id: exact;
    	    }
    	    actions = {
    	        idle_min;
    	        drop;
    	    	NoAction;
    	    }
    	    default_action = NoAction;
    	    size = 1024;
    	}

	//these ones are the tables used to upload the model on the switch
	//each tree will have 8 levels
	//the first tree is represented through level1, level2, etc..
	//from the second on, the representation will be level_2_1 or level_3_1, where the first number stands for the tree considered, meanwhile the second number is the level (depth).

	table level1{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}
	table level4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}


   apply {
	 	bit<32> tmp;
	 	bit<32> originale;
    if (hdr.ipv4.isValid()) {
		//Calculate all features

		if (hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17) {
    			if (hdr.ipv4.protocol == 6) {
    				get_register_index_tcp();
        			get_register_index_inverse_tcp();
    			}
    			else {
    				get_register_index_udp();
        			get_register_index_inverse_udp();
    			}

    			//reg_src_port.read(meta.src_port, (bit<32>)meta.register_index);
    			//reg_dst_port.read(meta.dst_port, (bit<32>)meta.register_index);



			//if (meta.proto == 6) {
			//	meta.src_port = hdr.tcp.srcPort;
			//	meta.dst_port = hdr.tcp.dstPort;
    			//}
    			//else{
        		//	meta.src_port = hdr.udp.srcPort;
			//	meta.dst_port = hdr.udp.dstPort;
    			//}
    			//reg_src_port.write(meta.register_index, meta.src_port);
    			//reg_dst_port.write(meta.register_index, meta.dst_port);

			//reg_time_first_pkt.read(meta.time_first_pkt, meta.register_index);

	                //this allows to check whether the packet is a forward or a backward one

	        	reg_flow.read(tmp, meta.register_index);
	        	//reg_flow.read(meta.flow, meta.register_index);
	        	//originale = tmp; 
	        	if(tmp == 0){

	        		// devo capire se il pacchetto fa parte di un flusso in backwarding --> hai register index_inverse
	        		reg_flow.read(tmp, meta.register_index_inverse);
	        		if(tmp != 0){

	        			meta.direction=1;
	        		        meta.register_index = meta.register_index_inverse; //in questo modo indicizzo sempre per register_index e accedo con un id univoco sui registri in back. 
	        		        //reg_flow.write(meta.register_index, meta.register_index_inverse);


	        		}
	        		else{
	        			// il pacchetto non l'ho mai visto in forwarding, non l'ho mai visto in backwarding allora è un pacchetto di un flusso nuovo --> decido che è in fwd
	        			meta.direction=0;
	        			meta.is_first = 1;
	        			initial_features();
	        			reg_flow.write(meta.register_index, meta.register_index);

	        		}
	        	}

			meta.time_last_pkt = (bit<32>)standard_metadata.ingress_global_timestamp;
			

			if(meta.is_first == 1) {
				reg_time_first_pkt.write(meta.register_index, meta.time_last_pkt );
			}
			
			
			
			reg_time_last_pkt.write(meta.register_index, meta.time_last_pkt);
			
			

	        	//reg_time_last_pkt.read(meta.time_last_pkt, meta.register_index);

			//if (meta.src_ip == 0) {//It was an empty register
				
			//}
			if (((bit<32>)standard_metadata.ingress_global_timestamp - meta.time_last_pkt) > FLOW_TIMEOUT) {
				/*We havent heard from this flow it has been FLOW_TIMEOUT
			        We will initialse the register space
			        */
				init_register(); //init_register inizializza anche i backward registers ... 
				meta.is_first = 1;
			}



	        	if (meta.direction == 0) {
				count_pkts_fwd(); //va eseguito sempre per primo
	        		//tot_f_pkts.apply();
				f_iat_tot.apply();
				f_iat_mean.apply();
				f_iat_max.apply();
				f_iat_min.apply();
				totlen_f_pkts.apply();
				f_pkt_len_mean.apply();
				f_pkt_len_max.apply();
				f_pkt_len_min.apply();
				f_header_len.apply();
				f_seg_size_min.apply();
				f_act_data_pkts.apply();
    				init_f_win_byts.apply();
    				log_msg("5 tupla ({}-{}-{}-{}-{}) hash {}", {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol, meta.register_index});
    				
   				

    			}

	        	//hai direction e register_index. Direction ti fa capire se il flusso è fwd - bwd mentre register index ha l'hash della 5-tupla del pacchetto appena entrato.
                        //else{ // flow in backward
                        else if (meta.direction == 1){

				count_pkts_bwd(); //va eseguito sempre per primo
			        //tot_b_pkts.apply();
			        b_iat_tot.apply();
    				b_iat_mean.apply();
    			        b_iat_max.apply();
    				b_iat_min.apply();
    				totlen_b_pkts.apply();
    			        b_pkt_len_mean.apply();
    				b_pkt_len_max.apply();
    				b_pkt_len_min.apply();
    				b_header_len.apply();
    			        init_b_win_byts.apply();
    			        log_msg("5 tupla ({}-{}-{}-{}-{}) hash {}", {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol, meta.register_index_inverse});
			 }

			reg_time_first_pkt.read(meta.time_first_pkt, meta.register_index);
			calc_dur();
			packet_len_tot();
		        flow_pkts_tot();
    			fl_iat_mean.apply();
    			fl_iat_max.apply();
    			fl_iat_min.apply();
    			act_mean.apply();
    			act_max.apply();
    			act_min.apply();
    			id_mean.apply();
    			id_max.apply();
    			id_min.apply();
    			packet_length_mean.apply(); //dopo packet_len_tot sempre che riempie meta.packet_lenTot
    			packet_length_max.apply();
    			packet_length_min.apply();

	                //the following conditions will check if the selected flag is 1 and so, the proper register will be updated
	                if (hdr.ipv4.protocol == 6) {
	                	fin_flag.apply();
	                	syn_flag.apply();
	                	rst_flag.apply();
	                	psh_flag.apply();
	                	ack_flag.apply();
	                	urg_flag.apply();
	                	ece_flag.apply();
	                }

			init_features();


			//start with parent node of decision tree
			//meta.direction = 0;
			meta.prevFeature = 0;
			meta.isTrue = 1;
			meta.node_id = 0;

			bit<8> pkt_fwd_cnt;
			bit<8> pkt_bwd_cnt;

			//if (meta.direction == 0){
			//	reg_tot_fwd_pkts.read(pkt_fwd_cnt, meta.register_index);
			//	reg_tot_bwd_pkts.read(pkt_bwd_cnt, meta.register_index_inverse);
			//}
			//else{
			//	reg_tot_bwd_pkts.read(pkt_bwd_cnt, meta.register_index);
			//	reg_tot_fwd_pkts.read(pkt_fwd_cnt, originale);
			//}
			
			
			reg_tot_bwd_pkts.read(pkt_bwd_cnt, meta.register_index);
			reg_tot_fwd_pkts.read(pkt_fwd_cnt, meta.register_index);
			bit<8> pkts;
			pkts = pkt_fwd_cnt + pkt_bwd_cnt;
			log_msg("prima {}", {meta.packets});
			
			if(pkts >= PACKET_THR) {
			log_msg("dopo {}", {pkts});
				//decision tree

				level1.apply();

				if (meta.class == CLASS_NOT_SET) {
		 		    level2.apply();
		  		    if (meta.class == CLASS_NOT_SET) {
		    		        level3.apply();
		    			if (meta.class == CLASS_NOT_SET) {
					     level4.apply();
				             if (meta.class == CLASS_NOT_SET) {
			  		         level5.apply();
			  			 if (meta.class == CLASS_NOT_SET) {
			   			      level6.apply();
			    			      if (meta.class == CLASS_NOT_SET) {
			      			          level7.apply();
			    			          if (meta.class == CLASS_NOT_SET)
			      			              level8.apply();
		        	}}}}}}


				log_msg("processed");
				if (meta.class <= 1) meta.class = 0;
				else meta.class = 1;

			}

			

            		           log_msg("Source_IP={}, Destination_IP={}, Source Port={}, Destination Port={}, Protocol={}, Dur={}, HAS_fin={}, HAS_syn={}, HAS_rst={}, HAS_psh={}, HAS_ack={}, HAS_urg={}, HAS_ece={}, Tot_Fwd_Packets={}, Tot_Bwd_Packets={}, Tot_Length_Fwd={}, Tot_Length_Bwd={}, Min_Fwd_Length={}, Max_Fwd_Length={}, Mean_Fwd_Length={}, Min_Bwd_Length={}, Max_Bwd_Length={}, Mean_Bwd_Length={}, Max_pkt_len={}, Min_pkt_len={}, Tot_pkt_len= {}, Mean_pkt_len={}, FWD_HEADER={}, FWD_SEG_SIZE_MIN={}, BWD_HEADER={}, FWD_Window={}, BWD_Window={}, FWD_PAY_Packets={}, FLOW_IAT_MIN={}, FLOW_IAT_MAX={}, FLOW_IAT_MEAN={}, FWD_IAT_MIN={}, FWD_IAT_MAX={}, FWD_IAT_TOT={}, FWD_IAT_MEAN={}, BWD_IAT_MIN={}, BWD_IAT_MAX={}, BWD_IAT_TOT={}, BWD_IAT_MEAN={}, Active_mean={}, Active_min={}, Active_max={}, Idle_mean={}, Idle_min={}, Idle_max={}, Packets={}, Class={}, Header= {}, TMP= {},FLOW= {}, INDEX= {}, INVERSE={}", {meta.src_ip, meta.dst_ip, meta.src_port, meta.dst_port, meta.proto, meta.flow_duration, meta.fin_flag_cnt, meta.syn_flag_cnt, meta.rst_flag_cnt, meta.psh_flag_cnt, meta.ack_flag_cnt, meta.urg_flag_cnt, meta.ece_flag_cnt, meta.tot_fwd_pkts, meta.tot_bwd_pkts, meta.totlen_fwd_pkts, meta.totlen_bwd_pkts, meta.fwd_pkt_len_min, meta.fwd_pkt_len_max, meta.fwd_pkt_len_mean, meta.bwd_pkt_len_min, meta.bwd_pkt_len_max, meta.bwd_pkt_len_mean, meta.pkt_len_max, meta.pkt_len_min, meta.totLen_pkts, meta.pkt_len_mean, meta.fwd_header_len, meta.fwd_seg_size_min, meta.bwd_header_len, meta.init_fwd_win_byts, meta.init_bwd_win_byts, meta.fwd_act_data_pkts, meta.flow_iat_min, meta.flow_iat_max, meta.flow_iat_mean, meta.fwd_iat_min, meta.fwd_iat_max, meta.fwd_iat_tot, meta.fwd_iat_mean, meta.bwd_iat_min, meta.bwd_iat_max, meta.bwd_iat_tot, meta.bwd_iat_mean, meta.active_mean, meta.active_min, meta.active_max, meta.idle_mean, meta.idle_min, meta.idle_max, meta.packets, meta.class, (bit<16>)hdr.ipv4.ihl*4, tmp, meta.flow, meta.register_index, meta.register_index_inverse});

                }//this is for closing the tcp and udp condition

               ipv4_lpm.apply();

            } //hdr.ipv4.isValid if

    } //apply if


} //ingress control if


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
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
