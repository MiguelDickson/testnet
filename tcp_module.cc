
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <iostream>
#include "Minet.h"
#include "sockint.h"
#include "tcpstate.h"
#include "constate.h"
#include "tcp.h"


using namespace std;


//This should be unnecessary: 
/*
struct TCPState {
   
    Buffer send_buf;
    
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};
*/


//Strictly a helper function: prints out the packet and a few minor analytics in easier-to-read-form (type, seqnum, acknum)
void analyze_packet (Packet p)
{
        unsigned char flags = 0;
        unsigned int seqnum =0;
        unsigned int acknum =0;
        unsigned short srcport =0;
        unsigned short destport =0;
        IPAddress source;
        IPAddress destination;
        TCPHeader tcp_head;
        IPHeader ip_head;    
        unsigned x = TCPHeader::EstimateTCPHeaderLength(p);
        p.ExtractHeaderFromPayload<TCPHeader>(x);
        tcp_head = p.FindHeader(Headers::TCPHeader);
        ip_head = p.FindHeader(Headers::IPHeader);
        tcp_head.GetFlags(flags);
        tcp_head.GetSeqNum(seqnum);
        tcp_head.GetAckNum(acknum);
        tcp_head.GetSourcePort(srcport);
        tcp_head.GetDestPort(destport);
        ip_head.GetSourceIP(source);
        ip_head.GetDestIP(destination);
        
        cerr << "\n The flags for the packet being analyzed" << flags << "\n";
        
        if (IS_SYN(flags))
        {
            if (IS_ACK(flags))
            {
            cerr << "\n SYN-ACK received!" << endl << "\nThe seqnum is:" << seqnum << "\nThe acknum is:" << acknum << endl;
            cerr << "\nThe source port is:\n" << srcport << endl << "\nThe dest prt is:\n" << destport << endl;
            cerr << "\nThe source IP is:\n" << source << endl << "\nThe dest IP is :\n" << destination << "\nThe rest of the packet is:" << p << endl;    
                    
            }
            else
            {
            cerr << "\n SYN received!" << endl << "\nThe seqnum is:" << seqnum << "\nThe acknum is:" << acknum << endl;
            cerr << "\nThe source port is:\n" << srcport << endl << "\nThe dest prt is:\n" << destport << endl;
            cerr << "\nThe source IP is:\n" << source << endl << "\nThe dest IP is :\n" << destination << "\nThe rest of the packet is:" << p << endl;       
            }        
        }
        else
        {
            if (IS_ACK(flags))
            {
            cerr << "\n ACK received! " << endl << "\nThe seqnum is:" << seqnum << "\nThe acknum is:" << acknum << endl;
            cerr << "\nThe source port is:\n" << srcport << endl << "\nThe dest prt is:\n" << destport << endl;
             cerr << "\nThe source IP is:\n" << source << endl << "\nThe dest IP is :\n" << destination << "\nThe rest of the packet is:" << p << endl;     
            }
            else
            {
            cerr << "\n Some other kind of packet!\n";
            }         
           
        }


}

//Respond_packet derives the correct action from the connection and whether or not there is data to be sent
void respond_packet (ConnectionToStateMapping<TCPState> &conn, bool get_data, char flags, const MinetHandle &mux, const MinetHandle &sock, unsigned int seq, unsigned int ack)
{
    //Check whether or not you're sending data. Slightly different loop if so.
    if (get_data == false)
    {
        cerr <<"\nHas no data to receive!\n";
        Packet p;
        int state;
        TCPHeader tcp_head;
        IPHeader ip_head;
        unsigned char response_flags;
        
        //Set the IP header
        ip_head.SetSourceIP(conn.connection.src);
        ip_head.SetDestIP(conn.connection.dest);
        ip_head.SetProtocol(IP_PROTO_TCP);  //Defined in tcp.h
        ip_head.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH); //Defined in tcp.h && ip.h
        //Push the IP header
        p.PushFrontHeader(ip_head);
        
        //Set parts of TCP header
        tcp_head.SetSourcePort(conn.connection.srcport, p);
        tcp_head.SetDestPort(conn.connection.destport, p);       
        // tcp_head.SetFlags(flags, p);
       
        state = conn.state.GetState();
        cerr << "\n The state: " << state;
        cerr << "\n Testline for states: " << LISTEN << " " << SYN_RCVD << " " << SYN_SENT << "\n";
       
        switch (state)
        { 
            case LISTEN:
            {
                cerr << "\n In LISTEN state!\n ";
                if (IS_SYN(flags))
                {
                cerr << "\n Received a syn! Sending syn-ack!\n";
                
                //Set last bits of TCP Header
                tcp_head.SetSeqNum(3333, p);
                tcp_head.SetAckNum(seq+1, p);
                tcp_head.SetWinSize((unsigned short)5840, p);
                tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
                SET_ACK(response_flags);
                SET_SYN(response_flags);
                tcp_head.SetFlags(response_flags,p);                
                conn.state.SetState(SYN_RCVD);
                conn.state.last_acked = conn.state.last_sent-1;
                conn.bTmrActive = true;
                conn.timeout=Time() + 60;
                conn.state.SetLastRecvd(seq+1);
                p.PushBackHeader(tcp_head);
                cerr << endl << endl << "\n Packet constructed! Looks like:" << endl << p << endl;
                MinetSend(mux, p);
                }
                break;
            }
            case SYN_RCVD:
            {
                cerr << "\n In SYN_RCVD state!\n ";
                if (IS_SYN(flags))
                {
                cerr << "\n Likely error, shouldn't be receiving syn still!\n";
                }
                               
                if (IS_ACK(flags) && (!(IS_SYN(flags))))
                {
                cerr << "\n Received ACK! PROPERLY ESTABLISHED. \n";
                tcp_head.SetSeqNum(seq, p);
                tcp_head.SetAckNum(ack, p);
                tcp_head.SetWinSize((unsigned short)5840, p);
                tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
                conn.state.SetState(ESTABLISHED);
                conn.state.last_acked = conn.state.last_sent-1;
                conn.bTmrActive = true;
                conn.timeout=Time() + 60;
                conn.state.SetLastRecvd(seq+1);                
                }
                 break;
            }    
            
            case ESTABLISHED:
            {
                cerr << "\n In ESTABLISHED state!\n";
                break;
            }
            
            default:
                cerr << "\n Dealing with something else!\n ";
                break;
        }
        
    }
    else
    {
    cerr <<"\nHas data to receive!\n";    
    }

} 



int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    ConnectionList<TCPState> clist;

    ///////////Pre-existing configuration code : DO NOT MODIFY
    MinetInit(MINET_TCP_MODULE);
    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;
    if ( (mux == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {
	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));
	return -1;
    }
    if ( (sock == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {
	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));
	return -1;
    }
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";
    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));
    MinetEvent event;
    double timeout = 600;
    /////////////////////BEGIN Hard-coded test listener////////////
    const char* addr = "192.168.114.1";
    const char* addr2 = "192.168.42.5";
    TCPState hardlistener(0, 1, 2);
    IPAddress testaddr(addr);
    IPAddress testaddr2(addr2);
    Connection testconn(testaddr, testaddr2, 13245, 12345, IP_PROTO_TCP);
    Time test_time(100000);
    ConnectionToStateMapping<TCPState> a(testconn, test_time, hardlistener, false);
    cerr << "\n\n\n Presenting the hard-coded connection:" << testconn << "\n";
    clist.push_back(a);
    cerr << "\n\n\n Presenting the connection list:" << clist << "\n";
    /////////////////////END Hard-coded test listener ////////////   
    
    ////////Main Loop//////////////
    while (MinetGetNextEvent(event, timeout) == 0) {    
    Connection find_conn;
    MinetSendToMonitor(MinetMonitoringEvent("GOT EVENT!"));

	if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	
	    if (event.handle == mux) {
		// ip packet has arrived!
        
        Packet p;
        unsigned char flags;
        unsigned char tcp_header_length, ip_header_length;
        unsigned int seq, ack;
        short unsigned int data_length;
        bool has_data;
        TCPHeader tcp_head;
        IPHeader ip_head;     
        flags = 0;
        MinetReceive(mux,p);
        
        //Diagnostic lines//
        MinetSendToMonitor(MinetMonitoringEvent("HANDLING PACKET!"));
        cerr << "PACKET BEING HANDLED" << endl << endl << p;        
        analyze_packet(p);
        
        //Extract the TCP header & IP header from packet        
        unsigned x = TCPHeader::EstimateTCPHeaderLength(p);
        p.ExtractHeaderFromPayload<TCPHeader>(x);
        tcp_head = p.FindHeader(Headers::TCPHeader);
        ip_head = p.FindHeader(Headers::IPHeader);
        
        //Analyze the incoming packet, and set find_conn appropriately (for searching through the connection list)
        //Note the flipped DEST/SRC (the destination from the incoming packet should be the source here and vice-versa)
        ip_head.GetDestIP(find_conn.src);
        ip_head.GetSourceIP(find_conn.dest);
        ip_head.GetProtocol(find_conn.protocol);
        tcp_head.GetSourcePort(find_conn.destport);        
        tcp_head.GetDestPort(find_conn.srcport);       

        
        //Get the sequence and acknowledgment numbers
        tcp_head.GetSeqNum(seq);
        tcp_head.GetAckNum(ack);
        
        //Get the flags, one of three things we need to know to send response packets
        tcp_head.GetFlags(flags);
        
        //Diagnostic lines 
        cerr << "\n\n\n Presenting the connection we're searching for!:" << find_conn << "\n";
     
        //Find the matching connection, if it exists
        ConnectionList<TCPState>::iterator conn_search = clist.FindMatching(find_conn);
        
        //Diagnostic lines
        ConnectionToStateMapping<TCPState> &current_conn2 = *conn_search;   
        cerr << "\n\n\n The connection or lackthereof we found:" << current_conn2.connection << "\n";
        
            //If the connection exists
            if (conn_search!= clist.end())
            {
            cerr << "\n The connection exists!\n" << endl;
            //Conn_search currently points to the ConnectionToStateMapping corresponding to the connection, so initialize a mapping to grab it 
            //Now have two of three necessary things to know to use send_packet
            ConnectionToStateMapping<TCPState> &current_conn = *conn_search;    
            
            //Find out if the packet has data.            
            //First set data length to the overall length of the packet
            /*
            ip_head.GetTotalLength(data_length);
            tcp_head.GetHeaderLen(tcp_header_length);            
            //With no options supported (per project specifications), IP header length is always 20.
            data_length = data_length - tcp_header_length - 20;
            cerr << "\n Calculated the data length to be: " << data_length << "\n";
            */
            
            Buffer buf;
            buf = p.GetPayload();
            data_length = buf.GetSize();
            
            cerr << "\n By payload calculated the data length to be: " << data_length << "\n";
            
            //Now we can continue
            if (data_length == 0)
                has_data = false;
            else
                {
                //Also add in here the buffering mechanisms into the connection's state
                has_data = true;
                }
                
            send_packet(current_conn, has_data, flags, mux, sock, seq, ack);    
            }
            
            
            //The connection does not exist
            else
            {
            cerr << "\n The connection does not exist!\n" << endl;
            
            }
            
       
        }

	    if (event.handle == sock) {
		// socket request or response has arrived
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	}

    }

    MinetDeinit();

    return 0;
}
