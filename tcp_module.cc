
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


//Strictly a helper function: prints out the packet 
void analyze_packet (Packet p)
{
        unsigned char flags = 0;
        unsigned int seqnum =0;
        unsigned int acknum =0;
        TCPHeader tcp_head;
        IPHeader ip_head;    
        unsigned x = TCPHeader::EstimateTCPHeaderLength(p);
        p.ExtractHeaderFromPayload<TCPHeader>(x);
        tcp_head = p.FindHeader(Headers::TCPHeader);
        ip_head = p.FindHeader(Headers::IPHeader);
        tcp_head.GetFlags(flags);
        tcp_head.GetSeqNum(seqnum);
        tcp_head.GetAckNum(acknum);
        
        
        if (IS_SYN(flags))
        {
            if (IS_ACK(flags))
            {
            cerr << "SYN-ACK received! The rest of the packet is:" << endl << p << endl;    
            cerr << "The seqnum is:" << seqnum << endl;
            cerr << "The acknum is:" << acknum << endl;
            
            }
            else
            {
            cerr << "SYN received! The rest of the packet is:" << endl << p << endl;
            cerr << "The seqnum is:" << seqnum << endl;
            cerr << "The acknum is:" << acknum << endl;
            
            }        
        }
        else
        {
            if (IS_ACK(flags))
            {
            cerr << "ACK received! The rest of the packet is:" << endl << p << endl;
            cerr << "The seqnum is:" << seqnum << endl;
            cerr << "The acknum is:" << acknum << endl;
            }
        }


}

//Send packet derives the correct action from the connection, whether or not there is data, and flags
void send_packet (ConnectionToStateMapping<TCPState> &conn, bool has_data, char flags, MinetHandle mux, Buffer buf)
{
    //Check whether or not you're sending data. Slightly different loop if so.
    if (! has_data)
    {
        Packet p;
        int state;
        TCPHeader tcp_head;
        IPHeader ip_head;
        ip_head.SetSourceIP(conn.connection.src);
        ip_head.SetDestIP(conn.connection.dest);
        ip_head.SetProtocol(IP_PROTO_TCP);  //Defined in tcp.h
        ip_head.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH); //Defined in tcp.h && ip.h
        tcp_head.SetSourcePort(conn.connection.srcport, p);
        tcp_head.SetDestPort(conn.connection.destport, p);       
        state = conn.state.GetState();
        /*
        switch (state)
        { 
        
        }
        */
    }

} 



int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    
   // int server = 0; //Set this to 0 for server, 1 for client. Remove after hard-code testing is completed.
    
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
    double timeout = 100;
    ////////////////////////////////////////////////
    
    
    while (MinetGetNextEvent(event, timeout) == 0) {    
    MinetSendToMonitor(MinetMonitoringEvent("GOT EVENT!"));

	if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	
	    if (event.handle == mux) {
		// ip packet has arrived!
        
        Packet p;
        unsigned char flags;
        TCPHeader tcp_head;
        IPHeader ip_head;     
        MinetReceive(mux,p);
        MinetSendToMonitor(MinetMonitoringEvent("HANDLING PACKET!"));
        cerr << "PACKET BEING HANDLED" << endl << endl << p;        
        analyze_packet(p);
        
        unsigned x = TCPHeader::EstimateTCPHeaderLength(p);
        p.ExtractHeaderFromPayload<TCPHeader>(x);
        tcp_head = p.FindHeader(Headers::TCPHeader);
        ip_head = p.FindHeader(Headers::IPHeader);
        tcp_head.GetFlags(flags);
        
        //switch 
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
