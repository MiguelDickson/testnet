
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

using namespace std;

struct TCPState {
    // need to write this
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()" ; 
	return os;
    }
};


int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    
    int server = 0; //Set this to 0 for server, 1 for client. Remove after hard-code testing is completed.
    
    ConnectionList<TCPState> clist;

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

    /*
    Main loop:
    */
    
    //This should later not be hard-coded and be a part of each connection
    
    int state;
    if (server ==0)
    {
        state =1; //Set initially to 1 in hard-coded server for "LISTEN" state. (See eState in tcpstate.h)
    }
    else
    {
        state =3; //Set initially to 3 in hard-coded client for "SENT ACK" state. Then send ACK. (See eState in tcpstate.h)
    }
  
   
    
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
        MinetSendToMonitor(MinetMonitoringEvent("HANDLING PACKET!"));
        MinetReceive(mux,p);
        unsigned x = TCPHeader::EstimateTCPHeaderLength(p);
        p.ExtractHeaderFromPayload<TCPHeader>(x);
        tcp_head = p.FindHeader(Headers::TCPHeader);
        ip_head = p.FindHeader(Headers::IPHeader);
        
        //If Listening 
        if (state == 1){
        
            if (server==0){
            tcp_head.GetFlags(flags);
                if (IS_SYN(flags))
                {
                //send SYNACK
                //send_packet( SYN_ACK PACKET) 
                state =3;                
                }
            
            }

        }
        
        if (state == 1) {
            
           if (server ==1) {
           tcp_head.GetFlags(flags);
                if (IS_SYN(flags) && IS_ACK(flags))
                {
                //send ACK
                //send_packet( ACK PACKET)
                state = 4;
                             
                }
           
           }
        
        
        }
        
        if (state = 3){
           
           if (server ==0){ 
           tcp_head.GetFlags(flags);
                if (IS_ACK(flags))
                {
                state = 5;                
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
