
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
        }


}

//Send packet derives the correct action from the connection, whether or not there is data, and flags
void send_packet (ConnectionToStateMapping<TCPState> &conn, bool has_data, char flags, MinetHandle mux)
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
        
        cerr << endl << endl << "Packet constructed! Looks like:" << endl << p << endl;
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
        TCPHeader tcp_head;
        IPHeader ip_head;     
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
        ip_head.GetDestIP(find_conn.src);
        ip_head.GetSourceIP(find_conn.dest);
        ip_head.GetProtocol(find_conn.protocol);
        tcp_head.GetSourcePort(find_conn.destport);        
        tcp_head.GetDestPort(find_conn.srcport);        
        
        cerr << "\n\n\n Presenting the connection we're searching for!:" << find_conn << "\n";
     
        ConnectionList<TCPState>::iterator conn_search = clist.FindMatching(find_conn);
        
        ConnectionToStateMapping<TCPState> &current_conn2 = *conn_search;   
        
        cerr << "\n\n\n The connection or lackthereof we found:" << current_conn2.connection << "\n";
        
            //The connection exists
            if (conn_search!= clist.end())
            {
            cerr << endl << endl << endl << "The connection exists!" << endl;
            
            //Conn_search currently points to the ConnectionToStateMapping corresponding to the connection, so initialize a mapping to grab it 
            //Now have 1 of 4 necessary things to know to use send_packet
            ConnectionToStateMapping<TCPState> &current_conn = *conn_search;    

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
