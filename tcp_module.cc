
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
#include <time.h>
#include <stdlib.h>
#include <stdio.h>


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
                if (IS_FIN(flags))
                {
                cerr << "\n FIN received! " << endl << "\nThe seqnum is:" << seqnum << "\nThe acknum is:" << acknum << endl;
                cerr << "\nThe source port is:\n" << srcport << endl << "\nThe dest prt is:\n" << destport << endl;
                cerr << "\nThe source IP is:\n" << source << endl << "\nThe dest IP is :\n" << destination << "\nThe rest of the packet is:" << p << endl;     
                }           
                else
                {
                cerr << "\n Some other kind of packet!\n";
                }
            }         
           
        }


}

//Respond_packet derives the correct action from the connection and whether or not there is data to be sent
//Return true if this connection should be killed after response. 
bool respond_packet (ConnectionToStateMapping<TCPState> &conn, bool get_data, char flags, const MinetHandle &mux, const MinetHandle &sock, unsigned int seq, unsigned int ack, Buffer b, short unsigned int data_length)
{
       
        cerr <<"\nIn respond_packet!\n";
        Packet p;
        //Buffer b;
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
                tcp_head.SetSeqNum(((rand()%50) +1) *3333, p);
                tcp_head.SetAckNum(seq+1, p);
                tcp_head.SetWinSize((unsigned short)5840, p);
                tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
                SET_ACK(response_flags);
                SET_SYN(response_flags);
                tcp_head.SetFlags(response_flags,p);                
                conn.state.SetState(SYN_RCVD);
                conn.state.last_acked = conn.state.last_sent-1;
                //conn.bTmrActive = true;
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
                //tcp_head.SetSeqNum(seq, p);
                //tcp_head.SetAckNum(ack, p);
                //tcp_head.SetWinSize((unsigned short)5840, p);
                //tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
                conn.state.SetState(ESTABLISHED);
                //conn.state.last_acked = conn.state.last_sent-1;
                conn.bTmrActive = true;
                conn.timeout=Time() + 60;
                conn.state.SetLastRecvd(seq+1);  
                if (get_data == true)
                    {
                    char *bufstring;
                    size_t size =0;
                    unsigned offset =0;
                    conn.state.RecvBuffer.GetData(bufstring, size, offset);
                    cerr << "\n Writing the following buffer to socket!: " << *bufstring << "\n";  
                        
                    }
                }
                 break;
            }    
            
            case SYN_SENT:
            {
                cerr << "\n In SYN_SENT state!\n";
                if (IS_SYN(flags) && IS_ACK(flags))
                {
                tcp_head.SetSeqNum(ack, p);
                tcp_head.SetAckNum(seq+1, p);
                tcp_head.SetWinSize((unsigned short)5840, p);
                tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);              
                SET_ACK(response_flags);
                tcp_head.SetFlags(response_flags,p);    
                conn.state.SetState(ESTABLISHED);
                conn.timeout=Time() + 60;
                p.PushBackHeader(tcp_head);
                cerr << endl << endl << "\n Packet constructed! Looks like:" << endl << p << endl;
                MinetSend(mux, p);
                }
				SockRequestResponse srr;
                srr.connection = conn.connection;
                srr.error = 0;
                srr.bytes = 0;
                srr.type = WRITE;
                MinetSend(sock, srr);
            
            }
            
            case ESTABLISHED:
            {
                cerr << "\n In ESTABLISHED state!\n";
                if (!(IS_FIN(flags)) && !(IS_SYN(flags)) && !(IS_RST(flags)) && (IS_PSH(flags)))
                {
					cerr << "Received data!";
					tcp_head.SetSeqNum(ack, p);
					tcp_head.SetAckNum(seq + data_length, p);
					//
					tcp_head.SetWinSize((unsigned short)5840, p);
					tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
					SET_ACK(response_flags);
					tcp_head.SetFlags(response_flags,p);   
					conn.state.last_acked = conn.state.last_sent;
					conn.state.SetLastRecvd(seq+1);
					p.PushBackHeader(tcp_head);
					cerr << "\n \n \n Ack-packet response to data constructed! Looks like:\n" << p;
					MinetSend(mux, p);
					SockRequestResponse srr(WRITE, conn.connection, b, data_length, EOK);
					MinetSend(sock, srr);
                
                }
                else
                {
                    if (IS_ACK(flags) && !IS_FIN(flags))
                    {
                    conn.state.SetLastRecvd(seq);
                    conn.state.last_acked = ack;
                    cerr << "Received acknowledgment of data sent";                
                    }
					
                    else if (IS_FIN(flags))
                    {
                    conn.state.SetLastRecvd(seq+1);        
                    tcp_head.SetSeqNum(ack, p);
                    tcp_head.SetAckNum(seq+1, p);
                    tcp_head.SetWinSize((unsigned short)5840, p);
                    tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
                    SET_ACK(response_flags);
                    tcp_head.SetFlags(response_flags,p);
                    conn.state.SetState(CLOSE_WAIT);
                    conn.state.last_acked = conn.state.last_sent-1;
                    conn.state.SetLastRecvd(seq+1);
                    p.PushBackHeader(tcp_head);
                    MinetSend(mux, p);    
                    }
                }
                                
                break;
            }
            
            case FIN_WAIT1:
            {
                if (IS_FIN(flags) && IS_ACK(flags))
                {
                conn.state.SetState(FIN_WAIT2);
                conn.state.SetLastRecvd(seq+1);
                conn.state.last_acked = ack;
                tcp_head.SetSeqNum(ack, p);
                tcp_head.SetAckNum(seq+1, p);
                tcp_head.SetWinSize((unsigned short)5840, p);
                tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
                SET_ACK(response_flags);
                tcp_head.SetFlags(response_flags,p);     
                p.PushBackHeader(tcp_head);
                MinetSend(mux,p);
                }
                break;
            }
            
            case FIN_WAIT2:
            {
                if (IS_ACK(flags))
                {
                conn.state.SetLastRecvd(seq+1);
                conn.state.last_acked = ack;
                tcp_head.SetSeqNum(ack, p);
                tcp_head.SetAckNum(seq+1, p);
                tcp_head.SetWinSize((unsigned short)5840, p);
                tcp_head.SetHeaderLen(TCP_HEADER_BASE_LENGTH, p);
                SET_ACK(response_flags);
                tcp_head.SetFlags(response_flags,p);     
                p.PushBackHeader(tcp_head);
                MinetSend(mux,p);
                
                //Send the close to the socket
                SockRequestRespnse srr;
                srr.type = CLOSE;
                srr.connection = conn.connection;
                srr.bytes = 0;
                srr.error = EOK;
                MinetSend(sock, srr);
                
                //Return true to kill connection after response actions
                return true;
                }
            }
            
            case CLOSE_WAIT:
            {
                if (IS_ACK(flags))
                {
                //Send the close to the socket
                SockRequestRespnse srr;
                srr.type = CLOSE;
                srr.connection = conn.connection;
                srr.bytes = 0;
                srr.error = EOK;
                MinetSend(sock, srr);
                
                //Return true to kill connection after response action
                return true;
                }
            }
            
            default:
                cerr << "\n Dealing with something else!\n ";
                break;
        }
        return false;
} 

void createPacket(ConnectionToStateMapping<TCPState> &connection_map, Packet &new_packet, unsigned char flags, int data_size)
{
	IPHeader ip_header;
	TCPHeader tcp_header;
	IPAddress source = connection_map.connection.src;
	IPAddress destination = connection_map.connection.dest;
	unsigned short source_port = connection_map.connection.srcport;
	unsigned short destination_port = connection_map.connection.destport;
	
	// create the IP header
	ip_header.SetProtocol(IP_PROTO_TCP);
	ip_header.SetSourceIP(source);
	ip_header.SetDestIP(destination);
	ip_header.SetTotalLength(data_size + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
	
	// push IP header onto packet
	new_packet.PushFrontHeader(ip_header);
	
	// create the TCP header
	tcp_header.SetSourcePort(source_port, new_packet);
	tcp_header.SetDestPort(destination_port, new_packet);
	tcp_header.SetAckNum(connection_map.state.GetLastRecvd(), new_packet);
	tcp_header.SetSeqNum(connection_map.state.GetLastSent()+1, new_packet);
	tcp_header.SetWinSize(connection_map.state.GetRwnd(), new_packet);
	tcp_header.SetFlags(flags, new_packet);
	tcp_header.SetHeaderLen(TCP_HEADER_BASE_LENGTH, new_packet);
	tcp_header.SetUrgentPtr(0, new_packet);
	
	// we want the TCP header BEHIND the IP header
	new_packet.PushBackHeader(tcp_header);
}

int main(int argc, char * argv[]) {
    
    MinetHandle mux;
    MinetHandle sock;
    ConnectionList<TCPState> clist;

    srand(time(NULL));
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
    const char* addr = "192.168.106.2";
    const char* addr2 = "192.168.42.5";
    TCPState hardlistener(0, 1, 2);
    IPAddress testaddr(addr);
    IPAddress testaddr2(addr2);
    Connection testconn(testaddr, testaddr2, 13245, 12345, IP_PROTO_TCP);
    Time test_time(100000);
    ConnectionToStateMapping<TCPState> a(testconn, test_time, hardlistener, false);
    cerr << "\n\n\n Presenting the hard-coded connection:" << testconn << "\n";
    clist.push_back(a);
    ////cerr << "\n\n\n Presenting the connection list:" << clist << "\n";
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
        cerr << "\n\n\n Presenting the connection list:" << clist << "\n";
     
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
            
            //Complete the connection parameters (if the connection was generated by ACCEPT socket request, it will be missing destination IP address)
            current_conn.connection.dest = find_conn.dest;
            current_conn.connection.destport = find_conn.destport;
            
            
            //Find out if the packet has data.            
            //First set data length to the overall length of the packet
            
            ip_head.GetTotalLength(data_length);
            ip_head.GetHeaderLength(ip_header_length);
            tcp_head.GetHeaderLen(tcp_header_length);            
            //With no options supported (per project specifications), IP header length is always 20.
            data_length = data_length - (ip_header_length * 4) - (tcp_header_length * 4);
            cerr << "\n Calculated the data length to be: " << data_length << "\n";
           
            
            Buffer buf;
            buf = p.GetPayload();
            //data_length = buf.GetSize();
            
            // cerr << "\n By payload calculated the data length to be: " << data_length << "\n";
            
            //Now we can continue
            if (data_length == 0)
                has_data = false;
            else
                {
                current_conn.state.RecvBuffer = buf;
                //Also add in here the buffering mechanisms into the connection's state
                has_data = true;
                }
           
            bool kill_connect = false;           
            kill_connect = respond_packet(current_conn, has_data, flags, mux, sock, seq, ack, buf, data_length);
            if (kill_connect == true)
                clist.erase(current_conn);
            }
            
            
            //The connection does not exist
            else
            {
            cerr << "\n The connection does not exist!\n" << endl;
            
            }
            
       
        }
		
		// socket request or response has arrived
	    if (event.handle == sock)
		{
			SockRequestResponse request_from_socket;
			SockRequestResponse response_to_socket;
			
			MinetReceive(sock, request_from_socket);
			
			unsigned char flags = 0;
			
			Packet new_packet;
			
			cerr << request_from_socket << endl;
			
			// this iterates over the connection list to see if the connection is in it
			ConnectionList<TCPState>::iterator c_item = clist.FindMatching(request_from_socket.connection);
			
			// connection is not in the connection list
			if (c_item == clist.end())
			{
				cerr << "Connection is NOT in list\n";
				cerr << "REQUEST TYPE = " << request_from_socket.type << endl;
				switch (request_from_socket.type)
				{
					case CONNECT:
					{
						cerr << "CONNECT request\n\n" << endl;
						
						// add new TCP state to connection mapping
						TCPState new_tcp_state (1, SYN_SENT, 3);
						ConnectionToStateMapping<TCPState> connection_state_map (request_from_socket.connection, Time()+1, new_tcp_state, false);
						
						// create rest of packet (ip/tcp headers)
						SET_SYN(flags);
						createPacket(connection_state_map, new_packet, flags, 0);
						
						// need to send twice, first packed dropped?
						MinetSend(mux, new_packet);
						sleep(1);
						MinetSend(mux, new_packet);
						
						connection_state_map.state.SetLastSent(connection_state_map.state.GetLastSent()+1);
						clist.push_back(connection_state_map);
						
						response_to_socket.type = STATUS;
						response_to_socket.connection = request_from_socket.connection;
						response_to_socket.bytes = 0;
						response_to_socket.error = EOK;
						
						MinetSend(sock, response_to_socket);
						
						break;
					}
					case ACCEPT:
					{	
						cerr << "ACCEPT request" << endl;
						
						// add new TCP state to connection mapping
						TCPState new_tcp_state (1, LISTEN, 3);
						ConnectionToStateMapping<TCPState> connection_state_map(request_from_socket.connection, Time()+1, new_tcp_state, false);
						clist.push_back(connection_state_map);
						
						// send response to socket module
						response_to_socket.type = STATUS;
						response_to_socket.connection = request_from_socket.connection;
						response_to_socket.bytes = 0;
						response_to_socket.error = EOK;
						
						MinetSend(sock, response_to_socket);
						
						break;
					}	
					case STATUS:
					{
						cerr << "STATUS request" << endl;
						
						break;
					}	
					case WRITE:
					{
						cerr << "WRITE request" << endl;
						
						break;
					}
					case FORWARD:
					{
						cerr << "FORWARD request" << endl;
						
						break;
					}
					case CLOSE:
					{
						cerr << "CLOSE request" << endl;
						
						break;
					}
					default:
					{
						cerr << "default case ???" << endl;
						
						break;
					}
				}
			}
			
			// connection is already in the connection list
			else
			{
				cerr << "Connection is already in list\n" ; 
				cerr << "REQUEST TYPE = " << request_from_socket.type << "\n";
				
				ConnectionToStateMapping<TCPState> &current_conn = *c_item; 
				
				int state = current_conn.state.GetState();
				
				cerr << "CURRENT STATE = " << state << "\n";
				
				switch (request_from_socket.type)
				{
					case CONNECT:
					{
						cerr << "CONNECT request" << endl;
						
						break;
					}
					case ACCEPT:
					{	
						cerr << "ACCEPT request" << endl;
						
						break;
					}	
					case STATUS:
					{
						cerr << "STATUS request" << endl;
						
						// number of bytes sent
						int num_bytes = request_from_socket.bytes;
						current_conn.state.RecvBuffer.Erase(0, num_bytes);
							
						// there is still data to be written
						if (current_conn.state.RecvBuffer.GetSize() != 0)
						{
							response_to_socket.type = WRITE;
							response_to_socket.connection = request_from_socket.connection;
							response_to_socket.bytes = c_item->state.RecvBuffer.GetSize();
							response_to_socket.data = c_item->state.RecvBuffer;
							response_to_socket.error = EOK;
							
							MinetSend(sock, response_to_socket);
						}
						
						break;
					}	
					case WRITE:
					{
						cerr << "WRITE request" << endl;
						
						int total_size = current_conn.state.SendBuffer.GetSize() + request_from_socket.data.GetSize();
						
						cerr << "total_size = " << total_size << endl;
						
						// okay to send data
						if (total_size <= current_conn.state.TCP_BUFFER_SIZE)
						{
							cerr << "okay to send data" << endl;
							current_conn.state.SendBuffer.AddBack(request_from_socket.data);
						}
						
						// not enough space in buffer to send data
						else
						{
							cerr << "not enough space in buffer to send data" << endl;
							response_to_socket.type = STATUS;
							response_to_socket.connection = request_from_socket.connection;
							response_to_socket.bytes = 0;
							response_to_socket.error = EBUF_SPACE;
							MinetSend(sock, response_to_socket);
						}
						
						// get buffer data
						Buffer buffer = current_conn.state.SendBuffer;
						
						// remove old, already send data
						buffer.ExtractFront(current_conn.state.last_sent - current_conn.state.last_acked); 
						
						int buffer_size = min(buffer.GetSize(), TCP_MAXIMUM_SEGMENT_SIZE);
						
						new_packet = buffer.Extract(0, buffer_size);
						
						cerr << "\n\n\n\nlast_sent = " << current_conn.state.last_sent << endl;
						cerr << "last_acked = " << current_conn.state.last_acked << endl;
						cerr << "Buffer size = " << buffer_size << endl;
						cerr << "Buffer = " << buffer << endl;
						
						//SET_ACK(flags);
						createPacket(current_conn, new_packet, flags, buffer_size);
						
						//cerr << "\n\nPacket to send = \n" << new_packet << endl;
						
						MinetSend(mux, new_packet);
						
						current_conn.state.SetLastSent(current_conn.state.GetLastSent() + buffer_size);
						current_conn.state.SendBuffer.Erase(0, buffer_size);
						
						response_to_socket.type = STATUS;
						response_to_socket.connection = request_from_socket.connection;
						response_to_socket.bytes = buffer_size;
						response_to_socket.error = EOK;
						MinetSend(sock, response_to_socket);
						
						break;
					}
					case FORWARD:
					{
						cerr << "FORWARD request" << endl;
						
						break;
					}
					case CLOSE:
					{
						cerr << "CLOSE request" << endl;
						
						if (state == ESTABLISHED)
						{
							
						}
						else if (state == SYN_SENT)
						{
							
						}
						else if (state == SYN_RCVD)
						{
							
						}
						else if (state == CLOSE_WAIT)
						{
							
						}
						
						break;
					}
					default:
					{
						cerr << "default case ???" << endl;
						
						break;
					}
				}
			}
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	}

    }

    MinetDeinit();

    return 0;
}
