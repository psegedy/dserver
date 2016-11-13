/*
 * File: dserver.cpp
 * Date: 13.11.2016
 * Name: DHCP server, ISA project
 * Author: Patrik Segedy <xseged00@vutbr.cz>
 * Description: Simple DHCP server
 */
#include "dserver.hpp"

int socket_handle = -1; //global variable for socket

int main(int argc, char **argv)
{
	signal(SIGINT, handleSignal);

	dhcp_packet packet;
	addresses addr;
	int rcBytes;
	int port = SERVER_PORT;
	unsigned char buff[BUFSIZE];
	struct sockaddr_in sa;
	struct sockaddr_in client; // address of client
	socklen_t length; // length of sockaddr_in client
	vector<uint32_t> pool;
	vector<uint32_t> excluded;
	vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> lease;	//[(MAC, IP address, lease start, lease end), (...), ....]
	uint32_t offered_address = (uint32_t)-1;
	string filename;

	// check arguments
	if (check_args(argc, argv, &addr, excluded, filename) == 1)
		return EXIT_FAILURE;

	// open file with static allocations
	if (!filename.empty())
	{
		ifstream infile(filename);
		if (infile.good()) {
			string mac;
			string ip;
			string delim(":");
			array<u_char, 16> mac_arr;
			while (infile >> mac >> ip) {
				cout << "mac: " << mac << " ip: " << ip << endl;
				if (inet_addr(ip.c_str()) == (uint32_t)-1) {
					cerr << "Error: Invalid IP address: " << ip << " in file: " << filename << endl;
					return EXIT_FAILURE;
				}
				int cnt = 0;
				mac_arr.fill(0);
				size_t found = mac.find(delim);
				while (found != string::npos && cnt < 6) {
					mac_arr[cnt] = stoi(mac.substr(0, found), 0, 16);
					mac = mac.erase(0, (found + delim.length()));
					found = mac.find(delim);
					cnt++;
				}
				mac_arr[cnt] = stoi(mac.substr(0), 0, 16);

				if (cnt != 5) {
					cerr << "Error: Invalid MAC address in file: " << filename << endl;
					return EXIT_FAILURE;
				}
				cout << "--------------" << endl;
				for (int i = 0; i < 6; ++i)
				{
					cout << hex << +mac_arr[i] << ":";
				}
				cout << dec << "--------------" << endl;
				lease.emplace_back(mac_arr, inet_addr(ip.c_str()), time(nullptr), time(nullptr) + LEASE_100Y);
				excluded.push_back(inet_addr(ip.c_str()));
			}
		}
		else {
			cerr << "Error: File not found" << endl;
			usage();
			return EXIT_FAILURE;
		}
	}

	get_addresses(&addr);

	cout << "network: " << inet_ntoa(*(struct in_addr *)&addr.network) << endl;
	cout << "mask: " << inet_ntoa(*(struct in_addr *)&addr.mask) << endl;
	cout << "first: " << inet_ntoa(*(struct in_addr *)&addr.first) << endl;
	cout << "last: " << inet_ntoa(*(struct in_addr *)&addr.last) << endl;
	cout << "broadcast: " << inet_ntoa(*(struct in_addr *)&addr.broadcast) << endl;

	//initialize address pool
	for (uint32_t i = addr.first; i <= addr.last; i += htonl(1)) {
		pool.push_back(i);
	}

	for (auto i = pool.begin(); i != pool.end(); ++i) {
		cout << inet_ntoa(*(struct in_addr *)&(*i)) << " ";
	}
	cout << endl;
	//delete first address (server address) and excluded addresses from pool
	pool.erase(pool.begin());
	for (auto i = excluded.begin(); i != excluded.end(); ++i) {
		pool.erase(remove(pool.begin(), pool.end(), *i), pool.end());
	}

	for (auto i = pool.begin(); i != pool.end(); ++i) {
		cout << inet_ntoa(*(struct in_addr *)&(*i)) << " ";
	}
	cout << endl;

	// create UDP socket
	if ((socket_handle = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		cerr << "ERR: Failed to create socket" << endl;
		return EXIT_FAILURE;
	}

	// set sockaddr struct
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	sa.sin_port = htons(port);

	// bind
	if ((bind(socket_handle, (struct sockaddr*)&sa, sizeof(sa))) < 0) {
		cerr << "ERR: Failed to bind" << endl;
		return EXIT_FAILURE;
	}
	length = sizeof(client);

	while((rcBytes = recvfrom(socket_handle, buff, BUFSIZE, 0, (struct sockaddr*)&client, &length)) >= 0) {
		cout << "Request received from: " << inet_ntoa(client.sin_addr);
		cout << " port: " << ntohs(client.sin_port) << endl;
		del_expired(pool, lease); //delete expired leases

		memcpy(&packet, &buff, rcBytes); //TODO: move to recvfrom

		int message_type = get_message_type(&packet);

		if (message_type == DHCPDISCOVER) {
			cout << "Mam DIscover\n";
			if ((offered_address = offer(socket_handle, &packet, &addr, pool, lease)) == 1) {
				cerr << "ERR: Failed to offer" << endl;
			}
		}
		else if (message_type == DHCPREQUEST) {
			//check request && send ACK/NAK
			cout << "MAM REQUEST, poslem ACK/NAK" << endl;
			uint32_t req_addr = 0;
			cout << "R: " << ntohl(inet_addr("192.168.0.10")) << "\nF: " << ntohl(addr.first) << " " << inet_ntoa(*(struct in_addr *)&addr.first) << "\nL: " << ntohl(addr.last) << " ";
			cout << inet_ntoa(*(struct in_addr *)&addr.last) << endl;
			// SELECTING state
			if (check_ip_addr(&packet, addr.first, OPT_SERVER_ID) == 0
				&& check_ip_addr(&packet, offered_address, OPT_REQ_IP) == 0
				&& packet.ciaddr == 0) {
				cout << "SELECTING\n";
				if (ack(socket_handle, &packet, offered_address, &addr, pool, lease) != 0)
					cerr << "ERR: Failed to ack" << endl;
			}
			// INIT-REBOOT state
			else if (check_ip_addr(&packet, addr.first, OPT_SERVER_ID) == 2
				&& packet.ciaddr == 0) {
				check_ip_addr(&packet, req_addr, OPT_REQ_IP, &req_addr);
				cout << "INIT-REBOOT, request: " << inet_ntoa(*(struct in_addr *)&req_addr) << endl;
				if (packet.giaddr == 0) {
					if (ntohl(req_addr) < ntohl(addr.first) || ntohl(req_addr) > ntohl(addr.last)) {
						// ip address is not from my pool -> send DHCPNAK
						if (nak(socket_handle, &packet, &addr) != 0)
							cerr << "Err: Failed to send DHCPNAK" << endl;
						cout << "TODO: SEND NACK-----------------" << endl;
					}
					int i = 0;
					// cout << get<0>(lease[0]) << endl;
					if ((i = find_by_mac(lease, packet.chaddr)) != -1) {
						// check that it requests address same as in lease
						cout << "DEBUG: checking req_addr" << endl;
						if (get<1>(lease[i]) == req_addr) {
							cout << "DEBUG: req_addr OK" << endl;
							if (ack(socket_handle, &packet, req_addr, &addr, pool, lease) != 0)
								cerr << "ERR: Failed to ack" << endl;
						}
						else {
							if (nak(socket_handle, &packet, &addr) != 0)
								cerr << "Err: Failed to send DHCPNAK" << endl;
							cout << "DEBUG: req_addr BAD, send NACK?" << endl;
						}
					}
					// address not in leases -> do nothing, be silent
				}
				else if (ack(socket_handle, &packet, req_addr, &addr, pool, lease) != 0)
					cerr << "ERR: Failed to ack" << endl;
					
			}
			// RENEWING/REBINDING state
			else if (check_ip_addr(&packet, addr.first, OPT_SERVER_ID) == 2 
				&& check_ip_addr(&packet, req_addr, OPT_SERVER_ID) == 2
				&& packet.ciaddr != 0) {
				cout << "RENEWING/REBINDING" << endl;
				if (ack(socket_handle, &packet, packet.ciaddr, &addr, pool, lease) != 0)
					cerr << "ERR: Failed to ack" << endl;
			}			
			offered_address = (uint32_t)-1;
		}
		else if (message_type == DHCPRELEASE) {
			cout << "MAM RELEASE, uvolnim adresu" << endl;
			del_by_mac(lease, pool, &packet, DHCPRELEASE);
		}
	}
	return 0;
}

//TODO pridat IP adresy, rozsahy?
uint32_t offer(int socket_handle, dhcp_packet *disc_packet, addresses *addr, vector<uint32_t> &pool,  vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease)
{
	int err;
	struct sockaddr_in sa;
	int on = 0;		//0 -> unicast, 1 -> broadcast
	dhcp_packet offer_packet;
	uint32_t addr1;
	int i = -1;
	if ((i = find_by_mac(lease, disc_packet->chaddr)) != -1) {
		addr1 = get<1>(lease[i]);  //offering previously allocated address
	}
	else if (pool.size() < 1) {
		cerr << "Warning: Address pool is empty" << endl;
		return 1;
	}


	memset(&offer_packet, 0, sizeof(offer_packet));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family=AF_INET;
	sa.sin_port=htons(CLIENT_PORT);

	if (disc_packet->giaddr != 0) //using relay
		sa.sin_addr.s_addr = disc_packet->giaddr;
	else if (disc_packet->ciaddr != 0) //client has ip address
		sa.sin_addr.s_addr = disc_packet->ciaddr;
	else if (disc_packet->flags == BROADCAST_BIT) { //broadcast bit is set to 1
		on = 1;
		sa.sin_addr.s_addr = addr->broadcast;
	}
	else {
		// temporary solution
		on = 1;
		sa.sin_addr.s_addr = addr->broadcast;
	}

	//set socket to broadcast
	setsockopt(socket_handle,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on));

	//set dhcp packet options
	offer_packet.op = BOOTPREPLY;
	offer_packet.htype = disc_packet->htype;
	offer_packet.hlen = disc_packet->hlen;
	offer_packet.xid = disc_packet->xid;
	offer_packet.flags = disc_packet->flags;
	
	if (i < 0) {
		addr1 = pool.front();	//give client first address of pool
		pool.erase(pool.begin());	//delete first address from pool	
	}
	cout << "DEBUG(253) i: " << i << " addr1: " << addr1 << endl;
	uint32_t addr2 = addr->first;
	memcpy(&offer_packet.yiaddr, &addr1, 4);
	memcpy(&offer_packet.siaddr, &addr2, 4);
	memcpy(&offer_packet.giaddr, &disc_packet->giaddr, 4);
	memcpy(&offer_packet.chaddr, &disc_packet->chaddr, 16);

	//magic cookie
	offer_packet.options[0] = 99;
	offer_packet.options[1] = 130;
	offer_packet.options[2] = 83;
	offer_packet.options[3] = 99;
	//dhcp message type - offer
	offer_packet.options[4] = 53;
	offer_packet.options[5] = 1;
	offer_packet.options[6] = 2;
	//lease time
	offer_packet.options[7] = 51;
	offer_packet.options[8] = 4;
	vector<unsigned char> v(itob(LEASE_TIME, 4));
	copy(v.begin(), v.end(), &offer_packet.options[9]);
	//server identifier
	offer_packet.options[13] = 54;
	offer_packet.options[14] = 4;
	v = itob(addr->first, 4);
	reverse_copy(v.begin(), v.end(), &offer_packet.options[15]);
	//subnet mask
	offer_packet.options[19] = 1;
	offer_packet.options[20] = 4;
	v = itob(addr->mask, 4);
	reverse_copy(v.begin(), v.end(), &offer_packet.options[21]);
	//end
	offer_packet.options[25] = 255;

	if ((err = sendto(socket_handle, &offer_packet, sizeof(offer_packet), 0, (struct sockaddr*)&sa, sizeof(sa))) < 0) {	
		cerr << "Error: sendto in offer: " << err << endl;
		return 1;
	}
	return addr1; //return offered address
}

int ack(int socket_handle, dhcp_packet *packet, uint32_t offered_address, addresses *addr, vector<uint32_t> &pool, vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease)
{
	int err;
	struct sockaddr_in sa;
	int on = 0;		//0 -> unicast, 1 -> broadcast
	dhcp_packet ack_packet;

	memset(&ack_packet, 0, sizeof(ack_packet));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family=AF_INET;
	sa.sin_port=htons(CLIENT_PORT);

	if (packet->giaddr != 0) //using relay
		sa.sin_addr.s_addr = packet->giaddr;
	else if (packet->ciaddr != 0) //client has ip address
		sa.sin_addr.s_addr = packet->ciaddr;
	else if (packet->flags == BROADCAST_BIT) { //broadcast bit is set to 1
		on = 1;
		sa.sin_addr.s_addr = addr->broadcast;
	}
	else {
		// here should be unicast to client's MAC address
		// broadcast anyway, i don't want to make SOCK_RAW 
		on = 1;
		sa.sin_addr.s_addr = addr->broadcast;
	}

	//set socket to broadcast
	setsockopt(socket_handle,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on));

	//set dhcp packet options
	ack_packet.op = BOOTPREPLY;
	ack_packet.htype = packet->htype;
	ack_packet.hlen = packet->hlen;
	ack_packet.xid = packet->xid;
	ack_packet.flags = packet->flags;
	uint32_t addr1 = offered_address;	//give client address from offer/request
	uint32_t addr2 = addr->first;
	memcpy(&ack_packet.yiaddr, &addr1, 4);
	memcpy(&ack_packet.siaddr, &addr2, 4);
	memcpy(&ack_packet.giaddr, &packet->giaddr, 4);
	memcpy(&ack_packet.chaddr, &packet->chaddr, 16);

	//magic cookie
	ack_packet.options[0] = 99;
	ack_packet.options[1] = 130;
	ack_packet.options[2] = 83;
	ack_packet.options[3] = 99;
	//dhcp message type - offer
	ack_packet.options[4] = 53;
	ack_packet.options[5] = 1;
	ack_packet.options[6] = DHCPACK;
	//lease time
	ack_packet.options[7] = 51;
	ack_packet.options[8] = 4;
	vector<unsigned char> v(itob(LEASE_TIME, 4));
	copy(v.begin(), v.end(), &ack_packet.options[9]);
	//server identifier
	ack_packet.options[13] = 54;
	ack_packet.options[14] = 4;
	v = itob(addr->first, 4);
	reverse_copy(v.begin(), v.end(), &ack_packet.options[15]);
	//subnet mask
	ack_packet.options[19] = 1;
	ack_packet.options[20] = 4;
	v = itob(addr->mask, 4);
	reverse_copy(v.begin(), v.end(), &ack_packet.options[21]);
	//end
	ack_packet.options[25] = 255;

	if ((err = sendto(socket_handle, &ack_packet, sizeof(ack_packet), 0, (struct sockaddr*)&sa, sizeof(sa))) < 0) {	
		cerr << "Error: sendto in ack: " << err << endl;
		return 1;
	}

	//update lease vector of tuples
	char buff_start[26];
	char buff_end[26];
	// get timestamps of start and end of lease
	time_t t_start = time(nullptr);
	time_t t_end = time(nullptr) + LEASE_TIME;
	array<u_char, 16> client_mac;
	//transform HW address of client from u_char* to array<u_char>
	memcpy(client_mac.data(), ack_packet.chaddr, 16);

	if (del_by_mac(lease, pool, &ack_packet, DHCPACK) != 1){
		// emplace lease info to vector
		lease.emplace_back(client_mac, offered_address, t_start, t_end);

		client_mac.fill(0);
		// print table of leases
		// for(auto row : lease) {
		auto row = lease.back();
		client_mac = get<0>(row);
		for (int i = 0; i < 5; ++i)
			cout << hex << +client_mac[i] << ":";
		ctime_r(&get<2>(row), buff_start);	//get c string from timestamp
		ctime_r(&get<3>(row), buff_end);
		string start(buff_start);	// get string from c string
		string end(buff_end);
		start.erase(start.find('\n', 0), 1);	// delete trailing \n
		end.erase(end.find('\n', 0), 1);
		// }
		cout << hex << +client_mac[5] << dec << " " << inet_ntoa(*(struct in_addr *)&get<1>(row)) << " " << start << " " << end << endl;
	}
	else {
		int i = -1;
		if ((i = find_by_mac(lease, ack_packet.chaddr)) != -1) {
			addr1 = get<1>(lease[i]);
			client_mac.fill(0);
			client_mac = get<0>(lease[i]);
			ctime_r(&get<2>(lease[i]), buff_start);	//get c string from timestamp
			ctime_r(&t_end, buff_end);
			string start(buff_start);	// get string from c string
			string end(buff_end);
			start.erase(start.find('\n', 0), 1);	// delete trailing \n
			end.erase(end.find('\n', 0), 1);
			for (int j = 0; j < 5; ++j)
				cout << hex << +client_mac[j] << ":";
			cout << hex << +client_mac[5] << dec << " " << inet_ntoa(*(struct in_addr *)&get<1>(lease[i])) << " " << start << " " << end << endl;
		}
	}
	
	return 0;
}

int nak(int socket_handle, dhcp_packet *packet, addresses *addr)
{
	int err;
	struct sockaddr_in sa;
	int on = 0;		//0 -> unicast, 1 -> broadcast
	dhcp_packet nak_packet;

	memset(&nak_packet, 0, sizeof(nak_packet));
	memset(&sa, 0, sizeof(sa));
	sa.sin_family=AF_INET;
	sa.sin_port=htons(CLIENT_PORT);

	//set socket to broadcast
	on = 1;
	sa.sin_addr.s_addr = addr->broadcast;
	// sa.sin_addr.s_addr = INADDR_BROADCAST;
	setsockopt(socket_handle,SOL_SOCKET,SO_BROADCAST,&on,sizeof(on));

	//set dhcp packet options
	nak_packet.op = BOOTPREPLY;
	nak_packet.htype = packet->htype;
	nak_packet.hlen = packet->hlen;
	nak_packet.xid = packet->xid;
	nak_packet.flags = packet->flags;
	memcpy(&nak_packet.giaddr, &packet->giaddr, 4);
	memcpy(&nak_packet.chaddr, &packet->chaddr, 16);

	//magic cookie
	nak_packet.options[0] = 99;
	nak_packet.options[1] = 130;
	nak_packet.options[2] = 83;
	nak_packet.options[3] = 99;
	//dhcp message type - offer
	nak_packet.options[4] = 53;
	nak_packet.options[5] = 1;
	nak_packet.options[6] = DHCPNAK;
	//server identifier
	nak_packet.options[7] = 54;
	nak_packet.options[8] = 4;
	std::vector<unsigned char> v;
	v = itob(addr->first, 4);
	reverse_copy(v.begin(), v.end(), &nak_packet.options[9]);
	//end
	nak_packet.options[13] = 255;

	if ((err = sendto(socket_handle, &nak_packet, sizeof(nak_packet), 0, (struct sockaddr*)&sa, sizeof(sa))) < 0) {	
		cerr << "Error: sendto in nack: " << err << endl;
		return 1;
	}
	return 0; //return offered address
}

//transform int to bytes
//inspired by http://stackoverflow.com/questions/5585532/c-int-to-byte-array
vector<unsigned char> itob(size_t number, int bytes)
{
	vector<unsigned char> v(bytes);
	for (int i = 0; i < bytes; ++i)
		v[(bytes - 1) - i] = (number >> (i * 8));
	return v;
}

void del_expired(vector<uint32_t> &pool, vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease)
{
	time_t now = time(nullptr);
	vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> to_delete;
	to_delete.clear();
	for (auto i = lease.begin(); i != lease.end(); ++i) {
		cout << "now: " << now << "end: " << get<3>(*i) << endl;
		if (now > get<3>(*i)) {
			cout << "deleting" << endl;
			to_delete.push_back(*i);
			pool.push_back(get<1>(*i));
		}
	}
	for (auto i = to_delete.begin(); i != to_delete.end(); ++i)
		lease.erase(remove(lease.begin(), lease.end(), *i), lease.end());
}

int del_by_mac(vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease, vector<uint32_t> &pool, dhcp_packet *packet, int message_type)
{
	array<u_char, 16> chaddr_arr;
	vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> to_delete;
	to_delete.clear();
	memcpy(&chaddr_arr, &packet->chaddr, 16);
	for (auto i = lease.begin(); i != lease.end(); ++i) {
		if (chaddr_arr == get<0>(*i)) {
			uint32_t addr = get<1>(*i);
			if (get<3>(*i) < (time(nullptr) + LEASE_TIME)) { //address is not statically allocated
				if (message_type == DHCPRELEASE || packet->yiaddr != addr) {
					cout << "release address: " << inet_ntoa(*(struct in_addr *)&addr) << endl;
					pool.push_back(addr);
					for (auto i = pool.begin(); i != pool.end(); ++i) {
						cout << inet_ntoa(*(struct in_addr *)&(*i)) << " ";
					}
					cout << endl;
				}
				to_delete.push_back(*i);
			}
			else
				return 1; //address is statically allocated
		}
	}
	for (auto i = to_delete.begin(); i != to_delete.end(); ++i) {
		lease.erase(remove(lease.begin(), lease.end(), *i), lease.end());
	}
	return 0;
}

int find_by_mac(vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease, u_char *mac)
{
	array<u_char, 16> chaddr_arr;
	memcpy(&chaddr_arr, mac, 16);
	cout << "DEBUG: finding mac: " << mac << endl;
	
	for (auto i = lease.begin(); i != lease.end(); ++i) {
		if (chaddr_arr == get<0>(*i)) {
			cout << "DEBUG: address found at: " << i - lease.begin() << endl; 
			return i - lease.begin();
		}
	}
	cout << "DEBUG: Mac not found" << endl;
	return -1;
}

//get 'DHCP message type'
int get_message_type(dhcp_packet *packet)
{
	uint8_t byte = 0;
	int i = 0;
	while(byte != 255) {
		byte = (uint8_t)packet->options[i];
		if (byte == 53 && (uint8_t)packet->options[i+1] == 1) //if option is 'DHCP message type'
			if ((uint8_t)packet->options[i+2] > 0 && (uint8_t)packet->options[i+2] < 8)	//message type is from interval <1,7>
				return (uint8_t)packet->options[i+2];
		i++;
	}
	return -1; //'DHCP message type' not found
}

uint32_t check_ip_addr(dhcp_packet *packet, uint32_t ip_addr, uint8_t option, uint32_t *ret_addr /*=nullptr*/)
{
	//options: 54 OPT_SERVER_ID 'server identifier'
	//		   50 OPT_REQ_IP 'requested ip address'
	uint8_t byte = 0;
	int i = 0;
	int ret = 0;
	vector<unsigned char> v;
	while(byte != 255) {
		byte = (uint8_t)packet->options[i];
		if (byte == option && (uint8_t)packet->options[i+1] == 4) { //if option is 'server identiier' or 'requested ip address'
			v = itob(ip_addr, 4);
			reverse(v.begin(), v.end());
			for (int j = 0; j < 4; ++j) {
				if (v[j] != packet->options[i+j+2])
					ret = 1;		//is not equal
			}
			if (ret_addr != nullptr)
				*ret_addr = (uint32_t(packet->options[i+5]) << 24 ) | (uint32_t(packet->options[i+4]) << 16 ) | (uint32_t(packet->options[i+3]) << 8 ) | uint32_t(packet->options[i+2]);
			return ret; // equal
		}
		i++;
	}
	return 2; //'server identifier' not found
}

// calculate broadcast, first and last usable address from network & mask
void get_addresses(addresses *addr)
{
	addr->broadcast = addr->network | ~(addr->mask);
	addr->first = addr->network + htonl(1);
	addr->last = addr->broadcast - htonl(1);
}

int check_args(int argc, char **argv, addresses *addr, vector<uint32_t> &excluded, string &static_file)
{	
	size_t found;
	string delim("/");
	string delim2(",");
	if (argc == 3 || argc == 5 || argc == 7) {
		if (strcmp(argv[1], "-p") == 0) {	// -p <ip_addr>/<mask>
			string addr_mask = argv[2];
			found = addr_mask.find(delim);
			if (found != string::npos)
				addr->network = inet_addr(addr_mask.substr(0, found).c_str());
				if ((int32_t)addr->network == -1) {
					cerr << "Invalid IP address" << endl;
					usage();
					return 1;
				}
				uint8_t cidr = stoi(addr_mask.erase(0, (found + delim.length())));
				if (cidr < 1 || cidr > 30) {
					cerr << "Invalid mask" << endl;
					usage();
					return 1;
				}
				addr->mask = htonl(~(0xffffffff >> cidr));
		}
		else {
			usage();
			return 1;
		}
		if (argc == 5 || argc == 7) {	// -p <ip_addr>/<mask> -e <ip_addr1,ip_addr2> [-s <static.txt>]
			if (strcmp(argv[3], "-e") == 0 || strcmp(argv[3], "-s") == 0 || (argc == 7 && strcmp(argv[3], "-e") == 0 && strcmp(argv[5], "-s") == 0)) {
				if (strcmp(argv[3], "-e") == 0) {
					string addrs = argv[4];
					found = addrs.find(delim2);
					uint32_t temp;
					while (found != string::npos) { 	//multiple addresses delimited by ','
						temp = inet_addr(addrs.substr(0, found).c_str());
						if ((int32_t)temp == -1) {
							cerr << "Invalid IP address" << endl;
							usage();
							return 1;
						}
						excluded.push_back(temp);
						addrs = addrs.erase(0, (found + delim2.length()));
						found = addrs.find(delim2);
					}
					// -e <ip_addr>
					temp = inet_addr(addrs.c_str());
					if ((int32_t)temp == -1) {
						cerr << "Invalid IP address" << endl;
						usage();
						return 1;
					}
					excluded.push_back(temp);
				}
				if (strcmp(argv[3], "-s") == 0) {
					static_file = argv[4];
				}
				if (argc == 7) {
					if (strcmp(argv[5], "-s") == 0) {
						static_file = argv[6];
					}
					else {
						usage();
						return 1;
					}
				}
			}
			else {
				usage();
				return 1;
			}
		}
	}
	else { // too many/few arguments
		usage();
		return 1;
	}
	for (auto i = excluded.begin(); i != excluded.end(); ++i) {
		cout << " " << inet_ntoa(*(struct in_addr *)&(*i));
	}
	cout << endl;

	return 0;
}

void handleSignal(int signal)
{
	if (socket_handle != -1)
		close(socket_handle);
	exit(signal);
}

void usage()
{
	cout << "Usage:" << endl
		 << "./dserver -p 192.168.0.0/24 [-e 192.168.0.1,192.168.0.2]" << endl << endl
		 << "Parameters" << endl
		 << "\t-p <ip_address/mask>   IP address range" << endl
		 << "\t-e <ip_addresses>      excluded addresses, delimited by ','" << endl
		 << "\t-s <static_file>       file that contains static allocations" << endl;
}