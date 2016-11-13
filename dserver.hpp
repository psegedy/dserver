/*
 * File: dserver.cpp
 * Date: 4.11.2016
 * Name: DHCP server, ISA project
 * Author: Patrik Segedy <xseged00@vutbr.cz>
 * Description: Simple DHCP server
 */

#ifndef __DSERVER_HPP
#define __DSERVER_HPP

#include <iostream>
#include <algorithm>
#include <ctime>
#include <fstream>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <csignal>

#define BUFSIZE 1024 // implicit buffer size
#define SERVER_PORT 67 // default server port
#define CLIENT_PORT 68	// default client port

#define OPTIONS_LENGTH 312
#define BROADCAST_BIT 32768

// DHCP message types
#define DHCPDISCOVER 1
#define DHCOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7

// BOOTP
#define BOOTPREQUEST 1
#define BOOTPREPLY 2

// options code
#define OPT_SERVER_ID 54
#define OPT_REQ_IP 50
// lease time
#define LEASE_TIME 120
#define LEASE_10Y 315532800

typedef struct dhcp_packet
{
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	u_char chaddr[16];
	u_char sname[64];
	u_char file[128];
	u_char options[OPTIONS_LENGTH];
} __attribute__ ((packed)) dhcp_packet;

typedef struct addresses
{
	uint32_t network;	//network address
	uint32_t first;		//first usable address(address of server)
	uint32_t last;		//last usable address
	uint32_t broadcast;	//broadcast address
	uint32_t mask;		//network mask
} addresses;

using namespace std;

// print usage
void usage();
// handle interrupt signal
void handleSignal(int signal);
// calculate ip addresses from network address
void get_addresses(addresses *addr);
// check program arguments, return excluded address list and filename of static allocations file
int check_args(int argc, char **argv, addresses *addr, vector<uint32_t> &excluded, string &static_file);
// get type of message from incoming packet (DHCPDISCOVER|DHCPREQUEST|DHCPRELEASE)
int get_message_type(dhcp_packet *packet);
/*check if ip address in paacket == ip_addr for OPT_REQ_IP or OPT_SERVER_ID
 *returns:
 *	0 - address is equal
 * 	1 - address is different
 *	2 - option not found
 * 	*ret_addr - returns ip address found in packet
*/
uint32_t check_ip_addr(dhcp_packet *packet, uint32_t ip_addr, uint8_t option, uint32_t *ret_addr = nullptr);
// send DHCPOFFER
uint32_t offer(int socket_handle, dhcp_packet *disc_packet, addresses *addr, vector<uint32_t> &pool,  vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease);
// send DHCPACK
int ack(int socket_handle, dhcp_packet *packet, uint32_t offered_address, addresses *addr, vector<uint32_t> &pool, vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease);
// send DHCPNAK
int nak(int socket_handle, dhcp_packet *packet, addresses *addr);
// find MAC address in leases
int find_by_mac(vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease, u_char *mac);
// delete expired leases
void del_expired(vector<uint32_t> &pool, vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease);
// delete lease for certain MAC address
int del_by_mac(vector<tuple<array<u_char, 16>, uint32_t, time_t, time_t>> &lease, vector<uint32_t> &pool, dhcp_packet *packet, int message_type);
// convert int number to vector of bytes
vector<unsigned char> itob(size_t number, int bytes);

#endif