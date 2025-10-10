
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <cctype>
#include <cstdio>
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/select.h>

#include "../graph.h"
#include "../net.h"
#include "../tcpconst.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"
#include "../common/cp2dp.h"
#include "../Interface/InterfaceUApi.h"
#include "LinuxInterface.h"


bool LinuxRtr = false;

// Structure to hold interface socket information
typedef struct linux_intf_socket_ {
    InterfaceP intf;
    int sockfd;
    int ifindex;
} linux_intf_socket_t;

static std::string read_file_content(const std::string& filepath) {
    // Limit filepath length to prevent buffer overflows
    if (filepath.length() > 512) {
        return "";
    }
    
    FILE* file = fopen(filepath.c_str(), "r");
    if (!file) {
        return "";
    }
    
    char buffer[256] = {0};
    std::string content;
    
    // Use fgets with explicit buffer size limit
    if (fgets(buffer, sizeof(buffer) - 1, file)) {
        buffer[sizeof(buffer) - 1] = '\0'; // Ensure null termination
        content = buffer;
        
        // Remove trailing newline and whitespace safely
        while (!content.empty()) {
            char last_char = content.back();
            if (last_char == '\n' || last_char == '\r' || std::isspace(last_char)) {
                content.pop_back();
            } else {
                break;
            }
        }
    }
    
    fclose(file);
    return content;
}

static bool get_mac_address(const std::string& if_name, unsigned char mac[6]) {
    if (if_name.empty() || if_name.length() > IFNAMSIZ) {
        return false;
    }
    
    std::string addr_file = "/sys/class/net/" + if_name + "/address";
    std::string content = read_file_content(addr_file);
    
    if (content.empty() || content.length() > 18) { // Max MAC length is 17 chars + null
        return false;
    }
    
    // Parse MAC address format: aa:bb:cc:dd:ee:ff
    // Use safer parsing without sscanf
    if (content.length() != 17) { // Exactly 17 characters: "aa:bb:cc:dd:ee:ff"
        return false;
    }
    
    // Check format: should have 5 colons at positions 2,5,8,11,14
    if (content[2] != ':' || content[5] != ':' || content[8] != ':' || 
        content[11] != ':' || content[14] != ':') {
        return false;
    }
    
    // Parse each byte manually
    for (int i = 0; i < 6; i++) {
        int pos = i * 3;
        if (pos + 1 >= (int)content.length()) {
            return false;
        }
        
        char hex_str[3] = {content[pos], content[pos + 1], '\0'};
        
        // Validate hex characters
        if (!std::isxdigit(hex_str[0]) || !std::isxdigit(hex_str[1])) {
            return false;
        }
        
        // Convert hex to byte
        unsigned int byte_val = 0;
        if (hex_str[0] >= '0' && hex_str[0] <= '9') {
            byte_val = hex_str[0] - '0';
        } else if (hex_str[0] >= 'a' && hex_str[0] <= 'f') {
            byte_val = hex_str[0] - 'a' + 10;
        } else if (hex_str[0] >= 'A' && hex_str[0] <= 'F') {
            byte_val = hex_str[0] - 'A' + 10;
        } else {
            return false;
        }
        
        byte_val *= 16;
        
        if (hex_str[1] >= '0' && hex_str[1] <= '9') {
            byte_val += hex_str[1] - '0';
        } else if (hex_str[1] >= 'a' && hex_str[1] <= 'f') {
            byte_val += hex_str[1] - 'a' + 10;
        } else if (hex_str[1] >= 'A' && hex_str[1] <= 'F') {
            byte_val += hex_str[1] - 'A' + 10;
        } else {
            return false;
        }
        
        mac[i] = (unsigned char)byte_val;
    }
    
    return true;
}

static bool get_operstate(const std::string& if_name) {
    if (if_name.empty() || if_name.length() > IFNAMSIZ) {
        return false;
    }
    
    std::string operstate_file = "/sys/class/net/" + if_name + "/operstate";
    std::string content = read_file_content(operstate_file);
    return (content == "up");
}

static bool get_ip_address(const std::string& if_name, uint32_t& ip_addr, uint8_t& prefix_len) {
    if (if_name.empty() || if_name.length() > IFNAMSIZ) {
        return false;
    }
    
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return false;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        close(sockfd);
        return false;
    }
    
    struct sockaddr_in* addr_in = (struct sockaddr_in*)&ifr.ifr_addr;
    ip_addr = ntohl(addr_in->sin_addr.s_addr);
    
    // Get netmask
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        close(sockfd);
        return false;
    }
    
    struct sockaddr_in* netmask_in = (struct sockaddr_in*)&ifr.ifr_netmask;
    uint32_t netmask = ntohl(netmask_in->sin_addr.s_addr);
    
    // Calculate prefix length
    prefix_len = 0;
    while (netmask & 0x80000000) {
        prefix_len++;
        netmask <<= 1;
    }
    
    close(sockfd);
    return true;
}

void 
LinuxLoadInterfaces (node_t *node) {

    DIR *dir;
    struct dirent *entry;
     ipv6_addr_t v6_addr = {0};

    dir = opendir("/sys/class/net");
    if (!dir) {
        std::cerr << "Failed to open /sys/class/net" << std::endl;
        return;
    }
    
    node->af_packet_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));    
    assert (node->af_packet_sock_fd > 0);

    while ((entry = readdir(dir)) != NULL) {
        std::string if_name = entry->d_name;
        
        // Skip special entries
        if (if_name.empty() || if_name == "." || if_name == "..") {
            continue;
        }
        
        // Skip interface names that are too long
        if (if_name.length() > IFNAMSIZ) {
            std::cerr << "Skipping interface with name too long: " << if_name << std::endl;
            continue;
        }
        
        // Skip loopback interface
        if (if_name == "lo") {
            continue;
        }

        /* IF inteface name do not start with ens* then skip*/
        if (if_name.find("ens") == std::string::npos) {
            continue;
        }
        
        // Get MAC address
        unsigned char mac_addr[6] = {0};
        bool has_mac = get_mac_address(if_name, mac_addr);
        
        // Get operational state
        bool is_up = get_operstate(if_name);
        
        // Get IP address
        uint32_t ip_addr = 0;
        uint8_t prefix_len = 0;
        bool has_ip = get_ip_address(if_name, ip_addr, prefix_len);
        
        // Create PhysicalInterface instance
        auto intf_shared = std::make_shared<PhysicalInterface>(if_name.c_str(), INTF_TYPE_PHY, nullptr);
        intf_shared->SetSharedPtr(intf_shared);
        Interface *intf = intf_shared.get();
        intf->att_node = node;
        
        // Assign MAC address
        if (has_mac) {
            mac_addr_t mac_addr_struct = {0};
            memcpy(mac_addr_struct.mac, mac_addr, 6);
            intf->SetMacAddr(&mac_addr_struct);
        }
        
        /* Get ifindex and store it */
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, intf->if_name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';

        assert (ioctl(node->af_packet_sock_fd, SIOCGIFINDEX, &ifr) == 0);
        intf->ifindex = ifr.ifr_ifindex;

        // Set IP address and add route if available
        if (has_ip) {
            intf->InterfaceSetIpAddressMask(ip_addr, prefix_len);
            interface_install_local_v4_routes  (node, intf);
        }
        
        mac_addr_t *mac_addr_ptr = intf->GetMacAddr();

        if (mac_addr_ptr) {

            intf->InterfaceSetIpv6LinkLocalAddress(&mac_addr_ptr->mac);
            intf->InterfaceGetIpv6LinkLocalAddress(&v6_addr.addr);
            ipv6_route_install  (node,
                        &v6_addr, 128, 
                        0, 0, 0, 0, 0,  (Srv6_endpcode_t)0,PROTO_STATIC);
        }
        
        int empty_intf_slot = node_get_intf_available_slot(node);
        assert (empty_intf_slot >= 0);
        node->intf[empty_intf_slot] = intf_shared;
         tcp_ip_init_intf_log_info(intf);
    }
    
    closedir(dir);

    LinuxRtr = true;
}

int
linux_send_xmit_out (Interface *intf, pkt_block_t *pkt_block) {

    assert (LinuxRtr);
        
    int sockfd = intf->att_node->af_packet_sock_fd;

    if (sockfd < 0) {

        cprintf ("%s : %s : linux_send_xmit_out() : Failed to create raw socket: errno : %d\n",
                intf->att_node->node_name, 
                intf->if_name.c_str(), strerror(errno));

        return -1;
    }
    
    int ifindex = intf->ifindex;
    char *pkt_data = (char*)pkt_block->pkt;
    int pkt_len = pkt_block->pkt_size;

    if (pkt_len <= 0 || pkt_len > MAX_MTU) { 

        cprintf ("%s : %s : linux_send_xmit_out() : Invalid packet length: %dB\n",
            intf->att_node->node_name, 
            intf->if_name.c_str(), pkt_len);

        return -1;
    }
    
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    sll.sll_halen = 6; // MAC address length
    
    mac_addr_t *src_mac = intf->GetMacAddr();
    memcpy(sll.sll_addr, src_mac->mac, 6);
    
    ssize_t bytes_sent = sendto(sockfd, pkt_data, pkt_len, 0, 
                               (struct sockaddr*)&sll, sizeof(sll));
    
    assert (bytes_sent > 0);
    intf->pkt_sent++;
    return (int)bytes_sent;
}

// Global variables for the listener thread
static linux_intf_socket_t intf_sockets[MAX_LINUX_INTERFACES];
static int num_intf_sockets = 0;
static bool listener_running = false;
static pthread_t listener_thread;

static void* 
linux_listener_thread(void* arg) {

    int max_fd = 0;
    fd_set read_fds;
    node_t *node = (node_t*)arg;
    ev_dis_pkt_data_t *ev_dis_pkt_data;
    char buffer[LINUX_PKT_SKT_BUFFER_SIZE];
    
    while (listener_running) {

        FD_ZERO(&read_fds);

        max_fd = 0;

        for (int i = 0; i < num_intf_sockets; i++) {

            if (intf_sockets[i].sockfd > 0) {

                FD_SET(intf_sockets[i].sockfd, &read_fds);

                if (intf_sockets[i].sockfd > max_fd) {
                    max_fd = intf_sockets[i].sockfd;
                }
            }
        }
        
        select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        
        for (int i = 0; i < num_intf_sockets; i++) {

            if (intf_sockets[i].sockfd > 0 && 
                FD_ISSET(intf_sockets[i].sockfd, &read_fds)) {
                
                struct sockaddr_ll from_addr;
                socklen_t from_len = sizeof(from_addr);

                ssize_t bytes_received = recvfrom(intf_sockets[i].sockfd, 
                        buffer,
                        sizeof(buffer), 0,
                        (struct sockaddr*)&from_addr, &from_len);
                
                if (bytes_received <= 0) {
                    continue;
                }
                
                ev_dis_pkt_data = new  ev_dis_pkt_data_t;
                ev_dis_pkt_data->pkt = tcp_ip_get_new_pkt_buffer(bytes_received);
                memcpy(ev_dis_pkt_data->pkt, buffer, bytes_received);
	            ev_dis_pkt_data->recv_node = node;
	            ev_dis_pkt_data->recv_intf = intf_sockets[i].intf;
	            ev_dis_pkt_data->pkt_size = bytes_received;

	            pkt_q_enqueue(EV_DP(node), DP_PKT_Q(node) ,
                  (char *)ev_dis_pkt_data, sizeof(ev_dis_pkt_data_t));
            }
        }
    }

    return NULL;
}

/* Start a single thread which will listen on all interfaces for the 
    Raw packet in infinite loop. Use select ( ) to multiplex on all interface
    sockets. When pkt is recvd successfully, create a new pkt_block
    structure and post the packet using dp_pkt_receive( )*/
void
Linux_listen_interfaces (node_t *node) {
    
    if (listener_running) {
        return;
    }
    
    // Initialize interface sockets array
    memset(intf_sockets, 0, sizeof(intf_sockets));
    num_intf_sockets = 0;
    
    // Create sockets for all interfaces
    for (int i = 0; i < MAX_INTF_PER_NODE; i++) {

        if (node->intf[i] && num_intf_sockets < MAX_LINUX_INTERFACES) {

            Interface *intf = node->intf[i].get();
            
            // Create raw socket for packet capture
            int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            int ifindex = intf->ifindex;
            
            // Bind socket to specific interface
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family = AF_PACKET;
            sll.sll_protocol = htons(ETH_P_ALL);
            sll.sll_ifindex = ifindex;
            
            if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
                std::cerr << "Linux_listen_interfaces: Failed to bind socket to " 
                          << intf->if_name << ": " << strerror(errno) << std::endl;
                close(sockfd);
                continue;
            }
            
            // Store socket information
            intf_sockets[num_intf_sockets].intf = intf->GetSharedPtr();
            intf_sockets[num_intf_sockets].sockfd = sockfd;
            intf_sockets[num_intf_sockets].ifindex = ifindex;
            num_intf_sockets++;
        }
    }
    
    if (num_intf_sockets == 0) {
        return;
    }
    
    // Start the listener thread
    listener_running = true;
    pthread_create(&listener_thread, NULL, linux_listener_thread, node);
}