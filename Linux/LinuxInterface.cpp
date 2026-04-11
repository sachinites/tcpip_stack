
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

#include "../router_init.h"
#include "../net.h"
#include "../tcpconst.h"
#include "../Layer3/SegmentRouting/SRv6/common/srv6_const.h"
#include "../dpal/cp2dp.h"
#include "../Interface/InterfaceUApi.h"
#include "LinuxInterface.h"
#include "../RTM/rtm.h"
#include "../RTM/rtm_nb_integ.h"
#include "../libs/common/cmn_prefix.h"
#include "../libs/common/ipv6_utils.h"
#include "../libs/pkt-block/pkt_block.h"
#include "../datapath/dp_uapi.h"


bool LinuxRtr = true;

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

    assert (dir);

    int af_packet_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));    
    assert (af_packet_sock_fd > 0);

    while ((entry = readdir(dir)) != NULL) {

        std::string if_name = entry->d_name;
        
        // Skip special entries
        if (if_name.empty() || if_name == "." || if_name == "..") {
            continue;
        }
        
        // Skip loopback interface
        if (if_name == "lo" || if_name == LINUX_MGMT_INTERFACE) {
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

        assert (ioctl(af_packet_sock_fd, SIOCGIFINDEX, &ifr) == 0);
        intf->ifindex = ifr.ifr_ifindex;
        assert (intf->ifindex <= MAX_INTF_IFINDEX );
        /* Reserve this ifindex*/
        interface_reserve_ifindex (node, intf->ifindex);

        cprintf ("\nLinuxRouter Detected NIC : ifname = %s, ifindex = %u", 
            intf->if_name.c_str(), intf->ifindex);

        cp2dp_interface_create(node, intf);
        vrf_add_interface(NODE_DEF_VRF(node), intf);
        cp2dp_send_intf_admin_status_update(node, intf->ifindex, !is_up);

        // Set IP address and add route if available
        if (has_ip) {

            intf->InterfaceSetIpAddressMask(ip_addr, prefix_len);
            
            cp2dp_send_intf_ipv4_addr_update(
                node, intf->ifindex, ip_addr, prefix_len);            

            rtm_t *rtm = rtm_get(node, RTM_DEFAULT_VRF, AF_IPV4, 0);
            intf->rtm_local_rt_idx = 
                cp_rtm_install_local_or_connected_v4_routes (
                    rtm, ip_addr, 32, intf->GetSharedPtr());
            intf->rtm_connected_rt_idx = 
                cp_rtm_install_local_or_connected_v4_routes (
                    rtm, apply_mask2 (ip_addr, prefix_len), prefix_len, intf->GetSharedPtr());
        }
        
        mac_addr_t *mac_addr_ptr = intf->GetMacAddr();

        if (mac_addr_ptr) {
            
            intf->InterfaceSetIpv6LinkLocalAddress(&mac_addr_ptr->mac);
            intf->InterfaceGetIpv6LinkLocalAddress(&v6_addr.addr);

            /* Install IPv6 link-local address route using new RTM API */
            rtm_t *rtm = rtm_get(node, RTM_DEFAULT_VRF, AF_IPV6, 0);

            intf->rtm_link_local_rt6_idx =
                cp_rtm_install_local_or_connected_v6_routes(
                    rtm, &v6_addr, 128, intf->GetSharedPtr());
        
            if (intf->rtm_link_local_rt6_idx == 0)
            {
                char ipv6_str[48];
                inet_ntop(AF_INET6, &v6_addr.addr, ipv6_str, sizeof(ipv6_str));
                cprintf("Warning: Failed to install IPv6 link-local route %s/128 on interface %s\n",
                        ipv6_str, intf->if_name.c_str());
            }
            else {
                cp2dp_send_intf_ipv6_addr_update(
                    node, intf->ifindex, v6_addr.addr, 128);
            }
        }

        bool inserted = node_global_intf_map_insert(node, intf);
        assert (inserted);
    }
    
    closedir(dir);
    close (af_packet_sock_fd);
    LinuxRtr = true;
}

int
linux_send_xmit_out (Interface *intf, pkt_block_t *pkt_block) {

    assert (LinuxRtr);
        
    int sockfd = intf->GetSockfd();

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
static bool listener_running = false;
static pthread_t listener_thread;

static void* 
linux_listener_thread(void* arg) {

    int sock_fd;
    int max_fd = 0;
    fd_set read_fds;
    node_t *node = (node_t*)arg;
    pkt_block_t *pkt_block;
    char buffer[LINUX_PKT_SKT_BUFFER_SIZE];
    
    while (listener_running) {

        FD_ZERO(&read_fds);

        max_fd = 0;

        Interface *intf;
        ITERATE_NODE_INTERFACES_BEGIN(node, intf) {
            
            sock_fd = intf->GetSockfd() ;

            if (sock_fd > 0) {

                FD_SET(sock_fd , &read_fds);

                if (sock_fd > max_fd) {
                    max_fd = sock_fd;
                }
            }
        } ITERATE_NODE_INTERFACES_END(node, intf);
        
        select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        
        ITERATE_NODE_INTERFACES_BEGIN(node, intf) {

            sock_fd = intf->GetSockfd() ;

            if (sock_fd > 0 &&  FD_ISSET(sock_fd, &read_fds)) {
                
                struct sockaddr_ll from_addr;
                socklen_t from_len = sizeof(from_addr);

                ssize_t bytes_received = recvfrom(sock_fd, 
                        buffer,
                        sizeof(buffer), 0,
                        (struct sockaddr*)&from_addr, &from_len);
                
                if (bytes_received <= 0) {
                    continue;
                }
                
                pkt_block = pkt_block_get_new(NULL, 0);
                pkt_block_set_new_pkt(pkt_block, (uint8_t *)buffer, bytes_received);
                pkt_block_update_new_hdr_type (pkt_block, ETHERNET_HEADER);
                dp_uapi_inject_packet (node->dp_ctx, pkt_block, intf->ifindex);
                XFREE(pkt_block);
            }
        } ITERATE_NODE_INTERFACES_END(node, intf);
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
    
    // Create sockets for all interfaces
    Interface *intf;
    ITERATE_NODE_INTERFACES_BEGIN(node, intf) {
            
        // Create raw socket for packet capture
        int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        int ifindex = intf->ifindex;
        intf->SetSockfd (sockfd);
        
        // Bind socket to specific interface
        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = ifindex;
        
        if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            cprintf ("Error : Linux_listen_interfaces: Failed to bind socket : if-name : %s , errno : %s\n", 
                      intf->if_name.c_str(), strerror(errno));
            close(sockfd);
            continue;
        }
    } ITERATE_NODE_INTERFACES_END(node, intf);
    
    listener_running = true;
    
    if (listener_running) pthread_create(&listener_thread, NULL, linux_listener_thread, node);
}
