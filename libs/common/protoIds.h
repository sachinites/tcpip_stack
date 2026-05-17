/*
 * protoIds.h - Standard Network Protocol Identifiers
 *
 * Covers:
 *   - IEEE 802 EtherType values
 *   - IANA IP Protocol numbers
 *   - Well-known UDP/TCP port numbers
 *   - Internal / stack-private protocol IDs
 *   - proto_id_str() : convert any ID to a human-readable string
 */

#ifndef __PROTO_IDS__
#define __PROTO_IDS__

#include <stdint.h>

typedef uint16_t gen_proto_id_t;
typedef uint8_t  ip_proto_id_t;

#define ETHERNET_HEADER         0x3

/* =========================================================================
 * EtherType values  (carried in Ethernet II / 802.1Q type field, 16-bit)
 * ========================================================================= */

#define ETH_TYPE_IPv4           0x0800  /* Internet Protocol v4          */
#define ETH_TYPE_ARP            0x0806  /* Address Resolution Protocol   */
#define ETH_TYPE_RARP           0x8035  /* Reverse ARP                   */
#define ETH_TYPE_IPv6           0x86DD  /* Internet Protocol v6          */
#define ETH_TYPE_MPLS_UC        0x8847  /* MPLS unicast                  */
#define ETH_TYPE_MPLS_MC        0x8848  /* MPLS multicast                */
#define ETH_TYPE_VLAN_8021Q     0x8100  /* 802.1Q VLAN tag               */
#define ETH_TYPE_VLAN_8021AD    0x88A8  /* 802.1ad QinQ (provider VLAN)  */
#define ETH_TYPE_LLDP           0x88CC  /* Link Layer Discovery Protocol */
#define ETH_TYPE_EAP_8021X      0x888E  /* 802.1X EAP over LAN           */
#define ETH_TYPE_PAUSE          0x8808  /* 802.3x flow-control PAUSE     */
#define ETH_TYPE_PPPoE_DISC     0x8863  /* PPPoE discovery stage         */
#define ETH_TYPE_PPPoE_SES      0x8864  /* PPPoE session stage           */
#define ETH_TYPE_FCOE           0x8906  /* Fibre Channel over Ethernet   */
#define ETH_TYPE_GRE            0x6558  /* Transparent Ethernet in GRE   */
#define ETH_TYPE_ISIS           0x00FE  /* IS-IS (some implementations)  */

/* =========================================================================
 * IANA IP Protocol numbers  (carried in IPv4 "Protocol" / IPv6 "Next Hdr")
 * Reference: https://www.iana.org/assignments/protocol-numbers
 * ========================================================================= */

#define IP_PROTO_ICMP           1       /* Internet Control Message      */
#define IP_PROTO_IGMP           2       /* Internet Group Management     */
#define IP_PROTO_IP_IN_IP       4       /* IPv4 encapsulation            */
#define IP_PROTO_TCP            6       /* Transmission Control          */
#define IP_PROTO_UDP            17      /* User Datagram                 */
#define IP_PROTO_IPv6           41      /* IPv6 encapsulation            */
#define IP_PROTO_SRH            43      /* SRH header*/
#define IP_PROTO_GRE            47      /* Generic Routing Encapsulation */
#define IP_PROTO_ESP            50      /* Encap Security Payload (IPsec)*/
#define IP_PROTO_AH             51      /* Authentication Header (IPsec) */
#define IP_PROTO_ICMPv6         58      /* ICMP for IPv6                 */
#define IP_PROTO_IPv6_NONXT     59      /* No next header (IPv6)         */
#define IP_PROTO_IPv6_OPTS      60      /* IPv6 destination options      */
#define IP_PROTO_EIGRP          88      /* Cisco EIGRP                   */
#define IP_PROTO_OSPF           89      /* Open Shortest Path First      */
#define IP_PROTO_IPIP           94      /* IP-within-IP Encapsulation    */
#define IP_PROTO_PIM            103     /* Protocol Independent Multicast*/
#define IP_PROTO_MPLS_IN_IP     137     /* MPLS-in-IP                    */
#define IP_PROTO_IPv6_ROUTE     43      /* IPv6 routing header / SRH     */
#define IP_PROTO_RSVP           46      /* Resource Reservation Protocol */
#define IP_PROTO_LDP            0xFF    /* Label Distribution (internal) */
#define IP_PROTO_ISIS           0x83    /* IS-IS (NLPID)                 */
#define IP_PROTO_ISIS_SRv6      0x85    /* IS-IS SRv6 (non-standard)     */
#define IP_PROTO_SRv6           115     /* SRv6 (internal ID)            */

/*======= SUB Proto Messages ============== */
#define ARP_BROAD_REQ 0x1
#define ARP_REPLY     0x2


/* =========================================================================
 * Well-known TCP / UDP port numbers
 * ========================================================================= */

#define PORT_FTP_DATA           20
#define PORT_FTP_CTRL           21
#define PORT_SSH                22
#define PORT_TELNET             23
#define PORT_SMTP               25
#define PORT_DNS                53
#define PORT_DHCP_SERVER        67
#define PORT_DHCP_CLIENT        68
#define PORT_TFTP               69
#define PORT_HTTP               80
#define PORT_NTP                123
#define PORT_SNMP               161
#define PORT_SNMP_TRAP          162
#define PORT_BGP                179
#define PORT_LDAP               389
#define PORT_HTTPS              443
#define PORT_LDP                646
#define PORT_RSVP_ENCAP         1698    /* RSVP over UDP                 */
#define PORT_L2TP               1701
#define PORT_PPTP               1723
#define PORT_RADIUS_AUTH        1812
#define PORT_RADIUS_ACCT        1813
#define PORT_BFD_CTRL           3784
#define PORT_BFD_ECHO           3785
#define PORT_VXLAN              4789
#define PORT_MPLS_UDP           6635    /* MPLS-in-UDP (RFC 7510)        */
#define PORT_GENEVE             6081

/* =========================================================================
 * Miscellaneous / stack-internal protocol tags
 * ========================================================================= */

#define PROTO_ANY               0xFFFE  /* Wildcard — match any proto    */
#define PROTO_MISC_APP          0xFFFD  /* Post-MPLS / misc app payload  */
#define PROTO_STATIC            101     /* Static route (internal tag)   */

/* =========================================================================
 * proto_id_str() — convert a protocol identifier to a printable string.
 *
 * The function first tries EtherType / IP-protocol well-known values, then
 * falls back to port-number names, then returns "unknown".
 * ========================================================================= */

static inline const char *
proto_id_str(uint16_t proto)
{
    switch (proto) {

    case ETHERNET_HEADER:           return "Ethernet";

    /* EtherTypes */
    case ETH_TYPE_IPv4:             return "IPv4";
    case ETH_TYPE_ARP:              return "ARP";
    case ETH_TYPE_RARP:             return "RARP";
    case ETH_TYPE_IPv6:             return "IPv6";
    case ETH_TYPE_MPLS_UC:          return "MPLS-UC";
    case ETH_TYPE_MPLS_MC:          return "MPLS-MC";
    case ETH_TYPE_VLAN_8021Q:       return "802.1Q";
    case ETH_TYPE_VLAN_8021AD:      return "802.1ad-QinQ";
    case ETH_TYPE_LLDP:             return "LLDP";
    case ETH_TYPE_EAP_8021X:        return "802.1X-EAP";
    case ETH_TYPE_PAUSE:            return "PAUSE";
    case ETH_TYPE_PPPoE_DISC:       return "PPPoE-Discovery";
    case ETH_TYPE_PPPoE_SES:        return "PPPoE-Session";
    case ETH_TYPE_FCOE:             return "FCoE";
    case ETH_TYPE_GRE:              return "GRE-Ethernet";

    /* IP protocol numbers (some overlap with EtherType — handled above) */
    case IP_PROTO_ICMP:             return "ICMP";
    case IP_PROTO_IGMP:             return "IGMP";
    case IP_PROTO_IP_IN_IP:         return "IP-in-IP";
    case IP_PROTO_TCP:              return "TCP";
    case IP_PROTO_UDP:              return "UDP";
    case IP_PROTO_GRE:              return "GRE";
    case IP_PROTO_ESP:              return "ESP";
    case IP_PROTO_AH:               return "AH";
    case IP_PROTO_ICMPv6:           return "ICMPv6";
    case IP_PROTO_IPv6_NONXT:       return "IPv6-NoNxt";
    case IP_PROTO_IPv6_OPTS:        return "IPv6-DestOpts";
    case IP_PROTO_EIGRP:            return "EIGRP";
    case IP_PROTO_OSPF:             return "OSPF";
    case IP_PROTO_IPIP:             return "IPIP";
    case IP_PROTO_PIM:              return "PIM";
    case IP_PROTO_MPLS_IN_IP:       return "MPLS-in-IP";
    case IP_PROTO_RSVP:             return "RSVP";
    case IP_PROTO_IPv6_ROUTE:       return "SRH/IPv6-Route";
    case IP_PROTO_LDP:              return "LDP";
    case IP_PROTO_ISIS:             return "IS-IS";
    case IP_PROTO_ISIS_SRv6:        return "IS-IS-SRv6";
    case IP_PROTO_SRv6:             return "SRv6";

    /* Well-known ports (only unambiguous ones included) */
    case PORT_FTP_DATA:             return "FTP-Data";
    case PORT_FTP_CTRL:             return "FTP";
    case PORT_SSH:                  return "SSH";
    case PORT_TELNET:               return "Telnet";
    case PORT_SMTP:                 return "SMTP";
    case PORT_DNS:                  return "DNS";
    case PORT_DHCP_SERVER:          return "DHCP-Server";
    case PORT_DHCP_CLIENT:          return "DHCP-Client";
    case PORT_TFTP:                 return "TFTP";
    case PORT_HTTP:                 return "HTTP";
    case PORT_NTP:                  return "NTP";
    case PORT_SNMP:                 return "SNMP";
    case PORT_SNMP_TRAP:            return "SNMP-Trap";
    case PORT_BGP:                  return "BGP";
    case PORT_LDAP:                 return "LDAP";
    case PORT_HTTPS:                return "HTTPS";
    case PORT_LDP:                  return "LDP-Port";
    case PORT_L2TP:                 return "L2TP";
    case PORT_PPTP:                 return "PPTP";
    case PORT_RADIUS_AUTH:          return "RADIUS-Auth";
    case PORT_RADIUS_ACCT:          return "RADIUS-Acct";
    case PORT_BFD_CTRL:             return "BFD-Ctrl";
    case PORT_BFD_ECHO:             return "BFD-Echo";
    case PORT_VXLAN:                return "VXLAN";
    case PORT_MPLS_UDP:             return "MPLS-UDP";
    case PORT_GENEVE:               return "Geneve";

    /* Stack-internal */
    case PROTO_STATIC:              return "Static";
    case PROTO_MISC_APP:            return "MiscApp";
    case PROTO_ANY:                 return "any";

    default:                        return "unknown";
    }
}



#endif /* __PROTO_IDS__ */
