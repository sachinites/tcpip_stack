#ifndef __INTERFACE_FWD__
#define __INTERFACE_FWD__
#include <memory>

class Interface ;
class VlanInterface;
class PhysicalInterface;
class VirtualInterface;
class VirtualPort;
class GRETunnelInterface ;

using InterfaceP = std::shared_ptr<Interface>;
using VlanInterfaceP = std::shared_ptr<VlanInterface>;
using PhysicalInterfaceP = std::shared_ptr<PhysicalInterface>;
using VirtualInterfaceP = std::shared_ptr<VirtualInterface>;
using VirtualPortP = std::shared_ptr<VirtualPort>;
using GRETunnelInterfaceP = std::shared_ptr<GRETunnelInterface>;

#endif 