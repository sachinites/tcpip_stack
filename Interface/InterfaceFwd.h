#ifndef __INTERFACE_FWD__
#define __INTERFACE_FWD__

#include <memory>

class Interface ;
class VlanInterface;
class PhysicalInterface;
class VirtualInterface;
class VirtualPort;
class GRETunnelInterface ;
class LoopbackInterface;
class BDInterface;
class ACInterface;
class HostPathInterface;
class NVEInterface;

using InterfaceP = std::shared_ptr<Interface>;
using VlanInterfaceP = std::shared_ptr<VlanInterface>;
using PhysicalInterfaceP = std::shared_ptr<PhysicalInterface>;
using VirtualInterfaceP = std::shared_ptr<VirtualInterface>;
using VirtualPortP = std::shared_ptr<VirtualPort>;
using GRETunnelInterfaceP = std::shared_ptr<GRETunnelInterface>;
using InterfaceLoP = std::shared_ptr<LoopbackInterface>;
using BDInterfaceP = std::shared_ptr<BDInterface>;
using ACInterfaceP = std::shared_ptr<ACInterface>;
using HostPathInterfaceP = std::shared_ptr<HostPathInterface>;
using NVEInterfaceP = std::shared_ptr<NVEInterface>;

#endif 