#ifndef __INTERFACE_FWD__
#define __INTERFACE_FWD__

#include <memory>

class Interface ;
class VlanInterface;
class PhysicalInterface;
class VirtualInterface;
class RmacInterface;
class VlanFloodInterface;
class VirtualPort;
class GRETunnelInterface ;
class LoopbackInterface;
class NVEInterface;
class BDInterface;
class ACInterface;

using InterfaceP = std::shared_ptr<Interface>;
using VlanInterfaceP = std::shared_ptr<VlanInterface>;
using PhysicalInterfaceP = std::shared_ptr<PhysicalInterface>;
using VirtualInterfaceP = std::shared_ptr<VirtualInterface>;
using RmacInterfaceP = std::shared_ptr<RmacInterface>;
using VlanFloodInterfaceP = std::shared_ptr<VlanFloodInterface>;
using VirtualPortP = std::shared_ptr<VirtualPort>;
using GRETunnelInterfaceP = std::shared_ptr<GRETunnelInterface>;
using InterfaceLoP = std::shared_ptr<LoopbackInterface>;
using NVEInterfaceP = std::shared_ptr<NVEInterface>;
using BDInterfaceP = std::shared_ptr<BDInterface>;
using ACInterfaceP = std::shared_ptr<ACInterface>;

#endif 