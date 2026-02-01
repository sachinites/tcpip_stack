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
class SRv6VirtualInterface;
class SRv6EndPointENDInterface;
class SRv6EndPointEND_XInterface;
class SRv6EndPointEND_DX4Interface;
class SRv6EndPointEND_DT4Interface;

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

using SRv6VirtualInterfaceP = std::shared_ptr<SRv6VirtualInterface>;
using SRv6EndPointENDInterfaceP = std::shared_ptr<SRv6EndPointENDInterface>;
using SRv6EndPointEND_XInterfaceP = std::shared_ptr<SRv6EndPointEND_XInterface>;
using SRv6EndPointEND_DX4InterfaceP = std::shared_ptr<SRv6EndPointEND_DX4Interface>;
using SRv6EndPointEND_DT4InterfaceP = std::shared_ptr<SRv6EndPointEND_DT4Interface>;

#endif 