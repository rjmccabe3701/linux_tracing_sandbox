#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <iostream>
#include <vector>

using std::cout;
using std::endl;

namespace pt = boost::property_tree;

struct TransmitIface
{
   size_t id;
   uint16_t tx_port;
   size_t kbps;
};

struct ReceiveIface
{
   size_t id;
   uint16_t rx_port;
};

int main(int argv, char** argc)
{
   pt::ptree root;
   pt::read_json(argc[1], root);

   std::vector<TransmitIface> tx_ifaces;
   std::vector<ReceiveIface> rx_ifaces;
   auto tx_ifaces_cfg = root.get_child("transmit_interfaces");

   for(auto& iface_cfg: tx_ifaces_cfg)
   {
      auto& tx_iface = tx_ifaces.emplace_back();
      tx_iface.id = iface_cfg.second.get<size_t>("id");
      tx_iface.tx_port = iface_cfg.second.get<uint16_t>("tx_port");
      tx_iface.kbps = iface_cfg.second.get<size_t>("bitrate_kbps");
   }
   auto rx_ifaces_cfg = root.get_child("receive_interfaces");
   for(auto& iface_cfg: rx_ifaces_cfg)
   {
      auto& rx_iface = rx_ifaces.emplace_back();
      rx_iface.id = iface_cfg.second.get<size_t>("id");
      rx_iface.rx_port = iface_cfg.second.get<uint16_t>("rx_port");
   }

   return 0;

}
