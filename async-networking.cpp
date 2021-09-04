#include "async-networking.hpp"


VNetwork::VNetwork(std::string ip, std::string name)
{
    iface = new viface::VIface(name, false);
    iface->setIPv4(ip);
}

VNetwork::~VNetwork()
{
    delete iface;
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

void VNetwork::up()
{
    iface->up();
}
void VNetwork::setIPv4(std::string ip)
{
    iface->setIPv4(ip);
}

void VNetwork::setup_sniffer(std::string ip, std::string name)
{
    Tins::SnifferConfiguration conf;
    conf.set_filter("ip src " + ip);
    conf.set_immediate_mode(true);

    sniffer = new Tins::Sniffer (name, conf);
    pcap_setnonblock(sniffer->get_pcap_handle(), true, nullptr);
    sniffer->set_pcap_sniffing_method(pcap_dispatch);
}

void VNetwork::setup_sniffer()
{
    Tins::SnifferConfiguration conf;
    conf.set_filter("ip src " + iface->getIPv4());
    conf.set_immediate_mode(true);

    sniffer = new Tins::Sniffer (iface->getName(), conf);
    pcap_setnonblock(sniffer->get_pcap_handle(), true, nullptr);
    sniffer->set_pcap_sniffing_method(pcap_dispatch);
}

void VNetwork::set_sender()
{
    sender = new Tins::PacketSender(Tins::NetworkInterface (iface->getName()));
}
