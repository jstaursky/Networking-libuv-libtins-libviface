#include "async-networking.hpp"


VNetwork::VNetwork (std::string ip, std::string name)
{
    iface = new viface::VIface (name, true);
    iface->setIPv4 (ip);
}

VNetwork::~VNetwork()
{
    delete sniffer;
    delete sender;
    delete iface;
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

void VNetwork::up ()
{
    if (!iface->isUp ())
        iface->up ();
    setup_sniffer ();
    setup_sender ();
}

void VNetwork::set_ip (std::string ip)
{
    iface->setIPv4 (ip);
}

void VNetwork::setup_sender ()
{
    sender = new Tins::PacketSender (Tins::NetworkInterface (iface->getName ()));
}

void VNetwork::setup_sniffer()
{
    if (!iface->isUp())
        iface->up();

    Tins::SnifferConfiguration conf;
    conf.set_filter ("ip src " + iface->getIPv4());
    conf.set_immediate_mode (true);

    sniffer = new Tins::Sniffer (iface->getName(), conf);
    pcap_setnonblock (sniffer->get_pcap_handle(), true, nullptr);
    sniffer->set_pcap_sniffing_method (pcap_dispatch);
}

void VNetwork::reconfigure_sniffer (std::string ip, std::string iface_name)
{
    if (!iface->isUp ())
        iface->up ();
    if (sniffer)
        delete sniffer; // remove default sniffer.

    Tins::SnifferConfiguration conf;
    conf.set_filter ("ip src " + ip);
    conf.set_immediate_mode (true);

    sniffer = new Tins::Sniffer (iface_name, conf);
    pcap_setnonblock (sniffer->get_pcap_handle (), true, nullptr);
    sniffer->set_pcap_sniffing_method (pcap_dispatch);
}

// Register sniffing events with event loop.
// NOTE: If an error occurs during polling then status < 0.
void VNetwork::attach_sniffer (uv_loop_t* loop, void (*c_callback) (uv_poll_t* handle, int status, int events))
{
    uv_poll_init (loop, &vnet_rx_h, sniffer->get_fd ());
    uv_handle_set_data ((uv_handle_t*)&vnet_rx_h, (void*) this);
    uv_poll_start (&vnet_rx_h, UV_READABLE, c_callback);
}

void VNetwork::attach_sender (uv_loop_t* loop, void (*c_callback) (uv_idle_t* handle))
{
    uv_idle_init (loop, &vnet_tx_h);
    uv_handle_set_data ((uv_handle_t*)&vnet_tx_h, (void*)this);
    uv_idle_start (&vnet_tx_h, c_callback);
}

void VNetwork::send_message (Tins::PDU* pdu)
{
    sender->send (*pdu);
}
