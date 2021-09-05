#include "async-networking.hpp"


class VNetwork::VNetworkIface : public viface::VIface {
public:
    VNetworkIface(std::string ip, std::string name) : viface::VIface (name, false) {
        setIPv4(ip);
    }
};

VNetwork::VNetwork(std::string ip, std::string name)
{
    iface = new VNetworkIface (ip, name);
}

VNetwork::~VNetwork()
{
	delete iface;
    delete sniffer;
    delete sender;
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

void VNetwork::up ()
{
	iface->up ();
}

void VNetwork::setIPv4 (std::string ip)
{
	iface->setIPv4 (ip);
}

void VNetwork::setup_sniffer (std::string ip, std::string name)
{
	Tins::SnifferConfiguration conf;
	conf.set_filter ("ip src " + ip);
	conf.set_immediate_mode (true);

	sniffer = new Tins::Sniffer (name, conf);
	pcap_setnonblock (sniffer->get_pcap_handle (), true, nullptr);
	sniffer->set_pcap_sniffing_method (pcap_dispatch);
}

void VNetwork::setup_sniffer ()
{
	Tins::SnifferConfiguration conf;
	conf.set_filter ("ip src " + iface->getIPv4 ());
	conf.set_immediate_mode (true);

	sniffer = new Tins::Sniffer (iface->getName (), conf);
	pcap_setnonblock (sniffer->get_pcap_handle (), true, nullptr);
	sniffer->set_pcap_sniffing_method (pcap_dispatch);
}

void VNetwork::setup_sender ()
{
	sender = new Tins::PacketSender (Tins::NetworkInterface (iface->getName ()));
}

// Register sniffing events with event loop.
// NOTE: If an error occurs during polling then status < 0.
void VNetwork::attach (uv_loop_t* loop, void (*callback)(uv_poll_t *handle, int status, int events))
{
	uv_poll_init (loop, &vnet_poll_h, sniffer->get_fd ());

    uv_handle_set_data((uv_handle_t*)&vnet_poll_h, (void*) this);

	uv_poll_start (&vnet_poll_h, UV_READABLE, callback);
}

