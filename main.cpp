#include "async-networking.hpp"

extern "C" void vnetwork_monitoring (uv_poll_t* handle, int status, int events)
{
    auto info = (VNetwork*)uv_handle_get_data((uv_handle_t*)handle);

    if (status == UV_EAGAIN)
        return;
    if (status < 0)
        return;

    Tins::Packet packet = info->sniffer->next_packet();
    Tins::PDU* pdu = packet.pdu();
    Tins::RawPDU* raw = pdu->find_pdu<Tins::RawPDU>();

    Tins::RawPDU::payload_type& payload = raw->payload();
    for (size_t i = 0; i < payload.size(); ++i) {
        printf ("%c", payload[i]);
    }
    std::cout << std::endl;
}

int main (int argc, char *argv[])
{
	uv_loop_t* loop = uv_default_loop ();

	VNetwork vn_device ("192.168.20.21", "viface%d");
	vn_device.up ();
	// Attach sniffer monitoring to the event loop.
	vn_device.attach_sniffer (loop, vnetwork_monitoring);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);

	return 0;
}
