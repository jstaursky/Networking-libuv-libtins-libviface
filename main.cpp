#include "async-networking.hpp"

extern "C" void vnetwork_monitoring (uv_poll_t* handle, int status, int events)
{
    auto info = (VNetwork*)uv_handle_get_data ((uv_handle_t*)handle);

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

extern "C" void send_message (uv_idle_t* handle)
{
    auto msg = (VNetwork*)uv_handle_get_data ((uv_handle_t*)handle);
    Tins::IP pkt = Tins::IP (msg->destination_ip) / Tins::RawPDU (msg->message);
    msg->send_message (&pkt);
}

int main (int argc, char* argv[])
{
    uv_loop_t* loop = uv_default_loop ();
    VNetwork vn_device ("192.168.20.21", "viface%d");

    vn_device.up ();
    // Attach sniffer monitoring to the event loop.
    vn_device.attach_sniffer (loop, vnetwork_monitoring);

    vn_device.message = "hello\n";
    vn_device.destination_ip = "192.168.20.20";
    vn_device.attach_sender (loop, send_message);
    uv_run (loop, UV_RUN_DEFAULT);
    uv_loop_close (loop);

    return 0;
}
