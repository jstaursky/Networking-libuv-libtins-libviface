#ifndef ASYNC_NETWORKING_H
#define ASYNC_NETWORKING_H

#include <tins/tins.h>
#include <viface/viface.hpp>
#include "uv.h"

#include <iostream>

extern "C" void vnetwork_monitoring(uv_poll_t *handle, int status, int events);

class VNetwork {
    friend void vnetwork_monitoring(uv_poll_t *, int, int);
public:
	VNetwork (std::string ip, std::string name);
	~VNetwork();

	void up ();                 // NOTE: up() _should_ be be run before using any
                                // of the setup_* functions.
	void set_ip (std::string);

    // Attach to event loop.
	void attach_sniffer (uv_loop_t* loop, void (*c_callback)(uv_poll_t*, int, int));
    void send_packet();
    void reconfigure_sniffer(std::string ip, std::string name);

  private:
    // Default sniffer and sender configuring.
    void setup_sniffer();
    void setup_sender();

    viface::VIface *iface;
    Tins::BaseSniffer *sniffer;
    Tins::PacketSender *sender;

    uv_poll_t vnet_poll_h; // libuv handle
};

#endif /* ASYNC_NETWORKING_H */

