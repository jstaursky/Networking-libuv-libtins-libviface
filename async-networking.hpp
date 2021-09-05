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

	void up ();                 // NOTE: up() MUST be run before using any of
                                // the setup_* functions.
	void set_ip (std::string);
	void setup_sniffer (std::string ip, std::string name);
	void setup_sniffer ();
	void setup_sender ();
	void attach (uv_loop_t* loop, void (*callback)(uv_poll_t*, int, int));

private:
    viface::VIface* iface;
	Tins::BaseSniffer* sniffer;
	Tins::PacketSender* sender;

	uv_poll_t vnet_poll_h;  // libuv handle
	uv_poll_cb create_event_monitor ();
};

#endif /* ASYNC_NETWORKING_H */

