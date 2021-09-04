#ifndef ASYNC_NETWORKING_H
#define ASYNC_NETWORKING_H

#include <tins/tins.h>
#include <viface/viface.hpp>
#include "uv.h"

#include <iostream>



class VNetwork
{
    using vnet_poll = uv_poll_t;

public:
    VNetwork(std::string ip, std::string name);
    ~VNetwork();

    void up ();
    void setIPv4 (std::string);
    void setup_sniffer (std::string ip, std::string name);
    void setup_sniffer ();
    void set_sender ();

private:
    viface::VIface* iface;
    Tins::BaseSniffer* sniffer;
    Tins::PacketSender* sender;

    vnet_poll tun_poll;
};



#endif /* ASYNC-NETWORKING_H */
