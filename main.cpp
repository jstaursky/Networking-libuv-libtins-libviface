#include "async-networking.hpp"


int main(int argc, char *argv[])
{

    VNetwork vn_device ("192.168.20.21", "viface%d");
    vn_device.setup_sniffer();
    vn_device.set_sender();
    vn_device.up();


    return 0;
}
