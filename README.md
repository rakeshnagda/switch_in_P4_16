Switch P4_16
=========

# Environment: Use "Flightplan's VM with the following additional installations:

    ./autogen.sh
    ./configure --with-bmv2 --with-pdfixed
    make
    sudo make install

# The recommended p4c and behavirol-model version are:

    commit c67f85d45feea5c31312c9a1e8a7063a976a1469 of the behavioral_model repo
    commit 730986bd4dce83a121159d06beb08ffa961afdc7 of the p4c repo

# The command to compile switch:

    p4c-bm2-ss --emit-externs -I../FPGA/RSEConfig -I../FPGA/MemcachedP4 -I../FPGA/RSEVivadoHLS/ -I Sources -o switch.json --target p4-build/bmv2 p4src/switch.p4 --arch v1model -DTARGET_BMV2 -DMID_FORWARDING_DECISION

# The command to run the test:

First, place the 'switch.json' into /p4-build/bmv2

Then, setup veth:

    sudo ./tools/veth_setup.sh

Then, start the software switch with:

    sudo ./bmv2/run_bm.sh

Then, start the drivers with:

    sudo ./bmv2/run_drivers.sh

You can now run all the tests:

    sudo ./bmv2/run_tests.sh  # for the PD tests

For more details refer to the switch.p4 (p4_14) README.