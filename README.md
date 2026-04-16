# GOOSE Authentication Stack Function (GASF) and Measurement Framework

This repository contains the user space implementation and tools developed 
for the In-network authentication of GOOSE traffic using Programmable Data Planes project.
The repository contains the GOOSE Authentication Stack Function (GASF), associated 
experiment scripts, and the measurement framework used to evaluate authentication 
overhead in representative programmable switching deployments.

## Aim of the Repository

The purpose of this repository is to provide the user space cryptographic processing component and supporting tools developed for this project. It supports:

- User space authentication and verification of GOOSE traffic through the GASF
- Support for multiple cryptographic schemes, including HMAC, BLAKE2s, AES-GCM/GMAC, and ChaCha20-Poly1305
- Packet processing for experimental authentication and verification workflows, in addition to authentication + encryption
- Execution of latency focused experiments under varying traffic conditions, which can be demonstrated on Mininet-based environments
- Scripts for recording performance measurements, including cryptographic, per-switch, and end-to-end latency
- Processing of experimental data into logs and structured output files for further analysis

This repository does not contain a complete standalone programmable switch implementation. Instead, it is intended to operate alongside an external BPFabric-based forwarding setup, which is responsible for the classification, redirection, and reinjection of GOOSE traffic during full system experiments.

Find BPFabric here https://github.com/UofG-netlab/BPFabric

### Directory Layout

- *switch_controls/* 
  This contains all the following directorys and is the main directory in the project

- **crypto/**  
  Contains the implementation of the crytogrpahic operations, including authentication, AEAD handling, extension formatting, and cryptographic profile management.

- **src/**  
  Implements packet handling and main switch logic, including sending, receiving, filtering, and integration with the cryptographic module.

- **data/**  
  Stores experimental outputs, including timing measurements and packet captures used for evaluation.

- **scripts/**  
  Contains the scripts for running experiments and capturing traffic.

## Requirements

The following dependencies are required to build and run the project:

- Linux-based operating system (tested on Ubuntu)
- GCC compiler
- libpcap
- OpenSSL 

For the measurment scripts and Mininet deployment:

- Python 3 
- Scapy
- tcpdump 
- Mininet 

Root privileges are required for packet capture and raw socket operations.

## Build

To compile the project, from within the `switch_controls/` directory, run:

```bash
make
```
## Running the Mininet Setup

From the `switch_controls/` directory, start the Mininet topology:

```bash
cd ..
sudo python3 mininet_setup.py
```

Once Mininet is running, open terminals for each S1, S2 and two for H1 (send and receive):
```bash
xterm S1 S2 H1 H1
```
In each terminal, move to the build directory:
```bash
cd switch_controls/build
```

### Host Programs

On H1 (receiver), run:
```bash
./receive
```
On H1 (sender), run:
```bash
./send
```
Nothing should happen yet, feel free to stop these and re-run once the switches are running.
### Switch Program

Both switches use the same executable and take two arguments:

1. **Switch mode**
   - `1` = authentication mode  
   - `2` = verification mode  

2. **Cryptographic profile**
   - `1` = HMAC-SHA256  
   - `2` = BLAKE2s  
   - `3` = AES-GMAC (authentication only)  
   - `4` = ChaCha20-Poly1305 (authentication only)  
   - `5` = AES-GMAC (AEAD)  
   - `6` = ChaCha20-Poly1305 (AEAD)  

On `S1`, run:
```bash
./switch1 1 {choice of profile}
```
Similarly for S2, run: 
```bash
./switch1 2 {choice of profile}
```
Ensure to choose the same profiles, else the pipeline will fail. The H1 receive script should now print received packets sequence numbers, this printing is purely for demonstration and debugging purposes.

### Possible issues/debug/fixes
  - For H1 (receiver), the receive port can be defined in `switch_controls/src/receive.c`, by changing the `LISTEN_IFACE`
  - For H1 (sender), the send port can be defined in `switch_controls/src/send.c`, by changing the `SEND_IFACE`, then on the H1 (sender) terminal:
  - For both switches, the ports are defined by the first argument, this will change the send_iface and the capture_iface, these can be seen at lines 326-332 in `switch1.c`, these can be adjusted if required (for the given switch mode) but will work for the current mininet setup.
  **any changes will require re-compiling using `make`**

### Measurment script:

To run the measurment script in the current Mininet setup, the best way is to open another xterm in Mininet (H1 preffered). From the `goose authentication` directory call:
```bash
 sudo python3 switch_controls/scripts/measure_latency.py \
    --profile {profile} \
    --duration {seconds}  \
    --named --alg {name of alg}
```
**Profile**: `mininet` - the mininet topolgy, `auth` - S1 switch only time, `verify` - S2 switch only time, `experiment` - this is for real hardware deploymnets 
Completion of this script displays average latency results in the terminal, and the .json.meta files will be stored in `switch_controls/data/t_spent_switch_results`.

## Running with BPFabric Softswitch
> **Note:** this assumes a fully working BPFabric pipeline is already setup on the device
> also assumes the incoming and outgoing ports are called `enp1s0` and `enp2s0`
> if port names alternate simply replace them in the following commands
> this also assumes this is ran on a programmable switch with connected incoming aand outgoing ports

### For the authentication/verification switches using softswitch

Start the softswtich:
```bash
cd <path-to-BPFabric>
sudo ip link add veth1 type veth peer name veth2
sudo ip link add veth3 type veth peer name veth4
 
sudo ip link set dev veth1 up
sudo ip link set dev veth2 up
sudo ip link set dev veth3 up
sudo ip link set dev veth4 up
 
sudo <path-to-BPFabric>/softswitch/softswitch --dpid=1 --controller="127.0.0.1:9000" --promiscuous veth1 veth3 enp1s0 enp2s0
```
Start the controller:
```bash
cd <path-to-BPFabric>/controller
python3 ./cli.py
```
>**Note:**this assumes that the `goose_forwarder.o` is in the `BPFabric/functions` folder
>if not this can be found in `goose authentication/switch_controls/extra` in the functions foler and compiled by running `make` in the `BPFabric/functions` directory
Inside the controller (cli) run:
```bash 
1 add 0 auth ../functions/goose_forwarder.o
```
This installs the forwarding program and applies the required packet processing rules. Now the GASF can be setup to listen on the appropiate veth ports, these is already defined in the switch program.  Assuming the steps for the Mininet setup were used (compiled etc, re-run `make` to be sure anyway), from the `switch_controls/build` directory, run:
```bash 
./switch1 {mode: 3 = auth switch, 4 = verify switch} {alg profile, see above for these}
```
This will run the program which will listen for incoming packets from the softswitch pipeline.

### Host side softswitch

The send/receive scripts run in the same way as the Mininet setup, although will require to be ran on its own device.
The receive script is not required for the full setup to work, but helps to know traffic is being received on the end port.

### Measurment scripts

This can be ran on host device, just as the Mininet experiment. Use the `experiment` profile when calling `measure_latency.py`, this is for the end-to-end latency. The incoming/outgoing port is set as `enp1s0/enp2s0`, this can be changed within the script if required, change the `start_iface` and `end_iface` in the `experiment` profile section.

## Running with DPDK Data Plane Implementation

> **Note:** This assumes that the BPFabric DPDK version is installed and functioning correctly.  
> It also assumes execution on a programmable switch with connected incoming and outgoing ports.
> It is also assumed that all programs are exited, to avoid issues between implementations, reseting the device is best advised.
### DPDK Setup for Authentication/Verification Pipeline

#### Enable Hugepages

```bash
sudo -i
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
exit
```
#### Bind network interfaces

Bind the appropiate ports (PCI addresses may vary, change depending on the physical ports used):
```bash 
sudo dpdk-devbind.py --status
sudo modprobe vfio-pci
sudo dpdk-devbind.py --bind=vfio-pci 0000:01:00.0
sudo dpdk-devbind.py --bind=vfio-pci 0000:02:00.0
```
**Note**: PCI addrresses are the addresses of the format 0000:01:00.0, calling `sudo dpdk-devbind.py --status` will allow to see what ports PCI addresses are.
Start BPFabric (DPDK):
```bash
cd <path-to-BPFabric>/dpdkswitch/build
sudo ./bpfabric -l 0-3 -n 4 --vdev=net_tap0 -- -q 1 -p 7 -d 1 -c 127.0.0.1:9000
```
#### Setup the GASF

For the DPDK version, there are 5 commented lines in `switch_controls/src/pcap_open.h` (lines 23-27), these are required to be uncommented for TAP to work, and then the `switch_controls` project needs `make` ran again.

Similar to the softswitch version, run the BPFabric cli and add the new forwaring command in the cli:
```bash
1 add 0 auth ../functions/goose_forwarder_dpdk.o
```
>**Note:* any issues with this, ensure `goose_forwarder_dpdk.o` exits, else follow the steps from the Softswitch and place inside the `BPFabric/functions` folder and call `make` inside this folder. The required file to compile is in the `extras` directory, named `goose_forwarder_dpdk.c`
Now setup the GASF as normal, from the same directory as before (`switch_controls/build`), run:
 ```bash
 ./switch1 {5 = auth for DPDK, 6 = verify for DPDK} {algorithm choice}
 ```
 **this program will listen on for the TAP port called `vtap0`, if the TAP port on the device is called something else, search `vtap0` in `switch.c` and change all occurences to the actual TAP name**


## Running the experiments under load 

>**Note:**This assumes a full working hardware setup as seen in the paper (H1-S1-S2-H1) with a external connection S2-E1 (external load device)
> If switching between implementations (softswitch or DPDK), its advised to restart device for simplicity

### External load device

This requires setting up a subnet so that the host device dosent short route traffic
Run from the command line (on the external load device):
**assuming the connecected port is `enp1s0`**
```bash
sudo nmcli device set enp1s0 managed no
sudo ip link set enp1s0 up
sudo ip addr add 10.10.10.2/24 dev enp1s0
ip -br addr
iperf3 -s -B 10.10.10.2
```
This will start a iperf server listening for traffic

### Setting up the switche

This is the same as the previous experiments, however some slight changes as follows:

>***NOTE!!!* these changes are only required on the **Verification switch**, this is as it has an additional port connection to the external load device, the authentication switch remains unchanged

#### Softswitch (verification switch)

The `goose_forwarder.c` file requires changes: comment out lines 5-9, and uncomment lines 12-16, and then recompile. Setup is the same, except from the final BAFabric setup command which becomes:
```bash 
sudo ~/BPFabric/softswitch/softswitch --dpid=1 --controller="127.0.0.1:9000" --promiscuous veth1 veth3 enp1s0 enp2s0 enp3s0
```
**assuming enp1s0 - incoming port, enp2s0 - outgoing port (to host), and enp3s0 - outgoing port to E1**
GASF setup and the veth setup commands are the same.

#### DPDK

Similarly this required the `goose_forwarder_dpdk.c` file to comment lines 5-8 and uncomment lines 11-14, and then recompile. Setup is the same, however again the additional port used will require to be bound:
```bash
sudo dpdk-devbind.py --bind=vfio-pci 0000:03:00:0
```
Or whatever address the port uses, and the final BPFabric command changes to:
```bash
sudo ./bpfabric -l 0-3 -n 4 --vdev=net_tap0 -- -q 1 -p 15 -d 1 -c 127.0.0.1:9000
```
The differnce is: the port mask (-p) must include all active interfaces. For N ports, use (2^N - 1). For example:
- 2 physical + 1 TAP → -p 7  
- 3 physical + 1 TAP → -p 15

The GASF setup is the same as the before DPDK. 

Any issues with this may be due to the port ordering from the setup, this can be derived from info from the BPFabric CLI and chaning TAP_PORT, IN_PHYS_PORT, OUT_PHYS_PORT and LOAD_PHYS_PORT based on this in `goose_forwarder_dpdk.c`

### Host setup

The host requires the two send/receive ports to operate on different subnets in order to run iperf, and so run:

```bash
sudo nmcli device set enp1s0 managed no
sudo nmcli device set enp2s0 managed no
sudo ip addr flush dev enp1s0
sudo ip addr flush dev enp2s0

sudo ip addr add 10.10.10.1/24 dev enp1s0
sudo ip addr add 10.10.20.1/24 dev enp2s0

sudo ip link set enp1s0 up
sudo ip link set enp2s0 up
```
Once this is setup, now send the traffic with:
```bash
sudo iperf3 -u -c 10.10.10.2 -B 10.10.10.1 -b 20M -l 185 -t 30
```
This will send traffic to the iperf server running on the external load device, this can be adjusted to vary load but will not be explored here.
