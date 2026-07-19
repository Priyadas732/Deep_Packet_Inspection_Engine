# High-Performance Deep Packet Inspection (DPI) Engine

A multi-threaded C++17 Deep Packet Inspection (DPI) engine designed for high-throughput packet processing, traffic classification, and flow-based filtering. It parses Layer 2–4 headers, extracts TLS Server Name Indication (SNI) and HTTP Host metadata, tracks network connections using consistent hashing, and applies customizable blocking rules, exporting filtered network traffic back to PCAP format.

---

## Key Features

- **Multi-Threaded Pipeline Architecture**: Uses a pipelining model (Reader → Load Balancers → Fast Path Workers → Output Writer) to parallelize packet parsing and DPI analysis.
- **Consistent Hashing**: Hashes packet five-tuples to assign packets belonging to the same connection to the same worker thread, ensuring thread-safe, stateful flow tracking without locking overhead.
- **Deep Packet Inspection**:
  - Parses Ethernet, IPv4, TCP, and UDP headers.
  - Extracts plaintext TLS Server Name Indication (SNI) from `Client Hello` handshake packets.
  - Extracts `Host` headers from plain HTTP traffic.
- **Stateful Flow-Based Blocking**:
  - Tracks connections using a 5-tuple hash map.
  - Flow-based block propagation: once a domain or IP block rule is triggered, all subsequent packets in that connection are automatically dropped.
  - Custom rules to block by Source IP, Application Type (e.g., YouTube, TikTok, Google), or Domain pattern (substring match).
- **PCAP Integration**: Native support for reading standard PCAP files and writing filtered traffic to an output PCAP.
- **Detailed Execution Reports**: Generates application-level traffic breakdowns, thread workload statistics, packet drop/forward counts, and lists detected SNIs upon completion.

---

## Architecture Overview

The system uses a highly optimized thread-pool pipeline with thread-safe queues (`TSQueue`) to distribute packet processing tasks.

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
               ┌──────────────┴──────────────┐
               │      hash(5-tuple) % N      │
               ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
       ┌──────┴──────┐               ┌──────┴──────┐
       │hash % M     │               │hash % M     │
       ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

1. **Reader Thread**: Parses the global PCAP header, reads raw packets sequentially, and distributes them to the Load Balancer queues based on the connection hash.
2. **Load Balancer (LB) Threads**: Decouple the reader from workers, routing packets to specific Fast Path threads using consistent hashing.
3. **Fast Path (FP) Threads**: Perform the core work:
   - Extract protocol headers (L2/L3/L4).
   - Trace flow state using a local connection map.
   - Extract SNI/Host payloads.
   - Match against active block-rules and update flow blocking state.
   - Enqueue permitted packets to the Output Queue.
4. **Output Writer Thread**: Sequentially writes allowed packets to the output PCAP file.

---

## File Structure

```
packet_analyzer/
├── include/                    # Header declarations
│   ├── connection_tracker.h   # Flow tracking and map definitions
│   ├── dpi_engine.h           # Main engine coordinator
│   ├── fast_path.h            # Fast Path worker thread declaration
│   ├── load_balancer.h        # Load balancer thread declaration
│   ├── packet_parser.h        # L2-L4 protocol parser
│   ├── pcap_reader.h          # PCAP file format helper
│   ├── rule_manager.h         # IP/App/Domain blocking rules
│   ├── sni_extractor.h        # TLS SNI and HTTP Host extractors
│   ├── thread_safe_queue.h    # Lock-based producer-consumer queue
│   └── types.h                # Core types (FiveTuple, AppType, etc.)
│
├── src/                        # Implementation files
│   ├── connection_tracker.cpp
│   ├── dpi_engine.cpp
│   ├── dpi_mt.cpp             # Multi-threaded engine runner
│   ├── fast_path.cpp
│   ├── load_balancer.cpp
│   ├── main.cpp               # CLI entrypoint (Simple packet printer)
│   ├── main_working.cpp       # Single-threaded alternative runner
│   ├── packet_parser.cpp
│   ├── pcap_reader.cpp
│   ├── rule_manager.cpp
│   ├── sni_extractor.cpp
│   └── types.cpp
│
├── generate_test_pcap.py      # Python utility to generate mock traffic
├── CMakeLists.txt             # Project build configuration
└── README.md                  # This file
```

---

## Getting Started

### Prerequisites

- A C++17 compatible compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.16+ (optional, or use direct build commands)
- Python 3 (for test data generation)

### Build Instructions

#### Using CMake

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

#### Direct Compilation (GCC / Clang)

If you prefer building without CMake:

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

For Windows setup (MSVC or MinGW), refer to the detailed [WINDOWS_SETUP.md](WINDOWS_SETUP.md) guide.

---

## Usage

### Run the Engine

Process a capture file and output the filtered result to a new file:

```bash
./dpi_engine input.pcap output.pcap
```

### Apply Filtering & Blocking Rules

You can block specific traffic by IP, domain, or application:

```bash
./dpi_engine input.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

### Thread Configuration

Adjust the number of load balancers and fast-path threads to tune performance:

```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 8
```

### Generate Test Data

If you need a sample PCAP to test features, run the generator script:

```bash
python generate_test_pcap.py
```
This generates `test_dpi.pcap` containing a mix of DNS queries, HTTP GET requests, TLS Client Hellos (YouTube, Google, Facebook), and raw TCP traffic.

---

## Statistics & Verification

Upon completion, the engine prints a comprehensive report summarizing thread performance and traffic classification metrics:

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                  5738                            ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                  4                               ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                      8                               ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:              0                               ║
║   FP2 processed:              0                               ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
```

---

## Future Enhancements

- **Dynamic Policy Reloading**: Read blocking rules from a configurations file (e.g. JSON/YAML) with hot-reload capabilities via SIGHUP signals.
- **Throttling/Rate Limiting**: Integrate bucket token/leaky bucket rate limiting algorithms for matched flows instead of outright dropping packets.
- **QUIC / HTTP3 Handshake Parsing**: Add decryption-less SNI extraction support for UDP-based HTTP3 connections.
- **Prometheus Metric Endpoint**: Serve real-time connection telemetry to Prometheus/Grafana dashboards.
