
# pytorrent

Pytorrent is a command line tool written in Python that downloads files from the **BitTorrent** network.

The purpose of this program is to learn how the BitTorrent protocol works.

## Supported BEPs

The following **BitTorrent Enhancement Proposals** (BEPs) are supported:

- [**BEP 3** - The BitTorrent Protocol Specification](https://www.bittorrent.org/beps/bep_0003.html)  
  Core specification of the BitTorrent protocol.
  
- [**BEP 5** - DHT Protocol](https://www.bittorrent.org/beps/bep_0005.html)  
  Used to achieve trackerless operation by implementing a decentralized method of peer discovery.

- [**BEP 10** - Extension Protocol](http://bittorrent.org/beps/bep_0010.html)  
  Adds support for extensions to the BitTorrent protocol.
  
- [**BEP 11** - Peer Exchange (PEX)](https://www.bittorrent.org/beps/bep_0011.html)  
  Enables clients to share peers among themselves to improve availability.
  
- [**BEP 15** - UDP Tracker Protocol](https://www.bittorrent.org/beps/bep_0015.html)  
  Describes the UDP-based tracker protocol for improved efficiency in peer discovery.

## Getting Started

### Prerequisites

- Python 3.x
- Pip (Python package manager)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/DavideLusuardi/pytorrent
   ```
   
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Usage

```bash
python torrent.py <torrent-file>
```

Replace `<torrent-file>` with the path to your `.torrent` file.

## Useful Resources

If you're looking to dive deeper into how a BitTorrent client is built, these resources will help:

- [How to Write a BitTorrent Client - Part 1](http://www.kristenwidman.com/blog/33/how-to-write-a-bittorrent-client-part-1/)
- [How to Write a BitTorrent Client - Part 2](http://www.kristenwidman.com/blog/71/how-to-write-a-bittorrent-client-part-2/)
- [BitTorrent Specification - Tracker HTTP/HTTPS Protocol](https://wiki.theory.org/BitTorrentSpecification)
