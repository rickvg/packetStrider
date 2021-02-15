# Packet Strider (v0.21) - Rust version

## Summary
packetStrider was ported to rust in order to gain performance when processing larger PCAP-files. This project can be built using cargo. 

## Differences with Python
This version does not support plots and Agent Forwarding detection as of now. It does include the following features:
- Forward SSH session detection, with login prompts and login success / failed
- Reverse SSH session detection, with login prompts and login success / failed
- Host key accepts
- Usage of the session R option
- Forward and reverse keystrokes
- Metadata of SSH-session: Server hassh, client hassh, SIP, DIP, SPORT, DPORT. This does not always work properly yet.

It does not support:
- Agent forwarding
- Plots
- Filtering the SSH-session. This can, however, easily be done using faster libs than pyshark, such as PcapPlusPlus.

## Getting started
Build the project

`cargo build`

Usage:
`./packet_strider -h`

```
USAGE:
    packet_strider.exe [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -d, --dir <dir>      Input directory with PCAPs
    -f, --file <file>    Input PCAP file
```

It automatically does all the processing for you.

## Improvements
Improvements are always welcome.
