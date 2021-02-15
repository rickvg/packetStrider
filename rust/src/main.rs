// https://github.com/shramos/pcap-splitter

use clap::{Arg, App};
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use etherparse::*;
use std::cmp;
use ssh_parser::*;

struct MetaHassh {
    proto_cl: String,
    hassh: String,
    proto_sv: String,
    hassh_server: String,
    sip: [u8; 4],
    sport: u16,
    dip: [u8; 4],
    dport: u16
}

struct Event {
    direct: String,
    event: String,
    at_pkt: i32,
    nxt_pkt: i32,
    bytes: i32,
    unk: i32
}

// Function for parsing the input PCAP-file
fn parse_pcap(filename: &str) {
    let file = File::open(filename).unwrap();
    let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    let mut num_blocks = 0;
    
    // initialize global variables for ssh
    let mut found_ssh_newkeys = false;
    let mut newkeys_counter = 0;
    let mut meta_size = [0, 0, 0, 0, 0];
    let mut size_matrix = Vec::new();
    let mut meta_hssh = MetaHassh{
        proto_cl: "".to_string(),
        hassh: "".to_string(),
        proto_sv: "".to_string(),
        hassh_server: "".to_string(),
        sip: [0,0,0,0],
        sport: 0,
        dip: [0,0,0,0],
        dport: 0
    };
    let mut pkt_counter = 0;
    let mut newkey_offsets = Vec::new();

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(_hdr) => {
                        // Print link type
                        //println!("Network header {}", _hdr.network);
                    },
                    PcapBlockOwned::Legacy(_b) => {           
                        let mut src_ip: [u8; 4] = [0, 0, 0, 0];
                        let mut dst_ip: [u8; 4] = [0, 0, 0, 0];
                        let mut src_port = 0;
                        let mut dest_port = 0;
                        //let mut seq_no = 0;

                        // Start parsing from the ethernet slice _b.data is packet data.
                        match PacketHeaders::from_ethernet_slice(&_b.data) {
                            Err(value) => println!("Err {:?}", value),
                            Ok(value) => {
                                // Get specific elements from IP header
                                match value.ip {
                                    Some(ipheader) => {
                                        match ipheader {
                                            IpHeader::Version4(_ip_hd) => {
                                                src_ip = _ip_hd.source;
                                                dst_ip = _ip_hd.destination;
                                            },
                                            IpHeader::Version6(_ip6_hd) => println!("IPv6 not implemented"),
                                        }
                                    },
                                    None => println!("No IP value"),
                                }

                                //println!("transport: {:?}", value.transport);
                                // Get specific elements from Transport header
                                match value.transport {
                                    Some(tcpheader) => {
                                        match tcpheader {
                                            TransportHeader::Tcp(_tcp_hd) => {
                                                src_port = _tcp_hd.source_port;
                                                dest_port = _tcp_hd.destination_port;
                                                //seq_no = _tcp_hd.sequence_number;
                                            },
                                            TransportHeader::Udp(_udp_hd) => println!("Found UDP Header"),
                                        }
                                    }
                                    None => println!("No value"),
                                }

                                //println!("Source IP: {:?}", src_ip);
                                //println!("Destination IP: {:?}", dst_ip);
                                //println!("Source port: {}", src_port);
                                //println!("Destination port: {}", dest_port);
                                //println!("Sequence number: {}", seq_no);
                                //println!("payload: {:?}", value.payload);

                                // go parse this payload as ssh now
                                if value.payload != [] {
                                    let tcp_len = value.payload.len() as i32;
                                    if dest_port > src_port {
                                        size_matrix.push(-tcp_len);
                                    } else {
                                        size_matrix.push(tcp_len);
                                    }
                                    // FIND META SIZES SECTION
                                    // Similar to the find meta sizes.
                                    if found_ssh_newkeys {
                                        // get length of TCP payload...
                                        let mut newkeys_next = value.payload.len() as i32;
                                        if dest_port > src_port {
                                            newkeys_next = -newkeys_next;
                                        }
                                        
                                        // handling the reverse_keystroke_size
                                        if newkeys_counter == 0 {
                                            let reverse_keystroke_size = -(newkeys_next - 8 + 40);
                                            meta_size[newkeys_counter] = reverse_keystroke_size;
                                            newkeys_counter += 1;
                                        }

                                        meta_size[newkeys_counter] = newkeys_next;
                                        newkeys_counter += 1;

                                        // Set counter for newkeys back to 0
                                        if newkeys_counter > 4 {
                                            newkeys_counter = 0;
                                            found_ssh_newkeys = false;
                                        }
                                    }
                                    // END FIND META SIZES SECTION


                                    // Parse the SSH-packet.
                                    let parsed_id = ssh_parser::parse_ssh_identification(value.payload);
                                    let parsed_ssh = ssh_parser::parse_ssh_packet(value.payload);
                                
                                    match parsed_ssh {
                                        Ok(ssh_parsed) => {
                                            match ssh_parsed.1.0 {
                                                SshPacket::KeyExchange(kex) => {
                                                    // START SECTION TO FIND HASSH
                                                    if src_port > dest_port {
                                                        let hassh_algos = format!("{};{};{};{}", String::from_utf8_lossy(kex.kex_algs), String::from_utf8_lossy(kex.encr_algs_client_to_server), String::from_utf8_lossy(kex.mac_algs_client_to_server), String::from_utf8_lossy(kex.comp_algs_client_to_server));
                                                        let digest = md5::compute(hassh_algos);
                                                        let client_hassh = format!("{:x}", digest);
                                                        meta_hssh.hassh = client_hassh;
                                                        meta_hssh.sip = src_ip;
                                                        meta_hssh.sport = src_port;
                                                        meta_hssh.dip = dst_ip;
                                                        meta_hssh.dport = dest_port;
                                                    } else if dest_port > src_port {
                                                        if meta_hssh.sip == [0,0,0,0] {
                                                            meta_hssh.dip = src_ip;
                                                            meta_hssh.dport = src_port;
                                                            meta_hssh.sip = dst_ip;
                                                            meta_hssh.sport = dest_port;
                                                        }
                                                        let hassh_server_algos = format!("{};{};{};{}", String::from_utf8_lossy(kex.kex_algs), String::from_utf8_lossy(kex.encr_algs_server_to_client), String::from_utf8_lossy(kex.mac_algs_server_to_client), String::from_utf8_lossy(kex.comp_algs_server_to_client));
                                                        let digest = md5::compute(hassh_server_algos);   
                                                        let server_hassh = format!("{:x}", digest);   
                                                        meta_hssh.hassh_server = server_hassh;
                                                    }
                                                    // END SECTION TO FIND HASSH
                                                },
                                                SshPacket::NewKeys => {
                                                    found_ssh_newkeys = true;
                                                    // push packet no to newkey_offsets, used later.
                                                    newkey_offsets.push(pkt_counter);
                                                },
                                                _ => ()
                                            }
                                        }
                                        , _ => ()
                                    }
                                    
                                    // Parse the client header
                                    match parsed_id {
                                        Ok(ssh_id) => {
                                            match ssh_id.1.1 {
                                                vers => {
                                                    let protocol = format!("SSH-{}-{}", String::from_utf8_lossy(vers.proto), String::from_utf8_lossy(vers.software));
                                                    if src_port > dest_port {
                                                        meta_hssh.proto_cl = protocol;
                                                    } else {
                                                        meta_hssh.proto_sv = protocol;
                                                    }
                                                }
                                            }
                                        }, _ => ()
                                    }

                                    // Check whether all is completed and matrix can be built.
                                    pkt_counter += 1;

                                }
                            }
                        }
                    }, _ => ()
                }  
                reader.consume(offset)          
            }, 
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete) => {
                reader.refill().unwrap();
            },
            Err(e) => panic!("Error while reading: {:}" , e),
        }
        
    }
    // Time to perform analytics
    //println!("Perform analytics");
    //println!("Meta-size: {:?}", meta_size);
    //println!("meta-hassh: .. is struct");
    //println!("matrix: {:?}", size_matrix);

    // First we initiate the order_keystrokes function
    let forward_keystroke_size = meta_size[1] - 8;
    let mut ordered_matrix = Vec::new();
    let keystone = 0;
    let mut looking_for_match = true;
    let mut temp_matrix = size_matrix;

    //https://stackoverflow.com/questions/26243025/remove-an-element-from-a-vector
    while temp_matrix.len() > 1 {
        if temp_matrix[keystone] != forward_keystroke_size {
            ordered_matrix.push(temp_matrix[keystone]);
            temp_matrix.remove(temp_matrix.iter().position(|x| *x == temp_matrix[keystone]).expect("needle not found"));
            looking_for_match = false;
        } else {
            // start of keystroke block.
            ordered_matrix.push(temp_matrix[keystone]);
            temp_matrix.remove(temp_matrix.iter().position(|x| *x == temp_matrix[keystone]).expect("needle not found"));
            looking_for_match = true;

            if !looking_for_match {
                ordered_matrix.push(temp_matrix[keystone]);
            } else {
                let mut mark = keystone;
                let mut count = 0;
                while looking_for_match && mark < temp_matrix.len() {
                    let size_mark = temp_matrix[mark];
                    if count == 10 {
                        ordered_matrix.push(temp_matrix[mark]);
                        temp_matrix.remove(temp_matrix.iter().position(|x| *x == temp_matrix[mark]).expect("needle not found"));
                        looking_for_match = false;
                        break;
                    }
                    if size_mark == -forward_keystroke_size {
                        ordered_matrix.push(temp_matrix[mark]);
                        temp_matrix.remove(temp_matrix.iter().position(|x| *x == temp_matrix[mark]).expect("needle not found"));
                        looking_for_match = false;
                    } else if size_mark <= -(forward_keystroke_size + 8) {
                        ordered_matrix.push(temp_matrix[mark]);
                        temp_matrix.remove(temp_matrix.iter().position(|x| *x == temp_matrix[mark]).expect("needle not found"));
                        looking_for_match = false;
                    } else {
                        mark += 1;
                    }
                    count += 1;
                }
            }

        }
    }
    ordered_matrix.extend(temp_matrix);
    // End of the order_keystrokes function
    
    // Initiate scan for forward login attempts
    // Args: matrix, meta_size returns fwd logged in.
    let mut fwd_logged_in_at_packet = 0;
    let mut all_results = Vec::new();
    let size_login_prompt = meta_size[4];

    // todo: timestamp
    for i in 8..cmp::min(ordered_matrix.len()-2, 300) {
        // Check for login prompt
        if ordered_matrix[i] == size_login_prompt {
            let logindat = Event{
                direct: "forward".to_string(),
                event: "login prompt".to_string(),
                at_pkt: i as i32,
                nxt_pkt: i as i32,
                bytes: ordered_matrix[i].abs(),
                unk: 1
            };
            all_results.push(logindat)
        }

        // Check for login failure or success
        if ordered_matrix[i] == size_login_prompt && ordered_matrix[i + 1] > 0 && ordered_matrix[i + 2] == size_login_prompt {
            let logindat = Event{
                direct: "forward".to_string(),
                event: "login failure".to_string(),
                at_pkt: i as i32,
                nxt_pkt: i as i32 + 1,
                bytes: ordered_matrix[i + 1].abs(),
                unk: 2
            };
            all_results.push(logindat)
        }
        
        if ordered_matrix[i] == size_login_prompt && ordered_matrix[i + 1] > 0 && ordered_matrix[i + 2] < 0 && ordered_matrix[i + 2] != size_login_prompt{
            let logindat = Event{
                direct: "forward".to_string(),
                event: "login success".to_string(),
                at_pkt: i as i32,
                nxt_pkt: i as i32 + 1,
                bytes: ordered_matrix[i + 1].abs(),
                unk: 2
            };
            all_results.push(logindat);
            fwd_logged_in_at_packet = i;
            break
        }
    }
    // End of scan for forward login attempts

    let mut res_hostkey_found = false;

    for i in newkey_offsets {
        // Initiate scan for host key accepts
        if !res_hostkey_found {
            let keydat = Event{
                direct: "forward".to_string(),
                event: "key offered".to_string(),
                at_pkt: i as i32 - 1,
                nxt_pkt: i as i32 - 1,
                bytes: ordered_matrix[i - 1].abs(),
                unk: 1
            };
            all_results.push(keydat);

            let keydat = Event{
                direct: "forward".to_string(),
                event: "key accepted".to_string(),
                at_pkt: i as i32,
                nxt_pkt: i as i32,
                bytes: ordered_matrix[i].abs(),
                unk: 1
            };
            all_results.push(keydat);
            res_hostkey_found = true;
        }
        // End scan for host key accepts

        // Scan for forward keystrokes
        let forward_keystroke_size = meta_size[1] - 8;
        let mut packets_infiltrated = 0;
        let mut bytes_infiltrated = 0;
        let mut keystrokes = 0;
        let mut temp = fwd_logged_in_at_packet;

        while temp < ordered_matrix.len()-2 {
            let size_this = ordered_matrix[temp];
            let size_next = ordered_matrix[temp + 1];
            let size_next_next = ordered_matrix[temp + 2];
            if size_this == forward_keystroke_size {
                if size_next == -forward_keystroke_size && size_next_next == forward_keystroke_size {
                    keystrokes += 1;
                    let keydat = Event{
                        direct: "forward".to_string(),
                        event: "keystroke".to_string(),
                        at_pkt: temp as i32,
                        nxt_pkt: temp as i32 + 1,
                        bytes: size_this.abs(),
                        unk: 2
                    };
                    all_results.push(keydat);
                    temp += 2;
                } else if size_next == -(forward_keystroke_size + 8) && size_next_next == forward_keystroke_size {
                    keystrokes += 1;
                    let keydat = Event{
                        direct: "forward".to_string(),
                        event: "< delete/ac".to_string(),
                        at_pkt: temp as i32,
                        nxt_pkt: temp as i32 + 1,
                        bytes: size_this.abs(),
                        unk: 2
                    };
                    all_results.push(keydat);
                    temp += 2;
                } else if size_next < -(forward_keystroke_size + 8) && size_next_next == forward_keystroke_size {
                    keystrokes += 1;
                    let keydat = Event{
                        direct: "forward".to_string(),
                        event: "tab complete".to_string(),
                        at_pkt: temp as i32,
                        nxt_pkt: temp as i32 + 1,
                        bytes: size_this.abs(),
                        unk: 2
                    };
                    all_results.push(keydat);
                    temp += 2;
                } else if size_next <= -forward_keystroke_size && size_next_next <= -forward_keystroke_size && keystrokes > 0 {
                    let temp_enterkey_pressed = temp;
                    let mut finish = temp + 2;
                    while finish < ordered_matrix.len() {
                        if ordered_matrix[finish] > 0 {
                            temp = finish;
                            break;
                        }
                        packets_infiltrated += 1;
                        bytes_infiltrated += ordered_matrix[finish].abs();
                        finish += 1;
                        temp += 1;
                    }
                    let keydat = Event{
                        direct: "forward".to_string(),
                        event: "_\u{2503} ENTER      ".to_string(),
                        at_pkt: temp_enterkey_pressed as i32,
                        nxt_pkt: temp as i32,
                        bytes: bytes_infiltrated,
                        unk: packets_infiltrated
                    };
                    all_results.push(keydat);
                    packets_infiltrated = 0;
                    bytes_infiltrated = 0;
                    keystrokes = 0;
                } else {
                    temp += 1;
                }
            } else {
                temp += 1;
            }
        }
        // End scan for forward keystrokes

        // initiate variables for scan for reverse_session_R_option
        let stop_at = cmp::min(ordered_matrix.len() - 10, 100);
        // start scan for reverse_session_R_option
        let mut offset = 4;
        while (i + offset + 7) < stop_at && offset < 20 {
            if ordered_matrix[i + offset] == size_login_prompt{
                if ordered_matrix[i + offset + 2] != size_login_prompt{
                    if ordered_matrix[i + offset + 3] > 0 && ordered_matrix[i + offset + 4] < 0 && ordered_matrix[i + offset + 4] != size_login_prompt && ordered_matrix[i + offset + 5] > 0 && ordered_matrix[i + offset + 6] < 0 && ordered_matrix[i + offset + 6] != size_login_prompt && ordered_matrix[i + offset + 6].abs() < ordered_matrix[i + offset + 5].abs() {
                        let rdat = Event{
                            direct: "reverse".to_string(),
                            event: "-R used on init".to_string(),
                            at_pkt: (i + offset + 7) as i32,
                            nxt_pkt: (i + offset + 7) as i32,
                            bytes: ordered_matrix[i + offset + 7].abs(),
                            unk: 3
                        };
                        all_results.push(rdat);
                        break;
                    } else if ordered_matrix[i + offset + 3] > 0 && ordered_matrix[i + offset + 4] > 0 && ordered_matrix[i + offset + 5] != size_login_prompt && ordered_matrix[i + offset + 5] < 0 && ordered_matrix[i + offset + 6] < 0 && ordered_matrix[i + offset + 6] != size_login_prompt && ordered_matrix[i + offset + 6].abs() < ordered_matrix[i + offset + 5].abs() && ordered_matrix[i + offset + 7] > 0 {
                        let rdat = Event{
                            direct: "reverse".to_string(),
                            event: "-R used on init".to_string(),
                            at_pkt: (i + offset + 7) as i32,
                            nxt_pkt: (i + offset + 7) as i32,
                            bytes: ordered_matrix[i + offset + 7].abs(),
                            unk: 3
                        };
                        all_results.push(rdat);
                        break;
                    }
                }
            }
            offset += 1;
        }
        // end scan reverse_session_R_option
    }

    // Scan for reverse session initiation
    let size_newkeys_next = meta_size[1];
    let size_newkeys_next2 = meta_size[2];

    for i in 0..ordered_matrix.len()-3 {
        if ordered_matrix[i + 1] == -(size_newkeys_next + 40) && ordered_matrix[i + 2] == -(size_newkeys_next2 -40) && ordered_matrix[i + 3] < 0 && ordered_matrix[i + 3].abs() >= (ordered_matrix[i + 2]) {
            let rdat = Event{
                direct: "reverse".to_string(),
                event: "session init".to_string(),
                at_pkt: i as i32,
                nxt_pkt: i as i32 + 3,
                bytes: ordered_matrix[i + 1].abs(),
                unk: 3
            };
            all_results.push(rdat);

            // Immediately scan for reverse_session_prompts
            let size_reverse_login_prompt = -meta_size[4] + 40 + 8;
            for j in i..cmp::min(ordered_matrix.len()-4, 300) {
                if ordered_matrix[j] == size_reverse_login_prompt && ordered_matrix[j + 1] < -size_reverse_login_prompt && ordered_matrix[j + 2] > size_reverse_login_prompt && ordered_matrix[j + 3] < -size_reverse_login_prompt && ordered_matrix[j + 4] == size_reverse_login_prompt {
                    let logindat = Event{
                        direct: "reverse".to_string(),
                        event: "login prompt".to_string(),
                        at_pkt: j as i32,
                        nxt_pkt: j as i32 + 4,
                        bytes: ordered_matrix[j].abs(),
                        unk: 4
                    };
                    all_results.push(logindat);

                    let logindat = Event{
                        direct: "reverse".to_string(),
                        event: "login failure".to_string(),
                        at_pkt: j as i32,
                        nxt_pkt: j as i32 + 4,
                        bytes: ordered_matrix[j + 1].abs(),
                        unk: 4
                    };
                    println!("{}, {}, {}, {}", logindat.direct, logindat.event, logindat.nxt_pkt, logindat.bytes);
                    all_results.push(logindat);
                }
                if ordered_matrix[j] == size_reverse_login_prompt && ordered_matrix[j + 1] < -size_reverse_login_prompt && ordered_matrix[j + 2] > 0 && ordered_matrix[j + 2] < size_reverse_login_prompt && ordered_matrix[j + 3] < -size_reverse_login_prompt &&  ordered_matrix[j + 4] > 0 && ordered_matrix[j + 4] < size_reverse_login_prompt {
                    let logindat = Event{
                        direct: "reverse".to_string(),
                        event: "login prompt".to_string(),
                        at_pkt: j as i32,
                        nxt_pkt: j as i32 + 4,
                        bytes: ordered_matrix[j].abs(),
                        unk: 4
                    };
                    all_results.push(logindat);

                    let logindat = Event{
                        direct: "reverse".to_string(),
                        event: "login success".to_string(),
                        at_pkt: j as i32,
                        nxt_pkt: j as i32 + 4,
                        bytes: ordered_matrix[j + 1].abs(),
                        unk: 4
                    };
                    all_results.push(logindat);
                    break;
                }
            }
            // End scan for reverse_session prompts

            // Start scan for reverse keystrokes
            let rev_keystroke_size = meta_size[0];
            let mut packets_exfiltrated = 0;
            let mut bytes_exfiltrated = 0;
            let mut keystrokes = 0;
            let mut temp = i - 1;

            while temp < ordered_matrix.len()-2 {
                let size_this = ordered_matrix[temp];
                let size_next = ordered_matrix[temp + 1];
                let size_next_next = ordered_matrix[temp + 2];

                if size_this == rev_keystroke_size {
                    if size_next == -rev_keystroke_size && size_next_next == rev_keystroke_size {
                        keystrokes += 1;
                        let keydat = Event{
                            direct: "reverse".to_string(),
                            event: "keystroke".to_string(),
                            at_pkt: temp as i32,
                            nxt_pkt: temp as i32 + 1,
                            bytes: size_this.abs(),
                            unk: 2
                        };
                        all_results.push(keydat);
                        temp += 2;
                    } else if size_next == -(rev_keystroke_size - 8) && size_next_next == rev_keystroke_size {
                        keystrokes += 1;
                        let keydat = Event{
                            direct: "reverse".to_string(),
                            event: "< delete".to_string(),
                            at_pkt: temp as i32,
                            nxt_pkt: temp as i32 + 1,
                            bytes: size_this.abs(),
                            unk: 2
                        };
                        all_results.push(keydat);
                        temp += 2;
                    } else if size_next == -rev_keystroke_size && size_next_next > -(rev_keystroke_size - 8) && keystrokes > 0 {
                        let temp_enterkey_pressed = temp;
                        let mut finish = temp + 2;
                        while finish < ordered_matrix.len() {
                            if ordered_matrix[finish] > 0 {
                                temp = finish;
                                break;
                            }
                            packets_exfiltrated += 1;
                            bytes_exfiltrated += ordered_matrix[finish].abs();
                            finish += 1;
                            temp += 1;
                        }
                        let keydat = Event{
                            direct: "reverse".to_string(),
                            event: "_\u{2503} ENTER      ".to_string(),
                            at_pkt: temp_enterkey_pressed as i32,
                            nxt_pkt: temp as i32 + 1,
                            bytes: bytes_exfiltrated,
                            unk: packets_exfiltrated
                        };
                        all_results.push(keydat);
                        packets_exfiltrated = 0;
                        bytes_exfiltrated = 0;
                        keystrokes = 0;
                    } else {
                        temp += 1;
                    }
                } else {
                    temp += 1;
                }
            }

            break;
        }
    }
    // End scan for reverse session initiation

    // Pretty print all results

    let source_ip: Vec<String> = meta_hssh.sip.to_vec().iter().map(|n| n.to_string()).collect();
    let source_ip = source_ip.join(".");
    let dest_ip: Vec<String> = meta_hssh.dip.to_vec().iter().map(|n| n.to_string()).collect();
    let dest_ip = dest_ip.join(".");
    println!("Client ID: {}\nClient hassh: {}\nClient IP: {}\nServer ID: {}\nServer hassh: {}\nServer IP: {}\nServer port: {}\n", meta_hssh.proto_cl, meta_hssh.hassh, source_ip, meta_hssh.proto_sv, meta_hssh.hassh_server, dest_ip, meta_hssh.dport);
    all_results.sort_by_key(|event| event.nxt_pkt);
    println!("Event\t\tDirection\tPacket no.\tBytes");
    for i in 0..all_results.len() {
        println!("{}\t{}\t\t{}\t\t{}", all_results[i].event, all_results[i].direct, all_results[i].nxt_pkt, all_results[i].bytes);
    }
    // End pretty print all results
    
    println!("num_blocks: {}\n", num_blocks);
}

fn main() {
    let matches = App::new("PacketStrider Rust Port")
        .version("0.0.2")
        .author("R")
        .about("Based on PacketStrider python: https://github.com/benjeems/packetStrider/")
        .setting(clap::AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("file")
            .short("f")
            .long("file")
            .takes_value(true)
            .help("Input PCAP file"))
        .arg(Arg::with_name("dir")
            .short("d")
            .long("dir")
            .takes_value(true)
            .help("Input directory with PCAPs"))
        .get_matches();
    
    if !matches.value_of("dir").is_none() {
        for file in std::fs::read_dir(matches.value_of("dir").unwrap()).unwrap() {
            let pcapfile = &file.unwrap().path().display().to_string();
            println!("Processing file: {}", pcapfile);
            parse_pcap(pcapfile);
        }
    } else if !matches.value_of("file").is_none() {
        let pcapfile = matches.value_of("file").unwrap();
        parse_pcap(pcapfile);
    }

    // Start parsing PCAP
}
