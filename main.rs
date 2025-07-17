use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::time::{SystemTime};
use std::io::{self, Write};

use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{Packet, ip::IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use serde::Serialize;
use chrono::{DateTime, Local};
use lazy_static::lazy_static;

// --- Feature Struct (ALL 84+ fields) ---
#[derive(Debug, Serialize, Default)]
struct FlowFeatures {
    // Basic 5-tuple
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    timestamp: String,

    // Flow stats
    flow_duration: f64,
    flow_byts_s: f64,
    flow_pkts_s: f64,
    fwd_pkts_s: f64,
    bwd_pkts_s: f64,
    tot_fwd_pkts: u32,
    tot_bwd_pkts: u32,
    totlen_fwd_pkts: u32,
    totlen_bwd_pkts: u32,
    fwd_pkt_len_max: u32,
    fwd_pkt_len_min: u32,
    fwd_pkt_len_mean: f64,
    fwd_pkt_len_std: f64,
    bwd_pkt_len_max: u32,
    bwd_pkt_len_min: u32,
    bwd_pkt_len_mean: f64,
    bwd_pkt_len_std: f64,
    pkt_len_max: u32,
    pkt_len_min: u32,
    pkt_len_mean: f64,
    pkt_len_std: f64,
    pkt_len_var: f64,
    fwd_header_len: u32,
    bwd_header_len: u32,
    fwd_seg_size_min: u32,
    fwd_act_data_pkts: u32,
    flow_iat_mean: f64,
    flow_iat_max: f64,
    flow_iat_min: f64,
    flow_iat_std: f64,
    fwd_iat_tot: f64,
    fwd_iat_max: f64,
    fwd_iat_min: f64,
    fwd_iat_mean: f64,
    fwd_iat_std: f64,
    bwd_iat_tot: f64,
    bwd_iat_max: f64,
    bwd_iat_min: f64,
    bwd_iat_mean: f64,
    bwd_iat_std: f64,
    fwd_psh_flags: u8,
    bwd_psh_flags: u8,
    fwd_urg_flags: u8,
    bwd_urg_flags: u8,
    fin_flag_cnt: u8,
    syn_flag_cnt: u8,
    rst_flag_cnt: u8,
    psh_flag_cnt: u8,
    ack_flag_cnt: u8,
    urg_flag_cnt: u8,
    ece_flag_cnt: u8,
    down_up_ratio: f64,
    pkt_size_avg: f64,
    init_fwd_win_byts: u16,
    init_bwd_win_byts: u16,
    active_max: f64,
    active_min: f64,
    active_mean: f64,
    active_std: f64,
    idle_max: f64,
    idle_min: f64,
    idle_mean: f64,
    idle_std: f64,
    fwd_byts_b_avg: f64,
    fwd_pkts_b_avg: f64,
    bwd_byts_b_avg: f64,
    bwd_pkts_b_avg: f64,
    fwd_blk_rate_avg: f64,
    bwd_blk_rate_avg: f64,
    fwd_seg_size_avg: f64,
    bwd_seg_size_avg: f64,
    cwr_flag_count: u8,
    subflow_fwd_pkts: u32,
    subflow_bwd_pkts: u32,
    subflow_fwd_byts: u32,
    subflow_bwd_byts: u32,
    label: String,
}

// --- Global Flow Table ---
lazy_static! {
    static ref FLOW_TABLE: Mutex<HashMap<(IpAddr, IpAddr, u16, u16, String), FlowTracker>> = 
        Mutex::new(HashMap::new());
}

// --- Flow Tracker ---
struct FlowTracker {
    start_time: SystemTime,
    fwd_packets: VecDeque<PacketData>,
    bwd_packets: VecDeque<PacketData>,
    last_fwd_time: Option<SystemTime>,
    last_bwd_time: Option<SystemTime>,
    init_fwd_win: Option<u16>,
    init_bwd_win: Option<u16>,
}

#[derive(Clone)]
struct PacketData {
    timestamp: SystemTime,
    size: usize,
    tcp_flags: Option<u8>,
    header_len: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // List all available interfaces (showing all, even if down)
    let interfaces = datalink::interfaces();
    println!("Available Network Interfaces:");
    for (i, iface) in interfaces.iter().enumerate() {
        print!("[{}] {} - IPs: ", i, iface.name);
        
        let ips: Vec<String> = iface.ips.iter()
        .filter_map(|ip_network| {
            if let IpAddr::V4(ipv4) = ip_network.ip() {
                Some(ipv4.to_string())
            } else {
                None
            }
        })
        .collect();
    if ips.is_empty() {
        println!("No IPv4 assigned");
    } else {
        println!("{}", ips.join(", "));
    }
}


    // Ask user to select interface index
    print!("Enter interface index to capture on: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let index: usize = input.trim().parse().expect("Please enter a valid number");

    if index >= interfaces.len() {
        panic!("Invalid interface index");
    }
    let interface = &interfaces[index];

    println!("Selected interface: {}", interface.name);

    // Open channel for capturing packets
    let (_, mut rx) = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(_, rx)) => ((), rx),
        _ => panic!("Failed to open channel"),
    };

    println!("Capturing on {}...", interface.name);

    // Your packet capture loop and processing below
    let mut writer = csv::Writer::from_path("flow_features.csv")?;

    while let Ok(packet) = rx.next() {
        if let Some(ipv4) = Ipv4Packet::new(packet) {
            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                        process_packet(
                            ipv4.get_source(),
                            ipv4.get_destination(),
                            tcp.get_source(),
                            tcp.get_destination(),
                            "TCP",
                            tcp.get_flags(),
                            ipv4.payload().len(),
                            tcp.get_data_offset() as usize * 4,
                            tcp.get_window(),
                            &mut writer,
                        )?;
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                        process_packet(
                            ipv4.get_source(),
                            ipv4.get_destination(),
                            udp.get_source(),
                            udp.get_destination(),
                            "UDP",
                            0,
                            ipv4.payload().len(),
                            8,
                            0,
                            &mut writer,
                        )?;
                    }
                }
                _ => (),
            }
        }
    }

    Ok(())
}


fn process_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    protocol: &str,
    tcp_flags: u8,
    payload_len: usize,
    header_len: usize,
    window_size: u16,
    writer: &mut csv::Writer<std::fs::File>,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now();
    let key = (IpAddr::V4(src_ip), IpAddr::V4(dst_ip), src_port, dst_port, protocol.to_string());

    let mut flow_table = FLOW_TABLE.lock().unwrap();
    let flow = flow_table.entry(key.clone()).or_insert_with(|| FlowTracker {
        start_time: now,
        fwd_packets: VecDeque::new(),
        bwd_packets: VecDeque::new(),
        last_fwd_time: None,
        last_bwd_time: None,
        init_fwd_win: None,
        init_bwd_win: None,
    });

    // Direction: forward if src_port < dst_port (simple heuristic)
    let is_forward = src_port < dst_port;
    let (packets, last_time) = if is_forward {
        (&mut flow.fwd_packets, &mut flow.last_fwd_time)
    } else {
        (&mut flow.bwd_packets, &mut flow.last_bwd_time)
    };

    packets.push_back(PacketData {
        timestamp: now,
        size: payload_len,
        tcp_flags: if protocol == "TCP" { Some(tcp_flags) } else { None },
        header_len,
    });

    if is_forward && flow.init_fwd_win.is_none() {
        flow.init_fwd_win = Some(window_size);
    } else if !is_forward && flow.init_bwd_win.is_none() {
        flow.init_bwd_win = Some(window_size);
    }

    *last_time = Some(now);

    let features = calculate_features(&key, &flow);
    writer.serialize(&features)?;
    writer.flush()?;

    Ok(())
}

fn calculate_features(
    key: &(IpAddr, IpAddr, u16, u16, String),
    flow: &FlowTracker,
) -> FlowFeatures {
    let (src_ip, dst_ip, src_port, dst_port, protocol) = key;
    let now = SystemTime::now();
    let mut features = FlowFeatures {
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port: *src_port,
        dst_port: *dst_port,
        protocol: protocol.clone(),
        timestamp: DateTime::<Local>::from(now).format("%Y-%m-%d %H:%M:%S").to_string(),
        ..Default::default()
    };

    let duration_secs = now.duration_since(flow.start_time).unwrap().as_secs_f64();
    features.flow_duration = duration_secs;

    // Packet counts
    features.tot_fwd_pkts = flow.fwd_packets.len() as u32;
    features.tot_bwd_pkts = flow.bwd_packets.len() as u32;

    // Forward packet metrics
    if !flow.fwd_packets.is_empty() {
        let fwd_sizes: Vec<u32> = flow.fwd_packets.iter().map(|p| p.size as u32).collect();
        features.fwd_pkt_len_max = *fwd_sizes.iter().max().unwrap_or(&0);
        features.fwd_pkt_len_min = *fwd_sizes.iter().min().unwrap_or(&0);
        features.fwd_pkt_len_mean = mean(&fwd_sizes);
        features.fwd_pkt_len_std = std_dev(&fwd_sizes, features.fwd_pkt_len_mean);
        features.totlen_fwd_pkts = fwd_sizes.iter().sum();
        features.fwd_header_len = flow.fwd_packets.front().unwrap().header_len as u32;

        // TCP Flags (Forward)
        if protocol == "TCP" {
            features.fwd_psh_flags = flow.fwd_packets.iter()
                .filter(|p| p.tcp_flags.unwrap_or(0) & 0x08 != 0).count() as u8;
            features.syn_flag_cnt = flow.fwd_packets.iter()
                .filter(|p| p.tcp_flags.unwrap_or(0) & 0x02 != 0).count() as u8;
            features.ack_flag_cnt = flow.fwd_packets.iter()
                .filter(|p| p.tcp_flags.unwrap_or(0) & 0x10 != 0).count() as u8;
            features.fin_flag_cnt = flow.fwd_packets.iter()
                .filter(|p| p.tcp_flags.unwrap_or(0) & 0x01 != 0).count() as u8;
            features.rst_flag_cnt = flow.fwd_packets.iter()
                .filter(|p| p.tcp_flags.unwrap_or(0) & 0x04 != 0).count() as u8;
            features.urg_flag_cnt = flow.fwd_packets.iter()
                .filter(|p| p.tcp_flags.unwrap_or(0) & 0x20 != 0).count() as u8;
            features.ece_flag_cnt = flow.fwd_packets.iter()
                .filter(|p| p.tcp_flags.unwrap_or(0) & 0x40 != 0).count() as u8;
        }
    }

    // Backward packet metrics
    if !flow.bwd_packets.is_empty() {
        let bwd_sizes: Vec<u32> = flow.bwd_packets.iter().map(|p| p.size as u32).collect();
        features.bwd_pkt_len_max = *bwd_sizes.iter().max().unwrap_or(&0);
        features.bwd_pkt_len_min = *bwd_sizes.iter().min().unwrap_or(&0);
        features.bwd_pkt_len_mean = mean(&bwd_sizes);
        features.bwd_pkt_len_std = std_dev(&bwd_sizes, features.bwd_pkt_len_mean);
        features.totlen_bwd_pkts = bwd_sizes.iter().sum();
        features.bwd_header_len = flow.bwd_packets.front().unwrap().header_len as u32;
    }

    // Flow rates
    if duration_secs > 0.0 {
        features.flow_byts_s = (features.totlen_fwd_pkts + features.totlen_bwd_pkts) as f64 / duration_secs;
        features.flow_pkts_s = (features.tot_fwd_pkts + features.tot_bwd_pkts) as f64 / duration_secs;
        features.fwd_pkts_s = features.tot_fwd_pkts as f64 / duration_secs;
        features.bwd_pkts_s = features.tot_bwd_pkts as f64 / duration_secs;
    }

    // Window sizes
    features.init_fwd_win_byts = flow.init_fwd_win.unwrap_or(0);
    features.init_bwd_win_byts = flow.init_bwd_win.unwrap_or(0);

    // Combined packet stats
    let all_sizes: Vec<u32> = flow.fwd_packets.iter().chain(flow.bwd_packets.iter())
        .map(|p| p.size as u32)
        .collect();
    if !all_sizes.is_empty() {
        features.pkt_len_max = *all_sizes.iter().max().unwrap();
        features.pkt_len_min = *all_sizes.iter().min().unwrap();
        features.pkt_len_mean = mean(&all_sizes);
        features.pkt_len_std = std_dev(&all_sizes, features.pkt_len_mean);
        features.pkt_len_var = features.pkt_len_std.powi(2);
    }

    features
}

fn mean(data: &[u32]) -> f64 {
    let sum: u32 = data.iter().sum();
    sum as f64 / data.len() as f64
}

fn std_dev(data: &[u32], mean: f64) -> f64 {
    let variance = data.iter()
        .map(|x| (*x as f64 - mean).powi(2))
        .sum::<f64>() / data.len() as f64;
    variance.sqrt()
}
