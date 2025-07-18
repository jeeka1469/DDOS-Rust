use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, Duration};
use std::io::{self, Write};

use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{Packet, ip::IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use serde::Serialize;
use chrono::{DateTime, Local};
use csv;
use lazy_static::lazy_static;

mod model_predictor;
use model_predictor::ModelPredictor;

// --- Feature Struct (ALL 84+ fields) ---
#[derive(Debug, Serialize, Default, Clone)]
pub struct FlowFeatures {
    // Basic 5-tuple
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub timestamp: String,

    // Flow stats
    pub flow_duration: f64,
    pub flow_byts_s: f64,
    pub flow_pkts_s: f64,
    pub fwd_pkts_s: f64,
    pub bwd_pkts_s: f64,
    pub tot_fwd_pkts: u32,
    pub tot_bwd_pkts: u32,
    pub totlen_fwd_pkts: u32,
    pub totlen_bwd_pkts: u32,
    pub fwd_pkt_len_max: u32,
    pub fwd_pkt_len_min: u32,
    pub fwd_pkt_len_mean: f64,
    pub fwd_pkt_len_std: f64,
    pub bwd_pkt_len_max: u32,
    pub bwd_pkt_len_min: u32,
    pub bwd_pkt_len_mean: f64,
    pub bwd_pkt_len_std: f64,
    pub pkt_len_max: u32,
    pub pkt_len_min: u32,
    pub pkt_len_mean: f64,
    pub pkt_len_std: f64,
    pub pkt_len_var: f64,
    pub fwd_header_len: u32,
    pub bwd_header_len: u32,
    pub fwd_seg_size_min: u32,
    pub fwd_act_data_pkts: u32,
    pub flow_iat_mean: f64,
    pub flow_iat_max: f64,
    pub flow_iat_min: f64,
    pub flow_iat_std: f64,
    pub fwd_iat_tot: f64,
    pub fwd_iat_max: f64,
    pub fwd_iat_min: f64,
    pub fwd_iat_mean: f64,
    pub fwd_iat_std: f64,
    pub bwd_iat_tot: f64,
    pub bwd_iat_max: f64,
    pub bwd_iat_min: f64,
    pub bwd_iat_mean: f64,
    pub bwd_iat_std: f64,
    pub fwd_psh_flags: u8,
    pub bwd_psh_flags: u8,
    pub fwd_urg_flags: u8,
    pub bwd_urg_flags: u8,
    pub fin_flag_cnt: u8,
    pub syn_flag_cnt: u8,
    pub rst_flag_cnt: u8,
    pub psh_flag_cnt: u8,
    pub ack_flag_cnt: u8,
    pub urg_flag_cnt: u8,
    pub ece_flag_cnt: u8,
    pub down_up_ratio: f64,
    pub pkt_size_avg: f64,
    pub init_fwd_win_byts: u16,
    pub init_bwd_win_byts: u16,
    pub active_max: f64,
    pub active_min: f64,
    pub active_mean: f64,
    pub active_std: f64,
    pub idle_max: f64,
    pub idle_min: f64,
    pub idle_mean: f64,
    pub idle_std: f64,
    pub fwd_byts_b_avg: f64,
    pub fwd_pkts_b_avg: f64,
    pub bwd_byts_b_avg: f64,
    pub bwd_pkts_b_avg: f64,
    pub fwd_blk_rate_avg: f64,
    pub bwd_blk_rate_avg: f64,
    pub fwd_seg_size_avg: f64,
    pub bwd_seg_size_avg: f64,
    pub cwr_flag_count: u8,
    pub subflow_fwd_pkts: u32,
    pub subflow_bwd_pkts: u32,
    pub subflow_fwd_byts: u32,
    pub subflow_bwd_byts: u32,
    pub label: String,
}

// --- Global Flow Table ---
lazy_static! {
    static ref FLOW_TABLE: Mutex<HashMap<String, FlowTracker>> = 
        Mutex::new(HashMap::new());
    static ref MODEL_PREDICTOR: Mutex<Option<ModelPredictor>> = 
        Mutex::new(None);
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
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: String,
    last_prediction: Option<(String, f64)>,
    prediction_count: u32,
}

#[derive(Clone)]
struct PacketData {
    timestamp: SystemTime,
    size: usize,
    tcp_flags: Option<u8>,
    header_len: usize,
    payload_len: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Handle Ctrl+C gracefully
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        if let Err(err) = ctrlc::set_handler(move || {
            println!("\nCtrl+C received, stopping capture...");
            running.store(false, Ordering::SeqCst);
            // Force flush any pending writes
            std::io::stdout().flush().unwrap_or(());
        }) {
            eprintln!("Error setting Ctrl+C handler: {}", err);
            return Err(Box::new(err));
        }
    }
    // Initialize the model predictor
    println!("Loading trained model...");
    let model_predictor = ModelPredictor::new(
        "unified_ddos_best_model.pkl",
        "unified_ddos_best_model_scaler.pkl",
        "unified_ddos_best_model_metadata.pkl"
    )?;
    
    {
        let mut predictor = MODEL_PREDICTOR.lock().unwrap();
        *predictor = Some(model_predictor);
    }
    
    println!("Model loaded successfully!");

    // List all available interfaces
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

    println!("Capturing on {}... Press Ctrl+C to stop", interface.name);
    println!("Real-time DDoS detection enabled!");

    // Initialize CSV writer
    let mut writer = csv::Writer::from_path("flow_features_with_predictions.csv")?;
    let mut packet_count = 0;

    while running.load(Ordering::SeqCst) {
        match rx.next() {
            Ok(packet) => {
                if !running.load(Ordering::SeqCst) {
                    println!("\nShutting down gracefully...");
                    break;
                }
                packet_count += 1;
                // Process every 5th packet to avoid overwhelming output
                if packet_count % 5 == 0 {
                    println!("Processed {} packets...", packet_count);
                }

                if let Some(ipv4) = Ipv4Packet::new(packet) {
                    let protocol_num = ipv4.get_next_level_protocol();
                    match protocol_num {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                process_tcp_packet(&ipv4, &tcp, &mut writer)?;
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                process_udp_packet(&ipv4, &udp, &mut writer)?;
                            }
                        }
                        _ => {
                            process_generic_packet(&ipv4, protocol_num, &mut writer)?;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading packet: {}", e);
                continue;
            }
        }
    }
    println!("Capture stopped. Exiting.");
    Ok(())
}

fn process_tcp_packet(
    ipv4: &Ipv4Packet,
    tcp: &TcpPacket,
    writer: &mut csv::Writer<std::fs::File>,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now();
    let src_ip = ipv4.get_source();
    let dst_ip = ipv4.get_destination();
    let src_port = tcp.get_source();
    let dst_port = tcp.get_destination();
    let protocol = "TCP";
    
    let flow_key = format!("{}:{}-{}:{}-{}", src_ip, src_port, dst_ip, dst_port, protocol);
    let reverse_key = format!("{}:{}-{}:{}-{}", dst_ip, dst_port, src_ip, src_port, protocol);
    
    let mut flow_table = FLOW_TABLE.lock().unwrap();
    
    // Check if this is a reverse flow
    let (key, is_reverse) = if flow_table.contains_key(&flow_key) {
        (flow_key, false)
    } else if flow_table.contains_key(&reverse_key) {
        (reverse_key, true)
    } else {
        (flow_key, false)
    };
    
    let flow = flow_table.entry(key.clone()).or_insert_with(|| FlowTracker {
        start_time: now,
        fwd_packets: VecDeque::new(),
        bwd_packets: VecDeque::new(),
        last_fwd_time: None,
        last_bwd_time: None,
        init_fwd_win: None,
        init_bwd_win: None,
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol: protocol.to_string(),
        last_prediction: None,
        prediction_count: 0,
    });

    let packet_data = PacketData {
        timestamp: now,
        size: ipv4.get_total_length() as usize,
        tcp_flags: Some(tcp.get_flags()),
        header_len: (tcp.get_data_offset() as usize) * 4,
        payload_len: tcp.payload().len(),
    };

    // Determine direction
    let is_forward = !is_reverse;
    if is_forward {
        flow.fwd_packets.push_back(packet_data);
        flow.last_fwd_time = Some(now);
        if flow.init_fwd_win.is_none() {
            flow.init_fwd_win = Some(tcp.get_window());
        }
    } else {
        flow.bwd_packets.push_back(packet_data);
        flow.last_bwd_time = Some(now);
        if flow.init_bwd_win.is_none() {
            flow.init_bwd_win = Some(tcp.get_window());
        }
    }

    // Calculate features
    let mut features = calculate_features(&flow);
    // Encode categorical features before prediction
    if let Err(e) = model_predictor::apply_label_encoders(&mut features, "unified_ddos_best_model_metadata.pkl") {
        eprintln!("Label encoding error: {}", e);
    }

    // Make prediction every 10 packets or if it's a new flow
    let total_packets = flow.fwd_packets.len() + flow.bwd_packets.len();
    if total_packets % 10 == 0 || flow.last_prediction.is_none() {
        if let Some(ref predictor) = *MODEL_PREDICTOR.lock().unwrap() {
            match predictor.predict(&features) {
                Ok((prediction, confidence)) => {
                    // Save original IPs for reporting
                    let orig_src_ip = features.src_ip.clone();
                    let orig_dst_ip = features.dst_ip.clone();
                    
                    features.label = prediction.clone();
                    flow.last_prediction = Some((prediction.clone(), confidence));
                    flow.prediction_count += 1;
                    
                    // Alert for potential DDoS
                    if prediction.to_lowercase().contains("ddos") || 
                       prediction.to_lowercase().contains("attack") {
                        println!("⚠️  POTENTIAL DDOS DETECTED!");
                        println!("   Flow: {}:{} -> {}:{}", 
                                orig_src_ip, features.src_port,
                                orig_dst_ip, features.dst_port);
                        println!("   Prediction: {} (Confidence: {:.2}%)", 
                                prediction, confidence * 100.0);
                        println!("   Flow Stats: {} fwd, {} bwd packets", 
                                features.tot_fwd_pkts, features.tot_bwd_pkts);
                    }
                }
                Err(e) => {
                    eprintln!("Prediction error: {}", e);
                    features.label = "Error".to_string();
                }
            }
        }
    } else if let Some((ref last_pred, _)) = flow.last_prediction {
        features.label = last_pred.clone();
    }

    // Write features to CSV
    writer.serialize(&features)?;
    writer.flush()?;

    // Print normal flow progress
    if total_packets % 20 == 0 {
        println!("TCP Flow: {}:{} -> {}:{} [Fwd: {}, Bwd: {}, Pred: {}]",
            features.src_ip, features.src_port,
            features.dst_ip, features.dst_port,
            features.tot_fwd_pkts, features.tot_bwd_pkts,
            features.label);
    }

    Ok(())
}

fn process_udp_packet(
    ipv4: &Ipv4Packet,
    udp: &UdpPacket,
    writer: &mut csv::Writer<std::fs::File>,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now();
    let src_ip = ipv4.get_source();
    let dst_ip = ipv4.get_destination();
    let src_port = udp.get_source();
    let dst_port = udp.get_destination();
    let protocol = "UDP";
    
    let flow_key = format!("{}:{}-{}:{}-{}", src_ip, src_port, dst_ip, dst_port, protocol);
    let reverse_key = format!("{}:{}-{}:{}-{}", dst_ip, dst_port, src_ip, src_port, protocol);
    
    let mut flow_table = FLOW_TABLE.lock().unwrap();
    
    let (key, is_reverse) = if flow_table.contains_key(&flow_key) {
        (flow_key, false)
    } else if flow_table.contains_key(&reverse_key) {
        (reverse_key, true)
    } else {
        (flow_key, false)
    };
    
    let flow = flow_table.entry(key.clone()).or_insert_with(|| FlowTracker {
        start_time: now,
        fwd_packets: VecDeque::new(),
        bwd_packets: VecDeque::new(),
        last_fwd_time: None,
        last_bwd_time: None,
        init_fwd_win: None,
        init_bwd_win: None,
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol: protocol.to_string(),
        last_prediction: None,
        prediction_count: 0,
    });

    let packet_data = PacketData {
        timestamp: now,
        size: ipv4.get_total_length() as usize,
        tcp_flags: None,
        header_len: 8, // UDP header is always 8 bytes
        payload_len: udp.payload().len(),
    };

    // Determine direction
    let is_forward = !is_reverse;
    if is_forward {
        flow.fwd_packets.push_back(packet_data);
        flow.last_fwd_time = Some(now);
    } else {
        flow.bwd_packets.push_back(packet_data);
        flow.last_bwd_time = Some(now);
    }

    // Calculate features and make prediction
    let mut features = calculate_features(&flow);
    // Encode categorical features before prediction
    if let Err(e) = model_predictor::apply_label_encoders(&mut features, "unified_ddos_best_model_metadata.pkl") {
        eprintln!("Label encoding error: {}", e);
    }

    let total_packets = flow.fwd_packets.len() + flow.bwd_packets.len();
    if total_packets % 15 == 0 || flow.last_prediction.is_none() {
        if let Some(ref predictor) = *MODEL_PREDICTOR.lock().unwrap() {
            match predictor.predict(&features) {
                Ok((prediction, confidence)) => {
                    // Save original IPs for reporting
                    let orig_src_ip = features.src_ip.clone();
                    let orig_dst_ip = features.dst_ip.clone();
                    
                    features.label = prediction.clone();
                    flow.last_prediction = Some((prediction.clone(), confidence));
                    flow.prediction_count += 1;
                    
                    // Alert for potential DDoS
                    if prediction.to_lowercase().contains("ddos") || 
                       prediction.to_lowercase().contains("attack") {
                        println!("⚠️  POTENTIAL DDOS DETECTED!");
                        println!("   UDP Flow: {}:{} -> {}:{}", 
                                orig_src_ip, features.src_port,
                                orig_dst_ip, features.dst_port);
                        println!("   Prediction: {} (Confidence: {:.2}%)", 
                                prediction, confidence * 100.0);
                    }
                }
                Err(e) => {
                    eprintln!("Prediction error: {}", e);
                    features.label = "Error".to_string();
                }
            }
        }
    } else if let Some((ref last_pred, _)) = flow.last_prediction {
        features.label = last_pred.clone();
    }

    // Write features to CSV
    writer.serialize(&features)?;
    writer.flush()?;

    // Print normal flow progress
    if total_packets % 25 == 0 {
        println!("UDP Flow: {}:{} -> {}:{} [Fwd: {}, Bwd: {}, Pred: {}]",
            features.src_ip, features.src_port,
            features.dst_ip, features.dst_port,
            features.tot_fwd_pkts, features.tot_bwd_pkts,
            features.label);
    }

    Ok(())
}

fn process_generic_packet(
    ipv4: &Ipv4Packet,
    protocol: pnet::packet::ip::IpNextHeaderProtocol,
    writer: &mut csv::Writer<std::fs::File>,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now();
    let src_ip = ipv4.get_source();
    let dst_ip = ipv4.get_destination();
    let protocol_name = format!("{:?}", protocol);
    
    let flow_key = format!("{}:0-{}:0-{}", src_ip, dst_ip, protocol_name);
    let reverse_key = format!("{}:0-{}:0-{}", dst_ip, src_ip, protocol_name);
    
    let mut flow_table = FLOW_TABLE.lock().unwrap();
    
    let (key, is_reverse) = if flow_table.contains_key(&flow_key) {
        (flow_key, false)
    } else if flow_table.contains_key(&reverse_key) {
        (reverse_key, true)
    } else {
        (flow_key, false)
    };
    
    let flow = flow_table.entry(key.clone()).or_insert_with(|| FlowTracker {
        start_time: now,
        fwd_packets: VecDeque::new(),
        bwd_packets: VecDeque::new(),
        last_fwd_time: None,
        last_bwd_time: None,
        init_fwd_win: None,
        init_bwd_win: None,
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        src_port: 0,
        dst_port: 0,
        protocol: protocol_name.clone(),
        last_prediction: None,
        prediction_count: 0,
    });

    let packet_data = PacketData {
        timestamp: now,
        size: ipv4.get_total_length() as usize,
        tcp_flags: None,
        header_len: ipv4.get_header_length() as usize,
        payload_len: ipv4.payload().len(),
    };

    // Determine direction
    let is_forward = !is_reverse;
    if is_forward {
        flow.fwd_packets.push_back(packet_data);
        flow.last_fwd_time = Some(now);
    } else {
        flow.bwd_packets.push_back(packet_data);
        flow.last_bwd_time = Some(now);
    }

    // Calculate features and make prediction
    let mut features = calculate_features(&flow);
    // Encode categorical features before prediction
    if let Err(e) = model_predictor::apply_label_encoders(&mut features, "unified_ddos_best_model_metadata.pkl") {
        eprintln!("Label encoding error: {}", e);
    }

    let total_packets = flow.fwd_packets.len() + flow.bwd_packets.len();
    if total_packets % 20 == 0 || flow.last_prediction.is_none() {
        if let Some(ref predictor) = *MODEL_PREDICTOR.lock().unwrap() {
            match predictor.predict(&features) {
                Ok((prediction, confidence)) => {
                    // Save original IPs for reporting
                    let orig_src_ip = features.src_ip.clone();
                    let orig_dst_ip = features.dst_ip.clone();
                    
                    features.label = prediction.clone();
                    flow.last_prediction = Some((prediction.clone(), confidence));
                    flow.prediction_count += 1;
                    
                    // Alert for potential DDoS
                    if prediction.to_lowercase().contains("ddos") || 
                       prediction.to_lowercase().contains("attack") {
                        println!("⚠️  POTENTIAL DDOS DETECTED!");
                        println!("   Generic Flow: {} -> {} ({})", 
                                orig_src_ip, orig_dst_ip, features.protocol);
                        println!("   Prediction: {} (Confidence: {:.2}%)", 
                                prediction, confidence * 100.0);
                    }
                }
                Err(e) => {
                    eprintln!("Prediction error: {}", e);
                    features.label = "Error".to_string();
                }
            }
        }
    } else if let Some((ref last_pred, _)) = flow.last_prediction {
        features.label = last_pred.clone();
    }

    // Write features to CSV
    writer.serialize(&features)?;
    writer.flush()?;

    Ok(())
}

fn calculate_features(flow: &FlowTracker) -> FlowFeatures {
    let mut features = FlowFeatures::default();
    
    // Basic 5-tuple
    features.src_ip = flow.src_ip.to_string();
    features.dst_ip = flow.dst_ip.to_string();
    features.src_port = flow.src_port;
    features.dst_port = flow.dst_port;
    features.protocol = flow.protocol.clone();
    features.timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
    
    // Basic packet counts
    features.tot_fwd_pkts = flow.fwd_packets.len() as u32;
    features.tot_bwd_pkts = flow.bwd_packets.len() as u32;
    
    // Calculate flow duration
    let current_time = SystemTime::now();
    features.flow_duration = current_time
        .duration_since(flow.start_time)
        .unwrap_or_default()
        .as_secs_f64();
    
    // Calculate packet lengths
    let fwd_lengths: Vec<u32> = flow.fwd_packets.iter().map(|p| p.size as u32).collect();
    let bwd_lengths: Vec<u32> = flow.bwd_packets.iter().map(|p| p.size as u32).collect();
    let all_lengths: Vec<u32> = fwd_lengths.iter().chain(bwd_lengths.iter()).copied().collect();
    
    // Forward packet statistics
    if !fwd_lengths.is_empty() {
        features.fwd_pkt_len_max = *fwd_lengths.iter().max().unwrap_or(&0);
        features.fwd_pkt_len_min = *fwd_lengths.iter().min().unwrap_or(&0);
        features.fwd_pkt_len_mean = fwd_lengths.iter().sum::<u32>() as f64 / fwd_lengths.len() as f64;
        features.fwd_pkt_len_std = calculate_std_dev(&fwd_lengths, features.fwd_pkt_len_mean);
        features.totlen_fwd_pkts = fwd_lengths.iter().sum();
    }
    
    // Backward packet statistics
    if !bwd_lengths.is_empty() {
        features.bwd_pkt_len_max = *bwd_lengths.iter().max().unwrap_or(&0);
        features.bwd_pkt_len_min = *bwd_lengths.iter().min().unwrap_or(&0);
        features.bwd_pkt_len_mean = bwd_lengths.iter().sum::<u32>() as f64 / bwd_lengths.len() as f64;
        features.bwd_pkt_len_std = calculate_std_dev(&bwd_lengths, features.bwd_pkt_len_mean);
        features.totlen_bwd_pkts = bwd_lengths.iter().sum();
    }
    
    // Overall packet statistics
    if !all_lengths.is_empty() {
        features.pkt_len_max = *all_lengths.iter().max().unwrap_or(&0);
        features.pkt_len_min = *all_lengths.iter().min().unwrap_or(&0);
        features.pkt_len_mean = all_lengths.iter().sum::<u32>() as f64 / all_lengths.len() as f64;
        features.pkt_len_std = calculate_std_dev(&all_lengths, features.pkt_len_mean);
        features.pkt_len_var = features.pkt_len_std * features.pkt_len_std;
        features.pkt_size_avg = features.pkt_len_mean;
    }
    
    // Calculate rates
    if features.flow_duration > 0.0 {
        features.flow_byts_s = (features.totlen_fwd_pkts + features.totlen_bwd_pkts) as f64 / features.flow_duration;
        features.flow_pkts_s = (features.tot_fwd_pkts + features.tot_bwd_pkts) as f64 / features.flow_duration;
        features.fwd_pkts_s = features.tot_fwd_pkts as f64 / features.flow_duration;
        features.bwd_pkts_s = features.tot_bwd_pkts as f64 / features.flow_duration;
    }
    
    // Calculate header lengths
    features.fwd_header_len = flow.fwd_packets.iter()
        .map(|p| p.header_len as u32)
        .sum();
    features.bwd_header_len = flow.bwd_packets.iter()
        .map(|p| p.header_len as u32)
        .sum();
    
    // Calculate active data packets (packets with payload)
    features.fwd_act_data_pkts = flow.fwd_packets.iter()
        .filter(|p| p.payload_len > 0)
        .count() as u32;
    
    // Calculate Inter-Arrival Times (IAT)
    calculate_iat_features(&flow.fwd_packets, &flow.bwd_packets, &mut features);
    
    // Calculate TCP flags if applicable
    if flow.protocol == "TCP" {
        calculate_tcp_flags(&flow.fwd_packets, &flow.bwd_packets, &mut features);
    }
    
    // Calculate window sizes
    features.init_fwd_win_byts = flow.init_fwd_win.unwrap_or(0);
    features.init_bwd_win_byts = flow.init_bwd_win.unwrap_or(0);
    
    // Calculate bulk and segment features
    calculate_bulk_features(&flow.fwd_packets, &flow.bwd_packets, &mut features);
    
    // Calculate subflow features (same as flow for single flow)
    features.subflow_fwd_pkts = features.tot_fwd_pkts;
    features.subflow_bwd_pkts = features.tot_bwd_pkts;
    features.subflow_fwd_byts = features.totlen_fwd_pkts;
    features.subflow_bwd_byts = features.totlen_bwd_pkts;
    
    // Calculate ratio features
    if features.totlen_fwd_pkts > 0 {
        features.down_up_ratio = features.totlen_bwd_pkts as f64 / features.totlen_fwd_pkts as f64;
    }
    
    // Calculate segment size features
    if features.tot_fwd_pkts > 0 {
        features.fwd_seg_size_avg = features.totlen_fwd_pkts as f64 / features.tot_fwd_pkts as f64;
        let fwd_payload_sizes: Vec<u32> = flow.fwd_packets.iter()
            .map(|p| p.payload_len as u32)
            .filter(|&size| size > 0)
            .collect();
        if !fwd_payload_sizes.is_empty() {
            features.fwd_seg_size_min = *fwd_payload_sizes.iter().min().unwrap_or(&0);
        }
    }
    
    if features.tot_bwd_pkts > 0 {
        features.bwd_seg_size_avg = features.totlen_bwd_pkts as f64 / features.tot_bwd_pkts as f64;
    }
    
    features
}

fn calculate_std_dev(values: &[u32], mean: f64) -> f64 {
    if values.len() <= 1 {
        return 0.0;
    }
    
    let variance = values.iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>() / (values.len() - 1) as f64;
    
    variance.sqrt()
}

fn calculate_iat_features(
    fwd_packets: &VecDeque<PacketData>,
    bwd_packets: &VecDeque<PacketData>,
    features: &mut FlowFeatures,
) {
    // Calculate forward IAT
    let fwd_iats = calculate_inter_arrival_times(fwd_packets);
    if !fwd_iats.is_empty() {
        features.fwd_iat_tot = fwd_iats.iter().sum();
        features.fwd_iat_max = fwd_iats.iter().fold(0.0, |a, &b| a.max(b));
        features.fwd_iat_min = fwd_iats.iter().fold(f64::MAX, |a, &b| a.min(b));
        features.fwd_iat_mean = features.fwd_iat_tot / fwd_iats.len() as f64;
        features.fwd_iat_std = calculate_std_dev_f64(&fwd_iats, features.fwd_iat_mean);
    }
    
    // Calculate backward IAT
    let bwd_iats = calculate_inter_arrival_times(bwd_packets);
    if !bwd_iats.is_empty() {
        features.bwd_iat_tot = bwd_iats.iter().sum();
        features.bwd_iat_max = bwd_iats.iter().fold(0.0, |a, &b| a.max(b));
        features.bwd_iat_min = bwd_iats.iter().fold(f64::MAX, |a, &b| a.min(b));
        features.bwd_iat_mean = features.bwd_iat_tot / bwd_iats.len() as f64;
        features.bwd_iat_std = calculate_std_dev_f64(&bwd_iats, features.bwd_iat_mean);
    }
    
    // Calculate flow IAT (combined)
    let mut all_packets: Vec<&PacketData> = fwd_packets.iter().chain(bwd_packets.iter()).collect();
    all_packets.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    
    let flow_iats = calculate_inter_arrival_times_from_sorted(&all_packets);
    if !flow_iats.is_empty() {
        features.flow_iat_max = flow_iats.iter().fold(0.0, |a, &b| a.max(b));
        features.flow_iat_min = flow_iats.iter().fold(f64::MAX, |a, &b| a.min(b));
        features.flow_iat_mean = flow_iats.iter().sum::<f64>() / flow_iats.len() as f64;
        features.flow_iat_std = calculate_std_dev_f64(&flow_iats, features.flow_iat_mean);
    }
}

fn calculate_inter_arrival_times(packets: &VecDeque<PacketData>) -> Vec<f64> {
    let mut iats = Vec::new();
    
    for window in packets.iter().collect::<Vec<_>>().windows(2) {
        if let [prev, curr] = window {
            if let Ok(duration) = curr.timestamp.duration_since(prev.timestamp) {
                iats.push(duration.as_secs_f64());
            }
        }
    }
    
    iats
}

fn calculate_inter_arrival_times_from_sorted(packets: &[&PacketData]) -> Vec<f64> {
    let mut iats = Vec::new();
    
    for window in packets.windows(2) {
        if let [prev, curr] = window {
            if let Ok(duration) = curr.timestamp.duration_since(prev.timestamp) {
                iats.push(duration.as_secs_f64());
            }
        }
    }
    
    iats
}

fn calculate_std_dev_f64(values: &[f64], mean: f64) -> f64 {
    if values.len() <= 1 {
        return 0.0;
    }
    
    let variance = values.iter()
        .map(|&x| {
            let diff = x - mean;
            diff * diff
        })
        .sum::<f64>() / (values.len() - 1) as f64;
    
    variance.sqrt()
}

fn calculate_tcp_flags(
    fwd_packets: &VecDeque<PacketData>,
    bwd_packets: &VecDeque<PacketData>,
    features: &mut FlowFeatures,
) {
    // TCP flag constants
    const FIN: u8 = 0x01;
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const PSH: u8 = 0x08;
    const ACK: u8 = 0x10;
    const URG: u8 = 0x20;
    const ECE: u8 = 0x40;
    const CWR: u8 = 0x80;
    
    let mut fin_count = 0;
    let mut syn_count = 0;
    let mut rst_count = 0;
    let mut psh_count = 0;
    let mut ack_count = 0;
    let mut urg_count = 0;
    let mut ece_count = 0;
    let mut cwr_count = 0;
    
    let mut fwd_psh_count = 0;
    let mut fwd_urg_count = 0;
    let mut bwd_psh_count = 0;
    let mut bwd_urg_count = 0;
    
    // Count forward flags
    for packet in fwd_packets {
        if let Some(flags) = packet.tcp_flags {
            if flags & FIN != 0 { fin_count += 1; }
            if flags & SYN != 0 { syn_count += 1; }
            if flags & RST != 0 { rst_count += 1; }
            if flags & PSH != 0 { psh_count += 1; fwd_psh_count += 1; }
            if flags & ACK != 0 { ack_count += 1; }
            if flags & URG != 0 { urg_count += 1; fwd_urg_count += 1; }
            if flags & ECE != 0 { ece_count += 1; }
            if flags & CWR != 0 { cwr_count += 1; }
        }
    }
    
    // Count backward flags
    for packet in bwd_packets {
        if let Some(flags) = packet.tcp_flags {
            if flags & FIN != 0 { fin_count += 1; }
            if flags & SYN != 0 { syn_count += 1; }
            if flags & RST != 0 { rst_count += 1; }
            if flags & PSH != 0 { psh_count += 1; bwd_psh_count += 1; }
            if flags & ACK != 0 { ack_count += 1; }
            if flags & URG != 0 { urg_count += 1; bwd_urg_count += 1; }
            if flags & ECE != 0 { ece_count += 1; }
            if flags & CWR != 0 { cwr_count += 1; }
        }
    }
    
    features.fin_flag_cnt = fin_count;
    features.syn_flag_cnt = syn_count;
    features.rst_flag_cnt = rst_count;
    features.psh_flag_cnt = psh_count;
    features.ack_flag_cnt = ack_count;
    features.urg_flag_cnt = urg_count;
    features.ece_flag_cnt = ece_count;
    features.cwr_flag_count = cwr_count;
    
    features.fwd_psh_flags = fwd_psh_count;
    features.fwd_urg_flags = fwd_urg_count;
    features.bwd_psh_flags = bwd_psh_count;
    features.bwd_urg_flags = bwd_urg_count;
}

fn calculate_bulk_features(
    fwd_packets: &VecDeque<PacketData>,
    bwd_packets: &VecDeque<PacketData>,
    features: &mut FlowFeatures,
) {
    // Calculate bulk transfer statistics
    let fwd_bulk_packets = fwd_packets.len() as f64;
    let bwd_bulk_packets = bwd_packets.len() as f64;
    
    if fwd_bulk_packets > 0.0 {
        features.fwd_byts_b_avg = features.totlen_fwd_pkts as f64 / fwd_bulk_packets;
        features.fwd_pkts_b_avg = fwd_bulk_packets;
        features.fwd_blk_rate_avg = fwd_bulk_packets / features.flow_duration.max(1.0);
    }
    
    if bwd_bulk_packets > 0.0 {
        features.bwd_byts_b_avg = features.totlen_bwd_pkts as f64 / bwd_bulk_packets;
        features.bwd_pkts_b_avg = bwd_bulk_packets;
        features.bwd_blk_rate_avg = bwd_bulk_packets / features.flow_duration.max(1.0);
    }
    
    // Calculate active and idle time statistics
    calculate_active_idle_stats(fwd_packets, bwd_packets, features);
}

fn calculate_active_idle_stats(
    fwd_packets: &VecDeque<PacketData>,
    bwd_packets: &VecDeque<PacketData>,
    features: &mut FlowFeatures,
) {
    // Combine all packets and sort by timestamp
    let mut all_packets: Vec<&PacketData> = fwd_packets.iter().chain(bwd_packets.iter()).collect();
    all_packets.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    
    if all_packets.len() < 2 {
        return;
    }
    
    let mut active_periods = Vec::new();
    let mut idle_periods = Vec::new();
    
    // Simple heuristic: periods with < 1 second between packets are "active"
    let active_threshold = Duration::from_secs(1);
    
    for window in all_packets.windows(2) {
        if let [prev, curr] = window {
            if let Ok(duration) = curr.timestamp.duration_since(prev.timestamp) {
                let duration_secs = duration.as_secs_f64();
                if duration <= active_threshold {
                    active_periods.push(duration_secs);
                } else {
                    idle_periods.push(duration_secs);
                }
            }
        }
    }
    
    // Calculate active time statistics
    if !active_periods.is_empty() {
        features.active_max = active_periods.iter().fold(0.0, |a, &b| a.max(b));
        features.active_min = active_periods.iter().fold(f64::MAX, |a, &b| a.min(b));
        features.active_mean = active_periods.iter().sum::<f64>() / active_periods.len() as f64;
        features.active_std = calculate_std_dev_f64(&active_periods, features.active_mean);
    }
    
    // Calculate idle time statistics
    if !idle_periods.is_empty() {
        features.idle_max = idle_periods.iter().fold(0.0, |a, &b| a.max(b));
        features.idle_min = idle_periods.iter().fold(f64::MAX, |a, &b| a.min(b));
        features.idle_mean = idle_periods.iter().sum::<f64>() / idle_periods.len() as f64;
        features.idle_std = calculate_std_dev_f64(&idle_periods, features.idle_mean);
    }
}