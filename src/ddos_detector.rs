use std::collections::HashMap;
use std::time::{Duration, SystemTime};

pub struct DDoSDetector {

    ip_requests: HashMap<String, Vec<SystemTime>>,

    time_window: Duration,
    threshold: usize,
}

impl DDoSDetector {
    pub fn new(time_window_secs: u64, threshold: usize) -> Self {
        DDoSDetector {
            ip_requests: HashMap::new(),
            time_window: Duration::from_secs(time_window_secs),
            threshold: threshold,
        }
    }

    pub fn check_ip(&mut self, ip: &str, attack_type: &str) -> Option<String> {
        let now = SystemTime::now();
        let requests = self.ip_requests.entry(ip.to_string()).or_insert_with(Vec::new);

        requests.push(now);

        requests.retain(|&time| {
            if let Ok(elapsed) = time.elapsed() {
                elapsed <= self.time_window
            } else {
                false
            }
        });

        if requests.len() >= self.threshold {
            Some(format!(
                "\x1b[31mALERT: Potential DDoS Attack detected!\x1b[0m\n\
                Source IP: {}\n\
                Attack Type: {}\n\
                Requests in last {} seconds: {}\n\
                Current Threshold: {}",
                ip,
                attack_type,
                self.time_window.as_secs(),
                requests.len(),
                self.threshold
            ))
        } else {
            None
        }
    }
}
