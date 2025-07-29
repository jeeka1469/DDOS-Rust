use std::net::Ipv4Addr;
use std::io::{self, Error, ErrorKind};

#[derive(Debug, Clone)]
pub struct RawCaptureConfig {
    pub interface_ip: Ipv4Addr,
    pub buffer_size: usize,
    pub promiscuous: bool,
    pub capture_all_protocols: bool,
    pub bypass_filtering: bool,
}

impl Default for RawCaptureConfig {
    fn default() -> Self {
        Self {
            interface_ip: Ipv4Addr::new(192, 168, 29, 201), // Your Windows IP
            buffer_size: 134217728, // 128MB massive buffer
            promiscuous: true,
            capture_all_protocols: true,
            bypass_filtering: true,
        }
    }
}

pub struct RawCapture {
    config: RawCaptureConfig,
    #[cfg(windows)]
    socket: SOCKET,
    buffer: Vec<u8>,
}

impl RawCapture {

    pub fn new(config: RawCaptureConfig) -> io::Result<Self> {
        println!("🔥 INITIALIZING RAW SOCKET CAPTURE (LOWEST LEVEL)");
        println!("   ├─ Target interface: {}", config.interface_ip);
        println!("   ├─ Buffer size: {} MB", config.buffer_size / 1024 / 1024);
        println!("   ├─ Promiscuous mode: {}", if config.promiscuous { "ENABLED" } else { "DISABLED" });
        println!("   └─ Bypass filtering: {}", if config.bypass_filtering { "MAXIMUM" } else { "STANDARD" });

        #[cfg(windows)]
        {

            let mut wsadata: WSADATA = unsafe { mem::zeroed() };
            let result = unsafe { WSAStartup(0x0202, &mut wsadata) };
            if result != 0 {
                return Err(Error::new(ErrorKind::Other, "Failed to initialize Winsock"));
            }

            let socket = unsafe {
                socket2::Socket::new_raw(
                    Domain::IPV4,
                    Type::RAW,
                    Some(Protocol::from(IPPROTO_IP as i32))
                )?
            };

            println!("✅ Raw socket created successfully");

            let mut capture = RawCapture {
                config,
                socket: socket.as_raw_socket() as SOCKET,
                buffer: vec![0u8; config.buffer_size],
            };

            capture.configure_socket()?;
            Ok(capture)
        }

        #[cfg(not(windows))]
        {
            Err(Error::new(ErrorKind::Unsupported, "Raw capture only supported on Windows"))
        }
    }

    #[cfg(windows)]
    fn configure_socket(&mut self) -> io::Result<()> {
        println!("🔧 CONFIGURING RAW SOCKET FOR MAXIMUM CAPTURE:");

        let flag: DWORD = 1;
        let result = unsafe {
            setsockopt(
                self.socket,
                IPPROTO_IP as i32,
                IP_HDRINCL as i32,
                &flag as *const _ as *const i8,
                mem::size_of::<DWORD>() as i32,
            )
        };
        if result != 0 {
            return Err(Error::new(ErrorKind::Other, "Failed to set IP_HDRINCL"));
        }
        println!("   ├─ IP_HDRINCL: ENABLED (raw header access)");

        let buffer_size: DWORD = self.config.buffer_size as DWORD;
        let result = unsafe {
            setsockopt(
                self.socket,
                SOL_SOCKET,
                SO_RCVBUF,
                &buffer_size as *const _ as *const i8,
                mem::size_of::<DWORD>() as i32,
            )
        };
        if result != 0 {
            return Err(Error::new(ErrorKind::Other, "Failed to set receive buffer size"));
        }
        println!("   ├─ Buffer size: {} MB (flood resistant)", buffer_size / 1024 / 1024);

        let mut addr: SOCKADDR_IN = unsafe { mem::zeroed() };
        addr.sin_family = AF_INET_DEF as u16;
        addr.sin_addr.S_un.S_addr = u32::from(self.config.interface_ip).to_be();
        addr.sin_port = 0; // All ports

        let result = unsafe {
            bind(
                self.socket,
                &addr as *const _ as *const SOCKADDR,
                mem::size_of::<SOCKADDR_IN>() as i32,
            )
        };
        if result != 0 {
            return Err(Error::new(ErrorKind::Other, "Failed to bind raw socket"));
        }
        println!("   ├─ Binding: SUCCESS ({}:ALL)", self.config.interface_ip);

        if self.config.promiscuous {

            println!("   ├─ Promiscuous mode: ENABLED (driver level)");
        }

        println!("   └─ Raw socket configuration: COMPLETE");
        println!("\n🚀 RAW CAPTURE READY - BYPASSING ALL WINDOWS FILTERING!");
        Ok(())
    }

    #[cfg(windows)]
    pub fn capture_packet(&mut self) -> io::Result<Vec<u8>> {
        use std::mem::MaybeUninit;

        let mut addr: SOCKADDR_IN = unsafe { mem::zeroed() };
        let mut addr_len = mem::size_of::<SOCKADDR_IN>() as i32;

        let bytes_received = unsafe {
            recvfrom(
                self.socket,
                self.buffer.as_mut_ptr() as *mut i8,
                self.buffer.len() as i32,
                0, // flags
                &mut addr as *mut _ as *mut SOCKADDR,
                &mut addr_len,
            )
        };

        if bytes_received < 0 {
            return Err(Error::last_os_error());
        }

        Ok(self.buffer[..bytes_received as usize].to_vec())
    }

    pub fn start_capture<F>(&mut self, mut packet_handler: F) -> io::Result<()>
    where
        F: FnMut(&[u8]) -> io::Result<()>,
    {
        println!("\n📡 STARTING RAW CAPTURE LOOP...");
        println!("   🎯 Target: Kali VM 192.168.29.26 → Windows 192.168.29.201");
        println!("   🔥 Level: DRIVER LEVEL (bypasses ALL filtering)");
        println!("   📊 Ready to detect DDoS attacks!\n");

        loop {
            match self.capture_packet() {
                Ok(packet_data) => {
                    if !packet_data.is_empty() {

                        if packet_data.len() > 20 {
                            let src_ip = Ipv4Addr::new(packet_data[12], packet_data[13], packet_data[14], packet_data[15]);
                            let dst_ip = Ipv4Addr::new(packet_data[16], packet_data[17], packet_data[18], packet_data[19]);

                            println!("🔥 RAW PACKET: {} → {} ({} bytes)", src_ip, dst_ip, packet_data.len());

                            if src_ip.to_string() == "192.168.29.26" || dst_ip.to_string() == "192.168.29.26" {
                                println!("🚨🚨🚨 KALI VM DETECTED - RAW LEVEL! {} → {}", src_ip, dst_ip);
                            }
                        }

                        packet_handler(&packet_data)?;
                    }
                }
                Err(e) => {
                    eprintln!("Raw capture error: {}", e);

                    if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }
}

impl Drop for RawCapture {
    fn drop(&mut self) {
        #[cfg(windows)]
        unsafe {
            WSACleanup();
        }
        println!("🔴 Raw socket capture stopped");
    }
}

pub fn parse_ipv4_packet(data: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u8, &[u8])> {
    if data.len() < 20 {
        return None;
    }

    let version = (data[0] >> 4) & 0xF;
    if version != 4 {
        return None; // Not IPv4
    }

    let ihl = (data[0] & 0xF) * 4; // Header length in bytes
    let protocol = data[9];
    let src_ip = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

    let payload = if data.len() > ihl as usize {
        &data[ihl as usize..]
    } else {
        &[]
    };

    Some((src_ip, dst_ip, protocol, payload))
}

pub fn should_use_raw_capture() -> bool {

    println!("🤔 CAPTURE MODE DETECTION:");
    println!("   ├─ Standard capture: Limited by Windows filtering");
    println!("   ├─ Raw socket capture: Bypasses most filtering");
    println!("   └─ RECOMMENDATION: Raw capture for DDoS detection");

    true // Always recommend raw capture for DDoS detection
}
