use pcap::{Capture, Device};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;

#[repr(packed)]
#[derive(Debug)]
struct ArpPacket {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
}

fn parse_arp_packet(data: &[u8]) -> Option<ArpPacket> {
    if data.len() < 28 {
        return None;
    }
    Some(ArpPacket {
        htype: u16::from_be_bytes([data[0], data[1]]),
        ptype: u16::from_be_bytes([data[2], data[3]]),
        hlen: data[4],
        plen: data[5],
        oper: u16::from_be_bytes([data[6], data[7]]),
        sha: data[8..14].try_into().unwrap(),
        spa: data[14..18].try_into().unwrap(),
        tha: data[18..24].try_into().unwrap(),
        tpa: data[24..28].try_into().unwrap(),
    })
}

fn main() {
    let devices = Device::list().expect("Failed to list devices");
    println!("Available Devices:");
    for device in &devices {
        println!(
            "- {} ({})",
            device.name,
            device.desc.clone().unwrap_or("No description".to_string())
        );
    }

    let interface_name = "wlxd017c2a11456"; // Change this to your interface
    let device = devices
        .into_iter()
        .find(|d| d.name == interface_name)
        .expect("Device not found");

    let ip_mac_map: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    let map_clone = Arc::clone(&ip_mac_map);
    thread::spawn(move || {
        let mut cap = Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .open()
            .expect("Failed to open capture");

        cap.filter("arp", true).expect("Failed to set ARP filter");

        while let Ok(packet) = cap.next() {
            if packet.data.len() < 42 {
                continue;
            }

            let ethertype = u16::from_be_bytes([packet.data[12], packet.data[13]]);
            if ethertype != 0x0806 {
                continue;
            }

            if let Some(arp) = parse_arp_packet(&packet.data[14..]) {
                let mac = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    arp.sha[0], arp.sha[1], arp.sha[2], arp.sha[3], arp.sha[4], arp.sha[5]
                );
                let ip = Ipv4Addr::new(arp.spa[0], arp.spa[1], arp.spa[2], arp.spa[3]);

                let mut map = map_clone.lock().unwrap();
                map.insert(mac.clone(), ip.to_string());

                println!("ARP: {} is at {}", ip, mac);
            }
        }
    });

    // Keep running or replace this with a REST API
    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}
