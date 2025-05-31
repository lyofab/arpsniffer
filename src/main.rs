use axum::{
    body::Body,
    extract::Path,
    http::{Response, StatusCode},
    response::Json,
    response::Redirect,
    routing::get,
    Router,
};
use clap::Parser;
use pcap::{Capture, Device};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
};
use tokio::{fs, signal};

#[derive(Parser)]
struct Cli {
    #[arg(short, long)]
    iface: String,
}

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

#[derive(Serialize)]
struct Mapping {
    mac: String,
    ip: String,
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

async fn handle_index() -> Result<Response<Body>, (StatusCode, String)> {
    let path = PathBuf::from("./static/index.html");
    match fs::read_to_string(path).await {
        Ok(content) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html")
            .body(Body::from(content))
            .unwrap()),
        Err(_) => Err((StatusCode::NOT_FOUND, "File not found".to_string())),
    }
}

#[tokio::main]
async fn main() {
    let ip_mac_map: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let map_clone = ip_mac_map.clone();

    let args = Cli::parse();

    // Start packet capture in background
    thread::spawn(move || {
        let interface_name = args.iface; // Change this to match your interface
        let device = Device::list()
            .unwrap()
            .into_iter()
            .find(|d| d.name == interface_name)
            .expect("Device not found");

        let mut cap = Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .snaplen(65535)
            .open()
            .expect("Failed to open capture");

        cap.filter("arp", true).expect("Failed to set filter");

        while let Ok(packet) = cap.next() {
            if packet.data.len() < 42 {
                continue;
            }

            let ethertype = u16::from_be_bytes([packet.data[12], packet.data[13]]);
            if ethertype != 0x0806 {
                continue;
            }

            if let Some(arp) = parse_arp_packet(&packet.data[14..]) {
                let sender_mac = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    arp.sha[0], arp.sha[1], arp.sha[2], arp.sha[3], arp.sha[4], arp.sha[5]
                );
                let sender_ip = Ipv4Addr::new(arp.spa[0], arp.spa[1], arp.spa[2], arp.spa[3]);

                let target_mac = format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    arp.sha[0], arp.sha[1], arp.sha[2], arp.sha[3], arp.sha[4], arp.sha[5]
                );
                let target_ip = Ipv4Addr::new(arp.spa[0], arp.spa[1], arp.spa[2], arp.spa[3]);
                println!(
                    "got something: sender({}, {}), target({}, {})",
                    sender_mac, sender_ip, target_mac, target_ip
                );

                if !sender_ip.is_unspecified() {
                    let mut map = map_clone.lock().unwrap();
                    map.insert(sender_mac.clone(), sender_ip.to_string());
                }
            }
        }
        println!("End of capture thread");
    });

    // Build API
    let app = Router::new()
        .route("/ip/:mac", get(with_mac))
        .route("/search", get(search_mac))
        .route("/all", get(all_mappings))
        .route("/", get(|| async { Redirect::permanent("/index.html") }))
        .route("/index.html", get(handle_index))
        .with_state(ip_mac_map);

    println!("🚀 Server running on http://localhost:3000");
    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn with_mac(
    Path(mac): Path<String>,
    axum::extract::State(state): axum::extract::State<Arc<Mutex<HashMap<String, String>>>>,
) -> Result<Json<Mapping>, StatusCode> {
    let db = state.lock().unwrap();
    if let Some(ip) = db.get(&mac.to_lowercase()) {
        Ok(Json(Mapping {
            mac,
            ip: ip.clone(),
        }))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn search_mac(
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
    axum::extract::State(state): axum::extract::State<Arc<Mutex<HashMap<String, String>>>>,
) -> Json<Vec<Mapping>> {
    let needle = params
        .get("mac")
        .map(|m| m.to_lowercase())
        .unwrap_or_default();
    let db = state.lock().unwrap();
    let results: Vec<Mapping> = db
        .iter()
        .filter(|(mac, _)| mac.contains(&needle))
        .map(|(mac, ip)| Mapping {
            mac: mac.clone(),
            ip: ip.clone(),
        })
        .collect();

    Json(results)
}

async fn all_mappings(
    axum::extract::State(state): axum::extract::State<Arc<Mutex<HashMap<String, String>>>>,
) -> Json<Vec<Mapping>> {
    let db = state.lock().unwrap();
    let results: Vec<Mapping> = db
        .iter()
        .map(|(mac, ip)| Mapping {
            mac: mac.clone(),
            ip: ip.clone(),
        })
        .collect();
    Json(results)
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
    println!("Shutdown signal received.");
}
