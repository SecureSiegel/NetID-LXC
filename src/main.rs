use chrono::{SecondsFormat, Utc};
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_LISTEN_SECONDS: u64 = 30;
const MAX_LISTEN_SECONDS: u64 = 60;
const MAX_RDNS_TARGETS: usize = 24;
const RDNS_CONCURRENCY: usize = 4;
const DEFAULT_OUTPUT_DIR: &str = "/var/lib/netid-lxc/output";

#[derive(Debug, Clone)]
struct RuntimeConfig {
    listen_seconds: u64,
    output_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct InterfaceInfo {
    name: String,
    mac: Option<String>,
    ip: Ipv4Addr,
    prefix: u8,
    netmask: Ipv4Addr,
    subnet: String,
}

#[derive(Debug, Clone)]
struct NeighborEntry {
    ip: Ipv4Addr,
    mac: Option<String>,
    interface: Option<String>,
    state: Option<String>,
}

#[derive(Debug, Clone)]
struct DhcpObservation {
    ip: Option<Ipv4Addr>,
    mac: Option<String>,
    hostname: Option<String>,
    source: String,
}

#[derive(Debug, Clone)]
struct MdnsObservation {
    source_ip: Option<Ipv4Addr>,
    hostname: Option<String>,
    instance: Option<String>,
    service_type: Option<String>,
}

#[derive(Debug, Clone)]
struct SsdpObservation {
    source_ip: Option<Ipv4Addr>,
    service_type: Option<String>,
    identifier: Option<String>,
    friendly_name: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct DeviceRecord {
    ips: Vec<String>,
    macs: Vec<String>,
    interface: Option<String>,
    observed_hostnames: Vec<String>,
    observed_instances: Vec<String>,
    observed_mdns_services: Vec<String>,
    observed_ssdp_services: Vec<String>,
    vendor: Option<String>,
    category: String,
    confidence: String,
    confidence_sources: Vec<String>,
    first_seen: String,
    last_seen: String,
}

#[derive(Debug)]
struct DeviceBuilder {
    ips: HashSet<Ipv4Addr>,
    macs: HashSet<String>,
    interface: Option<String>,
    hostnames: HashSet<String>,
    instances: HashSet<String>,
    mdns_services: HashSet<String>,
    ssdp_services: HashSet<String>,
    vendor: Option<String>,
    sources: HashSet<String>,
    first_seen: String,
    last_seen: String,
}

impl DeviceBuilder {
    fn new(now: &str) -> Self {
        Self {
            ips: HashSet::new(),
            macs: HashSet::new(),
            interface: None,
            hostnames: HashSet::new(),
            instances: HashSet::new(),
            mdns_services: HashSet::new(),
            ssdp_services: HashSet::new(),
            vendor: None,
            sources: HashSet::new(),
            first_seen: now.to_string(),
            last_seen: now.to_string(),
        }
    }

    fn touch(&mut self, now: &str) {
        self.last_seen = now.to_string();
    }

    fn to_record(mut self) -> DeviceRecord {
        let (category, confidence, confidence_sources) = classify_device(&self);

        let mut ips = self
            .ips
            .drain()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>();
        ips.sort();

        let mut macs = self.macs.drain().collect::<Vec<_>>();
        macs.sort();

        let mut observed_hostnames = self.hostnames.drain().collect::<Vec<_>>();
        observed_hostnames.sort();

        let mut observed_instances = self.instances.drain().collect::<Vec<_>>();
        observed_instances.sort();

        let mut observed_mdns_services = self.mdns_services.drain().collect::<Vec<_>>();
        observed_mdns_services.sort();

        let mut observed_ssdp_services = self.ssdp_services.drain().collect::<Vec<_>>();
        observed_ssdp_services.sort();

        DeviceRecord {
            ips,
            macs,
            interface: self.interface,
            observed_hostnames,
            observed_instances,
            observed_mdns_services,
            observed_ssdp_services,
            vendor: self.vendor,
            category,
            confidence,
            confidence_sources,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
        }
    }
}

#[derive(Debug)]
struct Inventory {
    devices: Vec<DeviceBuilder>,
}

impl Inventory {
    fn new() -> Self {
        Self { devices: Vec::new() }
    }

    fn find_by_ip_or_mac(&self, ip: Option<Ipv4Addr>, mac: Option<&str>) -> Option<usize> {
        self.devices.iter().position(|device| {
            let ip_match = ip.map(|x| device.ips.contains(&x)).unwrap_or(false);
            let mac_match = mac
                .map(|x| device.macs.contains(&normalize_mac(x)))
                .unwrap_or(false);
            ip_match || mac_match
        })
    }

    fn upsert(&mut self, ip: Option<Ipv4Addr>, mac: Option<&str>, now: &str) -> usize {
        if let Some(index) = self.find_by_ip_or_mac(ip, mac) {
            self.devices[index].touch(now);
            return index;
        }

        let mut builder = DeviceBuilder::new(now);
        if let Some(address) = ip {
            builder.ips.insert(address);
        }
        if let Some(addr) = mac {
            builder.macs.insert(normalize_mac(addr));
        }

        self.devices.push(builder);
        self.devices.len() - 1
    }

    fn records(self) -> Vec<DeviceRecord> {
        self.devices
            .into_iter()
            .map(DeviceBuilder::to_record)
            .collect::<Vec<_>>()
    }
}

fn main() {
    let started = Instant::now();
    let config = parse_runtime_config();
    let listen_seconds = config.listen_seconds;
    let output_dir = ensure_output_dir(&config.output_dir);

    println!("NetID-LXC passive inventory run started at {}", now_iso());
    println!("Inventory output directory: {}", output_dir.display());

    println!("[1/8] Discovering UP interfaces and directly-connected IPv4 subnets...");
    let interfaces = discover_interfaces();
    if interfaces.is_empty() {
        eprintln!("No UP interfaces with IPv4 addresses found.");
        std::process::exit(1);
    }

    for iface in &interfaces {
        println!(
            "  - iface={} mac={} ip={}/{} netmask={} subnet={}",
            iface.name,
            iface.mac.as_deref().unwrap_or("unknown"),
            iface.ip,
            iface.prefix,
            iface.netmask,
            iface.subnet
        );
    }

    let estimated_seconds = estimate_runtime_seconds(listen_seconds, interfaces.len());
    println!(
        "Estimated runtime: ~{}s (passive listen {}s, reverse DNS capped, no active probing)",
        estimated_seconds, listen_seconds
    );

    println!("[2/8] Reading IPv4 neighbor/ARP tables...");
    let mut neighbors = collect_neighbors(false);
    if neighbors.len() < 2 {
        println!("  Neighbor table sparse, taking a light second snapshot...");
        for entry in collect_neighbors(true) {
            if !neighbors
                .iter()
                .any(|existing| existing.ip == entry.ip && existing.interface == entry.interface)
            {
                neighbors.push(entry);
            }
        }
    }
    println!("  Collected {} neighbor entries", neighbors.len());

    println!("[3/8] Loading offline OUI vendor database...");
    let oui_db = load_oui_database();
    println!("  Loaded {} OUI prefixes", oui_db.len());

    println!("[4/8] Parsing local DHCP leases/log hints...");
    let dhcp_observations = collect_dhcp_observations();
    println!("  Parsed {} DHCP observations", dhcp_observations.len());

    println!("[5/8] Passive discovery (mDNS + optional SSDP) for up to {}s...", listen_seconds);
    let (mdns_observations, ssdp_observations) = passive_service_listen(listen_seconds);
    println!(
        "  Captured {} mDNS hints and {} SSDP hints",
        mdns_observations.len(),
        ssdp_observations.len()
    );

    let mut inventory = Inventory::new();
    let now = now_iso();

    for n in &neighbors {
        let idx = inventory.upsert(Some(n.ip), n.mac.as_deref(), &now);
        let device = &mut inventory.devices[idx];
        device.ips.insert(n.ip);
        if let Some(mac) = &n.mac {
            device.macs.insert(normalize_mac(mac));
            if let Some(vendor) = lookup_vendor(&oui_db, mac) {
                device.vendor = Some(vendor);
            }
            device.sources.insert("neighbor_mac".to_string());
        }
        if let Some(interface) = &n.interface {
            device.interface = Some(interface.clone());
        }
        if let Some(state) = &n.state {
            device.sources.insert(format!("neighbor_state:{state}"));
        }
    }

    for lease in &dhcp_observations {
        let idx = inventory.upsert(lease.ip, lease.mac.as_deref(), &now);
        let device = &mut inventory.devices[idx];
        if let Some(ip) = lease.ip {
            device.ips.insert(ip);
        }
        if let Some(mac) = &lease.mac {
            device.macs.insert(normalize_mac(mac));
            if let Some(vendor) = lookup_vendor(&oui_db, mac) {
                device.vendor = Some(vendor);
            }
        }
        if let Some(hostname) = &lease.hostname {
            device.hostnames.insert(hostname.clone());
            device.sources.insert("dhcp_hostname".to_string());
        }
        device.sources.insert(format!("dhcp_source:{}", lease.source));
    }

    for mdns in &mdns_observations {
        let idx = inventory.upsert(mdns.source_ip, None, &now);
        let device = &mut inventory.devices[idx];
        if let Some(ip) = mdns.source_ip {
            device.ips.insert(ip);
        }
        if let Some(hostname) = &mdns.hostname {
            device.hostnames.insert(hostname.clone());
            device.sources.insert("mdns_hostname".to_string());
        }
        if let Some(instance) = &mdns.instance {
            device.instances.insert(instance.clone());
            device.sources.insert("mdns_instance".to_string());
        }
        if let Some(service_type) = &mdns.service_type {
            device.mdns_services.insert(service_type.clone());
            device.sources.insert("mdns_service".to_string());
        }
    }

    for ssdp in &ssdp_observations {
        let idx = inventory.upsert(ssdp.source_ip, None, &now);
        let device = &mut inventory.devices[idx];
        if let Some(ip) = ssdp.source_ip {
            device.ips.insert(ip);
        }
        if let Some(service_type) = &ssdp.service_type {
            device.ssdp_services.insert(service_type.clone());
            device.sources.insert("ssdp_service".to_string());
        }
        if let Some(identifier) = &ssdp.identifier {
            device.instances.insert(identifier.clone());
            device.sources.insert("ssdp_identifier".to_string());
        }
        if let Some(friendly) = &ssdp.friendly_name {
            device.hostnames.insert(friendly.clone());
            device.sources.insert("ssdp_friendly_name".to_string());
        }
    }

    println!("[6/8] Limited reverse DNS lookup for discovered IPs...");
    let rdns_hints = reverse_dns_hints(
        &inventory
            .devices
            .iter()
            .flat_map(|d| d.ips.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>(),
    );
    println!("  Added {} reverse-DNS hints", rdns_hints.len());

    for device in &mut inventory.devices {
        let mut added = false;
        for ip in device.ips.clone() {
            if let Some(host) = rdns_hints.get(&ip) {
                device.hostnames.insert(host.clone());
                added = true;
            }
        }
        if added {
            device.sources.insert("reverse_dns".to_string());
            device.touch(&now_iso());
        }

        if device.vendor.is_none() {
            for mac in &device.macs {
                if let Some(vendor) = lookup_vendor(&oui_db, mac) {
                    device.vendor = Some(vendor);
                    break;
                }
            }
        }
    }

    println!("[7/8] Classifying devices with confidence scoring...");
    let mut records = inventory.records();
    records.sort_by_key(|device| device.ips.first().cloned().unwrap_or_default());

    println!("[8/8] Rendering table and writing JSON output...");
    print_inventory_table(&records);
    let (latest_path, run_path) = write_inventory_json(&records, &output_dir)
        .unwrap_or_else(|error| {
            eprintln!("Failed to write JSON output: {error}");
            std::process::exit(1);
        });

    println!("Saved latest inventory: {}", latest_path.display());
    println!("Saved run snapshot: {}", run_path.display());

    println!(
        "Run complete in {:.1}s. Devices discovered: {}",
        started.elapsed().as_secs_f64(),
        records.len()
    );
}

fn parse_runtime_config() -> RuntimeConfig {
    let args = std::env::args().collect::<Vec<_>>();
    let listen_seconds = if args.len() < 2 {
        DEFAULT_LISTEN_SECONDS
    } else {
        let parsed = args[1].parse::<u64>().unwrap_or(DEFAULT_LISTEN_SECONDS);
        parsed.min(MAX_LISTEN_SECONDS)
    };

    let output_dir = if let Some(arg_path) = args.get(2) {
        PathBuf::from(arg_path)
    } else if let Ok(env_path) = std::env::var("NETID_LXC_OUTPUT_DIR") {
        PathBuf::from(env_path)
    } else {
        PathBuf::from(DEFAULT_OUTPUT_DIR)
    };

    RuntimeConfig {
        listen_seconds,
        output_dir,
    }
}

fn ensure_output_dir(preferred: &Path) -> PathBuf {
    if fs::create_dir_all(preferred).is_ok() {
        return preferred.to_path_buf();
    }

    let fallback = PathBuf::from("./output");
    let _ = fs::create_dir_all(&fallback);
    fallback
}

fn write_inventory_json(records: &[DeviceRecord], output_dir: &Path) -> Result<(PathBuf, PathBuf), String> {
    let json = serde_json::to_string_pretty(records)
        .map_err(|error| format!("unable to serialize JSON: {error}"))?;

    let timestamp = Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let latest = output_dir.join("latest.json");
    let run = output_dir.join(format!("run-{timestamp}.json"));

    fs::write(&latest, &json)
        .map_err(|error| format!("unable to write {}: {error}", latest.display()))?;
    fs::write(&run, &json)
        .map_err(|error| format!("unable to write {}: {error}", run.display()))?;

    Ok((latest, run))
}

fn print_inventory_table(records: &[DeviceRecord]) {
    println!("");
    println!("Discovered Devices");

    let headers = [
        "IP",
        "MAC",
        "HOSTNAME",
        "VENDOR",
        "CATEGORY",
        "CONF",
        "IFACE",
        "SERVICES",
    ];

    let mut rows = Vec::new();
    for record in records {
        let ip = pick_first_or_dash(&record.ips);
        let mac = pick_first_or_dash(&record.macs);
        let hostname = pick_first_or_dash(&record.observed_hostnames);
        let vendor = record.vendor.clone().unwrap_or_else(|| "-".to_string());
        let category = record.category.clone();
        let confidence = record.confidence.clone();
        let iface = record.interface.clone().unwrap_or_else(|| "-".to_string());

        let mut services = record.observed_mdns_services.clone();
        services.extend(record.observed_ssdp_services.clone());
        services.sort();
        services.dedup();
        let service_text = if services.is_empty() {
            "-".to_string()
        } else {
            services.join(",")
        };

        rows.push(vec![ip, mac, hostname, vendor, category, confidence, iface, service_text]);
    }

    let max_widths = [15usize, 17, 24, 18, 18, 6, 10, 26];
    let mut widths = headers
        .iter()
        .enumerate()
        .map(|(i, h)| h.len().min(max_widths[i]))
        .collect::<Vec<_>>();

    for row in &rows {
        for (i, value) in row.iter().enumerate() {
            widths[i] = widths[i].max(value.len().min(max_widths[i]));
        }
    }

    println!("{}", render_row(&headers.map(|h| h.to_string()), &widths));
    println!("{}", render_separator(&widths));

    for row in rows {
        let clipped = row
            .iter()
            .enumerate()
            .map(|(i, value)| clip(value, max_widths[i]))
            .collect::<Vec<_>>();
        println!("{}", render_row(&clipped, &widths));
    }
    println!("");
}

fn render_row(values: &[String], widths: &[usize]) -> String {
    let mut out = String::new();
    out.push('|');
    for (value, width) in values.iter().zip(widths.iter()) {
        out.push(' ');
        out.push_str(&format!("{value:<width$}", width = *width));
        out.push(' ');
        out.push('|');
    }
    out
}

fn render_separator(widths: &[usize]) -> String {
    let mut out = String::new();
    out.push('+');
    for width in widths {
        out.push_str(&"-".repeat(width + 2));
        out.push('+');
    }
    out
}

fn clip(value: &str, max: usize) -> String {
    let char_count = value.chars().count();
    if char_count <= max {
        return value.to_string();
    }
    if max <= 3 {
        return value.chars().take(max).collect::<String>();
    }
    let mut clipped = value.chars().take(max - 3).collect::<String>();
    clipped.push_str("...");
    clipped
}

fn pick_first_or_dash(values: &[String]) -> String {
    values.first().cloned().unwrap_or_else(|| "-".to_string())
}

fn estimate_runtime_seconds(listen_seconds: u64, interface_count: usize) -> u64 {
    let interface_overhead = (interface_count as u64).min(6);
    listen_seconds + interface_overhead + 8
}

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn discover_interfaces() -> Vec<InterfaceInfo> {
    let mut interfaces = Vec::new();
    let mut up_links = HashSet::new();

    if let Ok(output) = run_command("ip", &["-o", "link", "show", "up"]) {
        for line in output.lines() {
            if let Some((_, rest)) = line.split_once(':') {
                let name = rest.trim().split(':').next().unwrap_or_default().trim();
                if !name.is_empty() {
                    up_links.insert(name.to_string());
                }
            }
        }
    }

    let addr_output = run_command("ip", &["-o", "-4", "addr", "show", "up"])
        .or_else(|_| run_command("ip", &["-o", "-4", "addr", "show"]))
        .unwrap_or_default();

    for line in addr_output.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 4 {
            continue;
        }

        let iface = parts[1].trim_end_matches(':');
        if !up_links.is_empty() && !up_links.contains(iface) {
            continue;
        }

        let inet_pos = parts.iter().position(|p| *p == "inet");
        let Some(pos) = inet_pos else {
            continue;
        };

        let cidr = parts.get(pos + 1).copied().unwrap_or_default();
        let Some((ip_str, prefix_str)) = cidr.split_once('/') else {
            continue;
        };

        let Ok(ip) = ip_str.parse::<Ipv4Addr>() else {
            continue;
        };

        let Ok(prefix) = prefix_str.parse::<u8>() else {
            continue;
        };

        let mask = prefix_to_mask(prefix);
        let netmask = Ipv4Addr::from(mask);
        let network = Ipv4Addr::from(u32::from(ip) & mask);
        let subnet = format!("{network}/{prefix}");
        let mac = read_interface_mac(iface);

        interfaces.push(InterfaceInfo {
            name: iface.to_string(),
            mac,
            ip,
            prefix,
            netmask,
            subnet,
        });
    }

    interfaces
}

fn prefix_to_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }

    let prefix = prefix_len as u32;
    (!0u32).checked_shl(32 - prefix).unwrap_or(0)
}

fn read_interface_mac(name: &str) -> Option<String> {
    let path = format!("/sys/class/net/{name}/address");
    let value = fs::read_to_string(path).ok()?;
    let mac = normalize_mac(value.trim());
    if mac.len() == 17 {
        Some(mac)
    } else {
        None
    }
}

fn collect_neighbors(include_all_states: bool) -> Vec<NeighborEntry> {
    let args = if include_all_states {
        vec!["-4", "neigh", "show", "nud", "all"]
    } else {
        vec!["-4", "neigh", "show"]
    };

    let mut entries = Vec::new();

    if let Ok(output) = run_command("ip", &args) {
        for line in output.lines() {
            if let Some(entry) = parse_neighbor_line(line) {
                entries.push(entry);
            }
        }
    }

    if let Ok(arp_file) = fs::read_to_string("/proc/net/arp") {
        for line in arp_file.lines().skip(1) {
            let cols = line.split_whitespace().collect::<Vec<_>>();
            if cols.len() < 6 {
                continue;
            }

            let Ok(ip) = cols[0].parse::<Ipv4Addr>() else {
                continue;
            };

            let mac = if cols[3] == "00:00:00:00:00:00" {
                None
            } else {
                Some(normalize_mac(cols[3]))
            };

            let interface = Some(cols[5].to_string());
            let already_present = entries
                .iter()
                .any(|e| e.ip == ip && e.interface == interface);

            if !already_present {
                entries.push(NeighborEntry {
                    ip,
                    mac,
                    interface,
                    state: Some("ARP".to_string()),
                });
            }
        }
    }

    entries
}

fn parse_neighbor_line(line: &str) -> Option<NeighborEntry> {
    let cols = line.split_whitespace().collect::<Vec<_>>();
    if cols.len() < 4 {
        return None;
    }

    let ip = cols[0].parse::<Ipv4Addr>().ok()?;
    let mut mac = None;
    let mut interface = None;
    let mut state = None;

    for i in 0..cols.len() {
        if cols[i] == "dev" {
            interface = cols.get(i + 1).map(|v| v.to_string());
        }
        if cols[i] == "lladdr" {
            mac = cols.get(i + 1).map(|v| normalize_mac(v));
        }
    }

    if let Some(last) = cols.last() {
        state = Some((*last).to_string());
    }

    Some(NeighborEntry {
        ip,
        mac,
        interface,
        state,
    })
}

fn load_oui_database() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let candidate_paths = vec![
        "/usr/share/ieee-data/oui.txt",
        "/usr/share/misc/oui.txt",
        "/var/lib/ieee-data/oui.csv",
    ];

    for path in candidate_paths {
        if let Ok(content) = fs::read_to_string(path) {
            parse_oui_content(&content, &mut map);
        }
    }

    if map.is_empty() {
        let fallback = [
            ("00163E", "Cisco Systems"),
            ("18B430", "Nest Labs"),
            ("3C5A37", "Google"),
            ("A4CF12", "Apple"),
            ("B827EB", "Raspberry Pi"),
            ("D850E6", "Amazon Technologies"),
            ("E04F43", "Ubiquiti"),
        ];

        for (prefix, vendor) in fallback {
            map.insert(prefix.to_string(), vendor.to_string());
        }
    }

    map
}

fn parse_oui_content(content: &str, map: &mut HashMap<String, String>) {
    let hex_re = Regex::new(r"^([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$")
        .expect("valid OUI regex");

    let csv_re = Regex::new(r"^([0-9A-Fa-f]{6})[,;\t ]+(.+)$").expect("valid CSV OUI regex");

    for line in content.lines() {
        if let Some(caps) = hex_re.captures(line) {
            let prefix = format!(
                "{}{}{}",
                caps.get(1).map(|x| x.as_str()).unwrap_or(""),
                caps.get(2).map(|x| x.as_str()).unwrap_or(""),
                caps.get(3).map(|x| x.as_str()).unwrap_or("")
            )
            .to_uppercase();
            let vendor = caps
                .get(4)
                .map(|x| x.as_str().trim().to_string())
                .unwrap_or_default();
            if !prefix.is_empty() && !vendor.is_empty() {
                map.entry(prefix).or_insert(vendor);
            }
            continue;
        }

        if let Some(caps) = csv_re.captures(line) {
            let prefix = caps
                .get(1)
                .map(|x| x.as_str().to_uppercase())
                .unwrap_or_default();
            let vendor = caps
                .get(2)
                .map(|x| x.as_str().trim().trim_matches('"').to_string())
                .unwrap_or_default();
            if prefix.len() == 6 && !vendor.is_empty() {
                map.entry(prefix).or_insert(vendor);
            }
        }
    }
}

fn normalize_mac(input: &str) -> String {
    let hex = input
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();

    if hex.len() != 12 {
        return input.to_lowercase();
    }

    let mut result = String::with_capacity(17);
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if index > 0 {
            result.push(':');
        }
        result.push(chunk[0] as char);
        result.push(chunk[1] as char);
    }

    result.to_lowercase()
}

fn lookup_vendor(oui_db: &HashMap<String, String>, mac: &str) -> Option<String> {
    let prefix = mac
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .collect::<String>()
        .to_uppercase();
    if prefix.len() < 6 {
        return None;
    }

    oui_db.get(&prefix[..6]).cloned()
}

fn collect_dhcp_observations() -> Vec<DhcpObservation> {
    let mut files = Vec::new();

    files.extend(existing_files(vec![
        "/var/lib/dhcp/dhclient.leases",
        "/var/lib/dhcp/dhclient.eth0.leases",
        "/var/lib/NetworkManager/dhclient.leases",
        "/var/lib/systemd/netif/leases/1",
        "/var/log/syslog",
        "/var/log/messages",
    ]));

    files.extend(scan_dir_files("/var/lib/systemd/netif/leases"));
    files.extend(scan_dir_files("/var/lib/NetworkManager"));

    files.sort();
    files.dedup();

    let ip_re = Regex::new(r"\b((?:\d{1,3}\.){3}\d{1,3})\b").expect("valid IP regex");
    let mac_re = Regex::new(r"\b([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\b").expect("valid MAC regex");
    let host_re = Regex::new(r#"(?:host-?name|hostname|client_hostname)\s*[= ]\s*\"?([A-Za-z0-9._-]+)\"?"#)
        .expect("valid hostname regex");

    let mut observations = Vec::new();

    for file in files {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };

        for line in content.lines() {
            let lower = line.to_ascii_lowercase();
            if !(lower.contains("dhcp") || lower.contains("lease") || lower.contains("bound")) {
                continue;
            }

            let ip = ip_re
                .captures(line)
                .and_then(|c| c.get(1))
                .and_then(|m| m.as_str().parse::<Ipv4Addr>().ok());

            let mac = mac_re
                .captures(line)
                .and_then(|c| c.get(1))
                .map(|m| normalize_mac(m.as_str()));

            let hostname = host_re
                .captures(line)
                .and_then(|c| c.get(1))
                .map(|h| h.as_str().to_string());

            if ip.is_none() && mac.is_none() && hostname.is_none() {
                continue;
            }

            observations.push(DhcpObservation {
                ip,
                mac,
                hostname,
                source: file.to_string_lossy().to_string(),
            });
        }
    }

    observations
}

fn existing_files(candidates: Vec<&str>) -> Vec<PathBuf> {
    candidates
        .into_iter()
        .map(PathBuf::from)
        .filter(|path| path.exists() && path.is_file())
        .collect::<Vec<_>>()
}

fn scan_dir_files(path: &str) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = fs::read_dir(path) else {
        return files;
    };

    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            files.push(p);
        }
    }

    files
}

fn passive_service_listen(listen_seconds: u64) -> (Vec<MdnsObservation>, Vec<SsdpObservation>) {
    let duration = Duration::from_secs(listen_seconds);
    let started = Instant::now();

    let mdns_socket = bind_udp_multicast("0.0.0.0:5353", Ipv4Addr::new(224, 0, 0, 251));
    let ssdp_socket = bind_udp_multicast("0.0.0.0:1900", Ipv4Addr::new(239, 255, 255, 250));

    if mdns_socket.is_none() {
        eprintln!("  Unable to bind mDNS listener on UDP/5353");
    }

    let mut mdns = Vec::new();
    let mut ssdp = Vec::new();

    let mut mdns_buf = [0u8; 2048];
    let mut ssdp_buf = [0u8; 4096];
    let mut last_progress = Instant::now();

    while started.elapsed() < duration {
        if let Some(sock) = &mdns_socket {
            match sock.recv_from(&mut mdns_buf) {
                Ok((size, src)) => {
                    mdns.extend(parse_mdns_packet(&mdns_buf[..size], src));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => {}
            }
        }

        if let Some(sock) = &ssdp_socket {
            match sock.recv_from(&mut ssdp_buf) {
                Ok((size, src)) => {
                    if let Some(obs) = parse_ssdp_packet(&ssdp_buf[..size], src) {
                        ssdp.push(obs);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => {}
            }
        }

        if last_progress.elapsed() >= Duration::from_secs(10) {
            let elapsed = started.elapsed().as_secs();
            println!("  Passive listen alive: {}s/{}s", elapsed, listen_seconds);
            last_progress = Instant::now();
        }
    }

    (mdns, ssdp)
}

fn bind_udp_multicast(bind_addr: &str, group: Ipv4Addr) -> Option<UdpSocket> {
    let socket = UdpSocket::bind(bind_addr).ok()?;
    let _ = socket.set_nonblocking(true);
    let _ = socket.set_read_timeout(Some(Duration::from_millis(300)));
    let _ = socket.join_multicast_v4(&group, &Ipv4Addr::UNSPECIFIED);
    Some(socket)
}

fn parse_mdns_packet(packet: &[u8], source: SocketAddr) -> Vec<MdnsObservation> {
    if packet.len() < 12 {
        return Vec::new();
    }

    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let nscount = u16::from_be_bytes([packet[8], packet[9]]) as usize;
    let arcount = u16::from_be_bytes([packet[10], packet[11]]) as usize;

    let mut cursor = 12usize;

    for _ in 0..qdcount {
        if read_dns_name(packet, &mut cursor, 0).is_none() {
            return Vec::new();
        }
        if cursor + 4 > packet.len() {
            return Vec::new();
        }
        cursor += 4;
    }

    let total_records = ancount + nscount + arcount;
    let mut observations = Vec::new();

    for _ in 0..total_records {
        let Some(name) = read_dns_name(packet, &mut cursor, 0) else {
            break;
        };

        if cursor + 10 > packet.len() {
            break;
        }

        let rtype = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
        let _class = u16::from_be_bytes([packet[cursor + 2], packet[cursor + 3]]);
        let _ttl = u32::from_be_bytes([
            packet[cursor + 4],
            packet[cursor + 5],
            packet[cursor + 6],
            packet[cursor + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[cursor + 8], packet[cursor + 9]]) as usize;
        cursor += 10;

        if cursor + rdlength > packet.len() {
            break;
        }

        let rdata_start = cursor;
        let source_ip = match source.ip() {
            IpAddr::V4(ipv4) => Some(ipv4),
            IpAddr::V6(_) => None,
        };

        match rtype {
            12 => {
                let mut ptr_cursor = rdata_start;
                if let Some(target) = read_dns_name(packet, &mut ptr_cursor, 0) {
                    let service = extract_service_type(&name);
                    let instance = extract_instance_name(&target, service.as_deref());
                    observations.push(MdnsObservation {
                        source_ip,
                        hostname: None,
                        instance,
                        service_type: service,
                    });
                }
            }
            33 => {
                if rdlength >= 6 {
                    let mut srv_cursor = rdata_start + 6;
                    if let Some(target) = read_dns_name(packet, &mut srv_cursor, 0) {
                        observations.push(MdnsObservation {
                            source_ip,
                            hostname: Some(strip_local_suffix(&target)),
                            instance: extract_instance_name(&name, extract_service_type(&name).as_deref()),
                            service_type: extract_service_type(&name),
                        });
                    }
                }
            }
            1 => {
                if rdlength == 4 {
                    let ip = Ipv4Addr::new(
                        packet[rdata_start],
                        packet[rdata_start + 1],
                        packet[rdata_start + 2],
                        packet[rdata_start + 3],
                    );
                    observations.push(MdnsObservation {
                        source_ip: Some(ip),
                        hostname: Some(strip_local_suffix(&name)),
                        instance: None,
                        service_type: None,
                    });
                }
            }
            _ => {}
        }

        cursor += rdlength;
    }

    observations
}

fn read_dns_name(packet: &[u8], cursor: &mut usize, depth: usize) -> Option<String> {
    if depth > 8 || *cursor >= packet.len() {
        return None;
    }

    let mut labels = Vec::new();
    let mut jumped = false;
    let mut position = *cursor;

    loop {
        if position >= packet.len() {
            return None;
        }

        let len = packet[position];
        if len == 0 {
            position += 1;
            if !jumped {
                *cursor = position;
            }
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if position + 1 >= packet.len() {
                return None;
            }
            let offset = (((len as usize) & 0x3F) << 8) | packet[position + 1] as usize;
            if !jumped {
                *cursor = position + 2;
            }
            position = offset;
            jumped = true;
            if depth + labels.len() > 24 {
                return None;
            }
            continue;
        }

        let label_len = len as usize;
        let start = position + 1;
        let end = start + label_len;
        if end > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[start..end]).ok()?.to_string();
        labels.push(label);
        position = end;
    }

    Some(labels.join("."))
}

fn extract_service_type(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let labels = lower.split('.').collect::<Vec<_>>();
    for i in 0..labels.len().saturating_sub(1) {
        if labels[i].starts_with('_') && (labels[i + 1] == "_tcp" || labels[i + 1] == "_udp") {
            return Some(format!("{}.{}", labels[i], labels[i + 1]));
        }
    }
    None
}

fn extract_instance_name(target: &str, service: Option<&str>) -> Option<String> {
    let Some(service_suffix) = service else {
        return None;
    };

    let lower_target = target.to_ascii_lowercase();
    let expected = format!(".{service_suffix}");
    if lower_target.ends_with(&expected) {
        let cut = target.len().saturating_sub(expected.len());
        let instance = target[..cut].trim_end_matches('.').to_string();
        if !instance.is_empty() {
            return Some(instance);
        }
    }

    None
}

fn strip_local_suffix(name: &str) -> String {
    name.trim_end_matches(".local")
        .trim_end_matches('.')
        .to_string()
}

fn parse_ssdp_packet(packet: &[u8], source: SocketAddr) -> Option<SsdpObservation> {
    let text = std::str::from_utf8(packet).ok()?;
    let mut headers = HashMap::new();

    for line in text.lines().skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let source_ip = match source.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    };

    let service_type = headers
        .get("st")
        .cloned()
        .or_else(|| headers.get("nt").cloned());
    let identifier = headers.get("usn").cloned();
    let friendly_name = headers.get("server").cloned();

    if source_ip.is_none() && service_type.is_none() && identifier.is_none() && friendly_name.is_none() {
        return None;
    }

    Some(SsdpObservation {
        source_ip,
        service_type,
        identifier,
        friendly_name,
    })
}

fn reverse_dns_hints(ips: &[Ipv4Addr]) -> HashMap<Ipv4Addr, String> {
    let mut unique = ips.to_vec();
    unique.sort();
    unique.dedup();
    if unique.len() > MAX_RDNS_TARGETS {
        unique.truncate(MAX_RDNS_TARGETS);
    }

    let queue = Arc::new(Mutex::new(VecDeque::from(unique)));
    let results = Arc::new(Mutex::new(HashMap::new()));
    let workers = RDNS_CONCURRENCY.max(1);

    let mut handles = Vec::new();
    for _ in 0..workers {
        let queue = Arc::clone(&queue);
        let results = Arc::clone(&results);

        handles.push(thread::spawn(move || {
            loop {
                let next = {
                    let mut guard = queue.lock().ok()?;
                    guard.pop_front()
                };

                let Some(ip) = next else {
                    break;
                };

                if let Some(host) = reverse_lookup_one(ip) {
                    if let Ok(mut guard) = results.lock() {
                        guard.insert(ip, host);
                    }
                }
            }
            Some(())
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    results.lock().map(|m| m.clone()).unwrap_or_default()
}

fn reverse_lookup_one(ip: Ipv4Addr) -> Option<String> {
    let ip_str = ip.to_string();

    let output = run_command("timeout", &["1", "getent", "hosts", &ip_str])
        .or_else(|_| run_command("getent", &["hosts", &ip_str]))
        .ok()?;

    for line in output.lines() {
        let cols = line.split_whitespace().collect::<Vec<_>>();
        if cols.len() >= 2 {
            return Some(cols[1].to_string());
        }
    }

    None
}

fn run_command(binary: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute {binary}: {error}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("{binary} {:?} failed: {stderr}", args));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn classify_device(device: &DeviceBuilder) -> (String, String, Vec<String>) {
    let has_dhcp_hostname = device.sources.contains("dhcp_hostname");
    let has_mdns_identity = device.sources.contains("mdns_hostname") || device.sources.contains("mdns_instance");
    let has_neighbor_mac = device.sources.contains("neighbor_mac") || !device.macs.is_empty();

    let mut evidence = Vec::new();
    if has_dhcp_hostname {
        evidence.push("dhcp_hostname".to_string());
    }
    if has_mdns_identity {
        evidence.push("mdns_identity".to_string());
    }
    if has_neighbor_mac {
        evidence.push("neighbor_mac".to_string());
    }
    if device.vendor.is_some() {
        evidence.push("oui_vendor".to_string());
    }

    let category = infer_category(device);

    let confidence = if has_dhcp_hostname && has_mdns_identity && has_neighbor_mac {
        "high".to_string()
    } else if (!device.mdns_services.is_empty() || !device.ssdp_services.is_empty()) && device.vendor.is_some() {
        evidence.push("service_plus_vendor".to_string());
        "medium".to_string()
    } else {
        "low".to_string()
    };

    (category, confidence, evidence)
}

fn infer_category(device: &DeviceBuilder) -> String {
    let mut hints = Vec::new();
    hints.extend(device.hostnames.iter().map(|h| h.to_ascii_lowercase()));
    hints.extend(device.instances.iter().map(|h| h.to_ascii_lowercase()));
    hints.extend(device.mdns_services.iter().map(|h| h.to_ascii_lowercase()));
    hints.extend(device.ssdp_services.iter().map(|h| h.to_ascii_lowercase()));
    if let Some(vendor) = &device.vendor {
        hints.push(vendor.to_ascii_lowercase());
    }

    let contains_any = |needles: &[&str]| -> bool {
        needles
            .iter()
            .any(|needle| hints.iter().any(|h| h.contains(needle)))
    };

    if contains_any(&["_ipp", "_printer", "laserjet", "hp-print", "brother"]) {
        return "printer".to_string();
    }
    if contains_any(&["_rtsp", "onvif", "hikvision", "dahua", "camera", "nvr"]) {
        return "camera/NVR".to_string();
    }
    if contains_any(&["_airplay", "_googlecast", "bravia", "roku", "appletv", "smarttv"]) {
        return "media/TV".to_string();
    }
    if contains_any(&["_smb", "_adisk", "synology", "qnap", "truenas", "nas"]) {
        return "NAS".to_string();
    }
    if contains_any(&["iphone", "android", "pixel", "galaxy"]) {
        return "phone".to_string();
    }
    if contains_any(&["laptop", "notebook", "desktop", "macbook", "workstation", "thinkpad"]) {
        return "workstation/laptop".to_string();
    }
    if contains_any(&["router", "gateway", "mikrotik", "ubiquiti", "netgear", "cisco", "tp-link", "asus"]) {
        return "AP/router".to_string();
    }
    if contains_any(&["hue", "hub", "homeassistant", "zigbee", "matter"]) {
        return "IoT hub".to_string();
    }

    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mac_addresses() {
        assert_eq!(normalize_mac("AABBCCDDEEFF"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(normalize_mac("aa-bb-cc-dd-ee-ff"), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parses_neighbor_line() {
        let line = "192.168.1.10 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE";
        let parsed = parse_neighbor_line(line).expect("neighbor parse");
        assert_eq!(parsed.ip, Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(parsed.interface.as_deref(), Some("eth0"));
        assert_eq!(parsed.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(parsed.state.as_deref(), Some("STALE"));
    }

    #[test]
    fn extracts_service_type() {
        assert_eq!(
            extract_service_type("My-Printer._ipp._tcp.local"),
            Some("_ipp._tcp".to_string())
        );
    }
}
