use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;

fn main() {
    let network_arg = std::env::args().nth(1).unwrap_or_else(|| "192.168.1.0/24".to_string());

    let (network_address, prefix_len) = match parse_network(&network_arg) {
        Ok(values) => values,
        Err(error) => {
            eprintln!("Invalid network '{network_arg}': {error}");
            std::process::exit(2);
        }
    };

    let targets = enumerate_targets(network_address, prefix_len);
    let mut reachable = Vec::new();

    for target in targets {
        if ping_host(target) {
            reachable.push(target);
        }
    }

    if reachable.is_empty() {
        println!("No responsive hosts found for {network_arg}.");
    } else {
        for address in reachable {
            println!("{}", address);
        }
    }
}

fn ping_host(address: Ipv4Addr) -> bool {
    let target = address.to_string();
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "1", &target])
        .output();

    match output {
        Ok(result) => result.status.success(),
        Err(_) => false,
    }
}

fn parse_network(input: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address, prefix) = input
        .split_once('/')
        .ok_or_else(|| "expected CIDR notation like 192.168.1.0/24".to_string())?;

    let ip = Ipv4Addr::from_str(address)
        .map_err(|error| format!("invalid IPv4 address '{address}': {error}"))?;
    let prefix_len = prefix
        .parse::<u8>()
        .map_err(|error| format!("invalid prefix '{prefix}': {error}"))?;

    if prefix_len > 32 {
        return Err(format!("prefix '{prefix}' exceeds /32"));
    }

    Ok((ip, prefix_len))
}

fn enumerate_targets(network_address: Ipv4Addr, prefix_len: u8) -> Vec<Ipv4Addr> {
    let mask = prefix_to_mask(prefix_len);
    let network = u32::from(network_address) & mask;
    let broadcast = network | (!mask & u32::MAX);

    if prefix_len == 0 {
        return vec![Ipv4Addr::from(network)];
    }

    let start = if prefix_len >= 31 { network } else { network + 1 };
    let end = if prefix_len >= 31 { broadcast } else { broadcast - 1 };

    (start..=end)
        .map(Ipv4Addr::from)
        .collect::<Vec<_>>()
}

fn prefix_to_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }

    let prefix = prefix_len as u32;
    (!0u32).checked_shl(32 - prefix).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerates_hosts_for_a_class_c_network() {
        let targets = enumerate_targets(Ipv4Addr::new(192, 168, 1, 0), 24);

        assert_eq!(targets.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(targets.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
        assert_eq!(targets.len(), 254);
    }

    #[test]
    fn parses_cidr_values() {
        let parsed = parse_network("10.0.0.5/24").unwrap();
        assert_eq!(parsed, (Ipv4Addr::new(10, 0, 0, 5), 24));
    }
}
