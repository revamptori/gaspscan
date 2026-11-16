//! Port-spec parsing ("22,80,1000-1010", "common", "all") and a small
//! built-in table of well-known TCP service names.

/// Well-known ports shown by `gaspscan ports` and `--ports common`.
pub const COMMON_PORTS: &[(u16, &str)] = &[
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "domain"),
    (67, "dhcps"),
    (68, "dhcpc"),
    (69, "tftp"),
    (80, "http"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "sunrpc"),
    (119, "nntp"),
    (123, "ntp"),
    (135, "msrpc"),
    (137, "netbios-ns"),
    (138, "netbios-dgm"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (161, "snmp"),
    (162, "snmptrap"),
    (179, "bgp"),
    (389, "ldap"),
    (427, "svrloc"),
    (443, "https"),
    (445, "microsoft-ds"),
    (465, "smtps"),
    (500, "isakmp"),
    (512, "exec"),
    (513, "login"),
    (514, "shell"),
    (515, "printer"),
    (520, "router"),
    (523, "ibm-db2"),
    (540, "uucp"),
    (548, "afp"),
    (554, "rtsp"),
    (587, "submission"),
    (631, "ipp"),
    (636, "ldaps"),
    (646, "ldp"),
    (873, "rsync"),
    (990, "ftps"),
    (993, "imaps"),
    (995, "pop3s"),
    (1025, "nfs-or-iis"),
    (1080, "socks"),
    (1194, "openvpn"),
    (1433, "ms-sql-s"),
    (1434, "ms-sql-m"),
    (1521, "oracle"),
    (1723, "pptp"),
    (1812, "radius"),
    (1900, "upnp"),
    (2049, "nfs"),
    (2082, "cpanel"),
    (2083, "cpanels"),
    (2181, "zookeeper"),
    (2222, "ms-dce"),
    (2375, "docker"),
    (2376, "docker-tls"),
    (2483, "oracle-tcps"),
    (3000, "ppp"),
    (3128, "squid"),
    (3306, "mysql"),
    (3389, "ms-wbt-server"),
    (4444, "krb524"),
    (4500, "nat-t-ike"),
    (5000, "upnp-alt"),
    (5432, "postgresql"),
    (5555, "freeciv"),
    (5631, "pcsnag"),
    (5666, "nrpe"),
    (5800, "vnc-http"),
    (5900, "vnc"),
    (6000, "x11"),
    (6379, "redis"),
    (6667, "irc"),
    (8000, "http-alt"),
    (8008, "http-alt"),
    (8080, "http-proxy"),
    (8081, "sunproxyadmin"),
    (8443, "https-alt"),
    (8888, "sun-answerbook"),
    (9000, "cslistener"),
    (9042, "cassandra"),
    (9092, "kafka"),
    (9200, "elasticsearch"),
    (9418, "git"),
    (27017, "mongodb"),
];

/// Look up the conventional service name for a TCP port, if known.
pub fn service_name(port: u16) -> Option<&'static str> {
    COMMON_PORTS
        .iter()
        .find(|&&(p, _)| p == port)
        .map(|&(_, name)| name)
}

/// The list used by the `common` port spec: exactly COMMON_PORTS in order.
pub fn common_port_list() -> Vec<u16> {
    COMMON_PORTS.iter().map(|&(p, _)| p).collect()
}

/// Parse a port specification into a sorted, de-duplicated list of ports.
///
/// Accepted forms:
///   "22"                      single port
///   "22,80,443"               comma-separated list
///   "1000-1010"               inclusive range
///   "22,1000-1010,443"        mixed
///   "common"                  built-in list of well-known ports
///   "all"                     1-65535
///
/// Returns an error message on invalid input.
pub fn parse_port_spec(spec: &str) -> Result<Vec<u16>, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("empty port specification".to_string());
    }
    if trimmed.eq_ignore_ascii_case("all") {
        return Ok((1u16..=65535).collect());
    }
    if trimmed.eq_ignore_ascii_case("common") {
        return Ok(common_port_list());
    }

    let mut ports: Vec<u16> = Vec::new();
    for token in trimmed.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(format!("empty item in port spec '{}'", spec));
        }
        match token.find('-') {
            Some(dash) => {
                let lo_s = token[..dash].trim();
                let hi_s = token[dash + 1..].trim();
                let lo = parse_port_number(lo_s, spec)?;
                let hi = parse_port_number(hi_s, spec)?;
                if lo > hi {
                    return Err(format!(
                        "invalid range '{}': start {} is greater than end {}",
                        token, lo, hi
                    ));
                }
                for p in lo..=hi {
                    ports.push(p);
                }
            }
            None => {
                ports.push(parse_port_number(token, spec)?);
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(format!("no ports in specification '{}'", spec));
    }
    Ok(ports)
}

fn parse_port_number(s: &str, spec: &str) -> Result<u16, String> {
    match s.parse::<u32>() {
        Ok(0) => Err(format!("port 0 is not valid in '{}'", spec)),
        Ok(n) if n <= 65535 => Ok(n as u16),
        Ok(n) => Err(format!("port {} out of range in '{}' (max 65535)", n, spec)),
        Err(_) => Err(format!("'{}' is not a valid port number in '{}'", s, spec)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_port() {
        assert_eq!(parse_port_spec("22").unwrap(), vec![22]);
    }

    #[test]
    fn parses_list_and_sorts() {
        assert_eq!(parse_port_spec("443,22,80").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn parses_inclusive_range() {
        assert_eq!(
            parse_port_spec("1000-1002").unwrap(),
            vec![1000, 1001, 1002]
        );
    }

    #[test]
    fn parses_mixed_spec() {
        assert_eq!(
            parse_port_spec("22,100-101,22,443").unwrap(),
            vec![22, 100, 101, 443]
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_port_spec("").is_err());
        assert!(parse_port_spec("abc").is_err());
        assert!(parse_port_spec("0").is_err());
        assert!(parse_port_spec("65536").is_err());
        assert!(parse_port_spec("100-90").is_err());
        assert!(parse_port_spec("22,,80").is_err());
        assert!(parse_port_spec("-5").is_err());
    }

    #[test]
    fn common_spec_has_well_known_entries() {
        let ports = parse_port_spec("common").unwrap();
        assert!(ports.contains(&22));
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
    }

    #[test]
    fn all_spec_covers_everything() {
        let ports = parse_port_spec("all").unwrap();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);
    }

    #[test]
    fn service_lookup_works() {
        assert_eq!(service_name(22), Some("ssh"));
        assert_eq!(service_name(443), Some("https"));
        assert_eq!(service_name(6), None);
    }
}
