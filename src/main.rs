use clap::Parser;
use qfilter::Filter;
use std::{fs::File, io::BufRead, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let upstream_addr: SocketAddr = args.upstream_dns.parse()?;
    let hash_set = read_denylist(&args.denylist)?;
    start_service(hash_set, upstream_addr).await?;
    Ok(())
}

#[derive(Parser)]
#[clap(author, version, about)]
struct Args {
    /// Path to the denylist file
    #[clap(short, long, default_value = "denylist.txt")]
    denylist: String,

    /// Upstream DNS server address (e.g., "1.1.1.1:53")
    #[clap(short, long, default_value = "1.1.1.1:53")]
    upstream_dns: String,
}

struct DomainSet {
    set: Filter,
}

impl DomainSet {
    fn new(capacity: u64) -> Self {
        Self {
            set: Filter::new(capacity, 0.00000001).unwrap(),
        }
    }

    fn insert(&mut self, s: &str) {
        self.set.insert(s).unwrap();
    }

    fn contains(&self, s: &str) -> bool {
        self.set.contains(s)
    }
}

fn read_denylist(path: &str) -> std::io::Result<DomainSet> {
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);

    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let line = match line.split_once('#') {
            Some((before_comment, _)) => before_comment,
            None => &line,
        };
        let line = line.trim().to_lowercase();
        if !line.is_empty() {
            entries.push(line);
        }
    }

    let mut filter = DomainSet::new(entries.len() as u64);

    for entry in entries {
        filter.insert(&entry);
    }

    Ok(filter)
}

async fn start_service(
    denylist: DomainSet,
    upstream_dns: SocketAddr,
) -> Result<(), std::io::Error> {
    let denylist = Arc::new(denylist);
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", 53)).await?);
    let upstream_dns = Arc::new(upstream_dns.to_owned());
    loop {
        let mut buf = [0u8; 512];
        let (len, src) = socket.recv_from(&mut buf).await?;
        let socket = Arc::clone(&socket);
        let denylist = Arc::clone(&denylist);
        let upstream_dns = Arc::clone(&upstream_dns);
        tokio::spawn(async move {
            let _ = handle_request(
                &buf[0..len],
                src,
                &socket,
                &denylist,
                &upstream_dns,
            )
            .await;
        });
    }
}

async fn handle_request(
    request: &[u8],
    source: SocketAddr,
    socket: &UdpSocket,
    denylist: &DomainSet,
    upstream_dns: &SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let domain = parse_dns_query(request)?;
    if in_denylist(&domain, denylist) {
        let response = create_nxdomain_response(request)?;
        socket.send_to(&response, source).await?;
    } else {
        let response = forward_to_upstream(request, upstream_dns).await?;
        socket.send_to(&response, source).await?;
    }
    Ok(())
}

fn create_nxdomain_response(request: &[u8]) -> Result<Vec<u8>, &'static str> {
    if request.len() < 12 {
        return Err("Invalid DNS request");
    }
    let mut response = request.to_vec();
    response[2] |= 0x80;
    response[3] = (response[3] & 0xF0) | 0x03;
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    Ok(response)
}

fn in_denylist(domain: &str, denylist: &DomainSet) -> bool {
    let mut parts = domain.rsplit('.');
    let mut current = if let Some(part) = parts.next() {
        part.to_owned()
    } else {
        return false;
    };
    for part in parts {
        current = format!("{}.{}", part, current);
        if denylist.contains(&current) {
            return true;
        }
    }
    false
}

fn parse_dns_query(request: &[u8]) -> Result<String, &'static str> {
    if request.len() < 12 {
        return Err("Invalid DNS request");
    }

    let mut pos = 12;
    let mut domain = String::new();

    while pos < request.len() && request[pos] != 0 {
        let len = request[pos] as usize;
        pos += 1;

        if pos + len > request.len() {
            return Err("Invalid domain name in DNS request");
        }

        domain.push_str(
            std::str::from_utf8(&request[pos..pos + len])
                .map_err(|_| "Invalid UTF-8 in domain name")?,
        );
        domain.push('.');
        pos += len;
    }

    if domain.ends_with('.') {
        domain.pop();
    }

    Ok(domain)
}

async fn forward_to_upstream(
    request: &[u8],
    upstream_dns: &SocketAddr,
) -> Result<Vec<u8>, &'static str> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    socket
        .send_to(request, upstream_dns)
        .await
        .map_err(|_| "Failed to forward")?;
    let mut response_buf = [0u8; 512];
    let response_size =
        timeout(Duration::from_millis(300), socket.recv(&mut response_buf))
            .await
            .map_err(|_| "Upstream DNS server timeout")?
            .map_err(|_| "Failed to receive response")?;

    Ok(response_buf[..response_size].to_vec())
}
