use qfilter::Filter;
use std::{fs::File, io::BufRead, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::UdpSocket, time::timeout};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let hash_set = read_denylist("denylist.txt")?;
    start_service(hash_set).await?;
    Ok(())
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
    let mut valid_entry_count = 0;

    for line in reader.lines() {
        let line = line?;
        let line = match line.split_once('#') {
            Some((before_comment, _)) => before_comment,
            None => &line,
        };
        let line = line.trim().to_lowercase();
        if !line.is_empty() {
            valid_entry_count += 1;
        }
    }

    let mut filter = DomainSet::new(valid_entry_count);
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let line = match line.split_once('#') {
            Some((before_comment, _)) => before_comment,
            None => &line,
        };
        let line = line.trim().to_lowercase();
        if !line.is_empty() {
            filter.insert(&line);
        }
    }
    Ok(filter)
}

async fn start_service(denylist: DomainSet) -> Result<(), std::io::Error> {
    let denylist = Arc::new(denylist);
    let socket = Arc::new(UdpSocket::bind(("0.0.0.0", 53)).await?);
    loop {
        let mut buf = [0u8; 512];
        let (len, src) = socket.recv_from(&mut buf).await?;
        let socket = Arc::clone(&socket);
        let denylist = Arc::clone(&denylist);
        tokio::spawn(async move {
            if let Err(e) =
                handle_request(&buf[0..len], src, &socket, &denylist).await
            {
                eprintln!("Error handling request from {}: {}", src, e);
            }
        });
    }
}

async fn handle_request(
    request: &[u8],
    source: SocketAddr,
    socket: &UdpSocket,
    denylist: &DomainSet,
) -> Result<(), Box<dyn std::error::Error>> {
    let domain = parse_dns_query(request)?;
    if in_denylist(&domain, denylist) {
        println!("{domain} blocked");
        let response = create_nxdomain_response(request)?;
        socket.send_to(&response, source).await?;
    } else {
        let response = forward_to_upstream(request).await?;
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

async fn forward_to_upstream(request: &[u8]) -> Result<Vec<u8>, &'static str> {
    const UPSTREAM_DNS: &str = "1.1.1.1:53";
    let upstream_addr: SocketAddr = UPSTREAM_DNS.parse().unwrap();
    let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();

    socket
        .send_to(request, upstream_addr)
        .await
        .map_err(|_| "Failed to forward")?;
    let mut response_buf = [0u8; 512];
    let response_size =
        timeout(Duration::from_secs(3), socket.recv(&mut response_buf))
            .await
            .map_err(|_| "Upstream DNS server timeout")?
            .map_err(|_| "Failed to receive response")?;

    Ok(response_buf[..response_size].to_vec())
}
