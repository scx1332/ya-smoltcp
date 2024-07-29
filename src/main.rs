mod utils;

use std::env;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use dns_parser::QueryType;
use pcap::{Capture, Device};
use smoltcp::{
    phy::DeviceCapabilities,
    wire::{EthernetAddress, IpAddress, IpCidr},
};
use std::os::fd::AsRawFd;
use smoltcp::phy::{Medium, TunTapInterface};
use tokio::io::{copy, split, AsyncReadExt, AsyncWriteExt};
use tokio_smoltcp::{device::AsyncDevice, smoltcp::iface, Net, NetConfig};

#[derive(Debug, Parser)]
struct Opt {
    device: String,
    #[clap(short, long, default_value = "00:01:02:03:04:05")]
    ethernet_addr: String,
    #[clap(short, long, default_value = "192.168.69.1/24")]
    ip_addr: String,
    #[clap(short, long, default_value = "192.168.69.100")]
    gateway: String,
}

fn get_by_device(device: Device) -> Result<impl AsyncDevice> {
    use std::io;
    use tokio_smoltcp::device::AsyncCapture;

    let cap = Capture::from_device(device.clone())
        .context("Failed to capture device")?
        .promisc(true)
        .immediate_mode(true)
        .timeout(5)
        .open()
        .context("Failed to open device")?;

    fn map_err(e: pcap::Error) -> io::Error {
        match e {
            pcap::Error::IoError(e) => e.into(),
            pcap::Error::TimeoutExpired => io::ErrorKind::WouldBlock.into(),
            other => io::Error::new(io::ErrorKind::Other, other),
        }
    }
    let mut caps = DeviceCapabilities::default();
    match caps.medium {
        smoltcp::phy::Medium::Ethernet => {
            println!("Detected medium: Ethernet");
        }
        _ => return Err(anyhow!("Unsupported medium")),
    }
    caps.max_burst_size = Some(100);
    caps.max_transmission_unit = 1500;


    let device = TunTapInterface::new("tap0", Medium::Ethernet).context("Failed to create tun/tap interface")?;
    //let fd = device.as_raw_fd();
    Ok(AsyncCapture::new(
        device,
        |d| {
            let r = d.receive().map_err(map_err).map(|p| p.to_vec());
            // eprintln!("recv {:?}", r);
            r
        },
        |d, pkt| {
            let r = d.sendpacket(pkt).map_err(map_err);
            // eprintln!("send {:?}", r);
            r
        },
        caps,
    )
        .context("Failed to create async capture")?)
}


async fn async_main(opt: Opt) -> Result<()> {
    //print all devices
    for device in Device::list()? {
        println!("Device: {:?}", device);
    }
    let device = Device::list()?
        .into_iter()
        .find(|d| d.name == opt.device)
        .ok_or(anyhow!("Device not found"))?;
    let ethernet_addr: EthernetAddress = opt.ethernet_addr.parse().unwrap();
    let ip_addr: IpCidr = opt.ip_addr.parse().unwrap();
    let gateway: IpAddress = opt.gateway.parse().unwrap();

    let device = get_by_device(device)?;
    let mut interface_config = iface::Config::new(ethernet_addr.into());
    interface_config.random_seed = rand::random();
    let net = Net::new(
        device,
        NetConfig::new(interface_config, ip_addr, vec![gateway]),
    );

    let udp = net.udp_bind("0.0.0.0:0".parse()?).await?;
    println!("udp local_addr {:?}", udp.local_addr());
    let mut query_builder = dns_parser::Builder::new_query(1, true);
    query_builder.add_question(
        "www.baidu.com",
        false,
        QueryType::A,
        dns_parser::QueryClass::IN,
    );
    let query = query_builder.build().unwrap();
    udp.send_to(&query, "8.8.8.8:53".parse()?).await?;
    let mut answer = [0u8; 1024];
    let (size, _) = udp.recv_from(&mut answer).await?;
    let packet = dns_parser::Packet::parse(&answer[..size])?;
    println!("dns answer packet: {:#?}", packet);
    let dst_ip = packet
        .answers
        .iter()
        .filter_map(|a| match a.data {
            dns_parser::RData::A(dns_parser::rdata::A(ip)) => Some(ip),
            _ => None,
        })
        .next()
        .expect("No A record in response");

    println!("Connecting www.baidu.com");
    let mut tcp = net.tcp_connect((dst_ip, 80).into()).await?;
    println!("Connected");

    tcp.write_all(b"GET / HTTP/1.0\r\nHost: www.baidu.com\r\n\r\n")
        .await?;
    println!("Sent");

    let mut string = String::new();
    tcp.read_to_string(&mut string).await?;
    println!("read {}", string);

    let mut listener = net.tcp_bind("0.0.0.0:12345".parse()?).await?;
    loop {
        let (tcp, addr) = listener.accept().await?;
        println!("Accept from {:?}", addr);
        tokio::spawn(async move {
            let (mut tx, mut rx) = split(tcp);
            copy(&mut tx, &mut rx).await.unwrap();
        });
    }

    // Ok(())
}


#[tokio::main]
async fn main() -> Result<()> {
    env::set_var("RUST_LOG", env::var("RUST_LOG").unwrap_or("info".to_string()));
    env_logger::init();

    let opt = Opt::parse();
    if let Err(e) = async_main(opt).await {
        eprintln!("Error {:?}", e);
    }
    Ok(())
}
