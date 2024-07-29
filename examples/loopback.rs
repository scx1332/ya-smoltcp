mod utils;
use core::str;
use log::{debug, error, info};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, Loopback, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};


mod mock {
    use smoltcp::time::{Duration, Instant};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // should be AtomicU64 but that's unstable
    #[derive(Debug, Clone)]
    #[cfg_attr(feature = "defmt", derive(defmt::Format))]
    pub struct Clock(Arc<AtomicUsize>);

    impl Clock {
        pub fn new() -> Clock {
            Clock(Arc::new(AtomicUsize::new(0)))
        }

        pub fn advance(&self, duration: Duration) {
            self.0
                .fetch_add(duration.total_millis() as usize, Ordering::SeqCst);
        }

        pub fn elapsed(&self) -> Instant {
            Instant::from_millis(self.0.load(Ordering::SeqCst) as i64)
        }
    }
}

fn create_tcp_socket() -> tcp::Socket<'static> {
    let rx_buffer = vec![0; 1024];
    let tx_buffer = vec![0; 1024];
    let tcp_rx_buffer = tcp::SocketBuffer::new(rx_buffer);
    let tcp_tx_buffer = tcp::SocketBuffer::new(tx_buffer);
    tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
}

fn main() {
    let clock = mock::Clock::new();
    let device = Loopback::new(Medium::Ethernet);


    let mut device = {
        let clock = clock.clone();
        utils::setup_logging_with_clock("", move || clock.elapsed());

        let (mut opts, mut free) = utils::create_options();
        utils::add_middleware_options(&mut opts, &mut free);

        let mut matches = utils::parse_options(&opts, free);
        utils::parse_middleware_options(&mut matches, device, /*loopback=*/ true)
    };

    // Create interface
    let mut config = match device.capabilities().medium {
        Medium::Ethernet => {
            Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into())
        }
        Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
    };

    let mut iface = Interface::new(config, &mut device, Instant::now());
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
            .unwrap();
    });

    // Create sockets
    let server_socket = create_tcp_socket();

    let client_socket = create_tcp_socket();

    let mut sockets: [_; 2] = Default::default();
    let mut sockets = SocketSet::new(&mut sockets[..]);
    let server_handle = sockets.add(server_socket);
    let client_handle = sockets.add(client_socket);

    let mut did_listen = false;
    let mut did_connect = false;
    let mut done = false;
    while !done && clock.elapsed() < Instant::from_millis(10_000) {
        iface.poll(clock.elapsed(), &mut device, &mut sockets);

        let mut socket = sockets.get_mut::<tcp::Socket>(server_handle);
        if !socket.is_active() && !socket.is_listening() {
            if !did_listen {
                debug!("listening");
                socket.listen(1234).unwrap();
                did_listen = true;
            }
        }

        if socket.can_recv() {
            debug!(
                "got {:?}",
                socket.recv(|buffer| { (buffer.len(), str::from_utf8(buffer).unwrap()) })
            );
            socket.close();
            done = true;
        }

        let mut socket = sockets.get_mut::<tcp::Socket>(client_handle);
        let cx = iface.context();
        if !socket.is_open() {
            if !did_connect {
                debug!("connecting");
                socket
                    .connect(cx, (IpAddress::v4(127, 0, 0, 1), 1234), 65000)
                    .unwrap();
                did_connect = true;
            }
        }

        if socket.can_send() {
            debug!("sending");
            socket.send_slice(b"0123456789abcdef").unwrap();
            socket.close();
        }

        match iface.poll_delay(clock.elapsed(), &sockets) {
            Some(Duration::ZERO) => debug!("resuming"),
            Some(delay) => {
                debug!("sleeping for {} ms", delay);
                clock.advance(delay)
            }
            None => clock.advance(Duration::from_millis(1)),
        }
    }

    if done {
        info!("done")
    } else {
        error!("this is taking too long, bailing out")
    }
}