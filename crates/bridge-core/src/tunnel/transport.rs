//! UDP transport for WireGuard tunnels.
//!
//! Wraps tokio's UdpSocket with the interface needed by the tunnel I/O loop.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

/// Async UDP transport for WireGuard packets.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    /// Bind to a local address. Use "0.0.0.0:0" for auto-assigned port.
    pub async fn bind(addr: &str) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self { socket })
    }

    /// Connect to a remote peer endpoint (sets the default send destination).
    pub async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.socket.connect(addr).await
    }

    /// Send a packet to the connected peer.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf).await
    }

    /// Receive a packet into the buffer. Returns number of bytes read.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf).await
    }

    /// Get the local address this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}
