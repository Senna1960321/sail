//! UDP through the outbound: a stream to `sp.v2.udp-over-tcp.arpa`, each
//! packet with its address.

use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::BytesMut;

use crate::adapter::*;
use crate::session::{Session, SocksAddrWireType};
use crate::transport::uot;

use super::client::Client;

pub struct Handler {
    pub client: Arc<Client>,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Reliable
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        tracing::trace!("handling outbound datagram");
        #[cfg(feature = "internal-udp-target-diagnostics")]
        let diagnostic_trace = crate::app::udp_target_diagnostics::current();
        #[cfg(feature = "internal-udp-target-diagnostics")]
        if let Some(trace) = &diagnostic_trace {
            trace.emit(trace.event(crate::app::udp_target_diagnostics::ANYTLS));
            trace.address(
                crate::app::udp_target_diagnostics::REQUEST,
                &sess.destination,
            );
        }
        let mut first = BytesMut::new();
        uot::magic_destination().write_buf(&mut first, SocksAddrWireType::PortLast);
        // Not connected: every packet names its address, so that one
        // session can reach any.
        uot::put_request(&mut first, false, &sess.destination);
        let stream = self.client.open_stream(sess, &first).await?;
        let datagram = uot::OutboundDatagram::new(stream, &sess.destination);
        #[cfg(feature = "internal-udp-target-diagnostics")]
        let datagram = datagram.with_diagnostic_trace(diagnostic_trace);
        Ok(Box::new(datagram))
    }
}
