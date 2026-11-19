//! A diagnostics read of the live flows: what each holds toward its peer.

use std::net::{Ipv4Addr, SocketAddr};

use sail_netstack::{
    emit_tcp_segment, parse_ip_packet, parse_tcp_segment, BudgetProfile, NetworkGeneration,
    ResourceLedger, SendControl, SeqNumber, TcpEvent, TcpFlags, TcpTable, TcpTableConfig,
};

fn packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgment: u32,
    flags: TcpFlags,
) -> Vec<u8> {
    emit_tcp_segment(
        source,
        destination,
        SendControl {
            sequence: SeqNumber::new(sequence),
            acknowledgment: SeqNumber::new(acknowledgment),
            flags,
            window: 32_000,
        },
        &[],
        64,
        1,
    )
    .unwrap()
}

/// A flow's sample shows what it sent and holds, and the oldest byte its
/// peer has not acknowledged, which moves as the peer acknowledges.
#[test]
fn a_flow_sample_follows_what_is_in_flight_and_acknowledged() {
    let ledger = ResourceLedger::new(BudgetProfile::Router.budget()).unwrap();
    let mut table = TcpTable::new(ledger, NetworkGeneration::new(1), TcpTableConfig::default());
    assert!(table.flow_samples().is_empty());

    let source = SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 40_000));
    let destination = SocketAddr::from((Ipv4Addr::new(10, 0, 1, 1), 443));
    let syn_ack = table
        .ingest(&packet(source, destination, 100, 0, TcpFlags::SYN))
        .unwrap();
    let syn_ack =
        parse_tcp_segment(parse_ip_packet(&syn_ack.outgoing[0], true).unwrap(), true).unwrap();
    let next = syn_ack.meta.sequence.wrapping_add(1).get();
    let accepted = table
        .ingest(&packet(source, destination, 101, next, TcpFlags::ACK))
        .unwrap();
    let token = match accepted.events.as_slice() {
        [TcpEvent::Accepted(connection)] => connection.token,
        events => panic!("unexpected events: {events:?}"),
    };
    table.accept(token).unwrap();

    let sent = table.write(token, &[1; 500]).unwrap();
    assert_eq!(sent.outgoing.len(), 1);
    let [sample] = table.flow_samples()[..] else {
        panic!("one flow")
    };
    assert_eq!(sample.send_unacked, next);
    assert_eq!(sample.in_flight, 500);
    assert_eq!(sample.send_buffered, 500);
    assert_eq!(sample.peer_window, 32_000);
    assert!(sample.congestion_window > 0);

    table
        .ingest(&packet(
            source,
            destination,
            101,
            next.wrapping_add(500),
            TcpFlags::ACK,
        ))
        .unwrap();
    let [acked] = table.flow_samples()[..] else {
        panic!("one flow")
    };
    assert_eq!(acked.id, sample.id);
    assert_eq!(acked.send_unacked.wrapping_sub(sample.send_unacked), 500);
    assert_eq!((acked.in_flight, acked.send_buffered), (0, 0));
}
