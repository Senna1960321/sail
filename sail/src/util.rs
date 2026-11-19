pub mod rfc3339;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Compatibility accessors for hickory-proto 0.26's public message fields.
pub(crate) trait DnsMessageExt {
    fn id(&self) -> u16;
    fn message_type(&self) -> hickory_proto::op::MessageType;
    fn op_code(&self) -> hickory_proto::op::OpCode;
    fn recursion_desired(&self) -> bool;
    fn checking_disabled(&self) -> bool;
    fn response_code(&self) -> hickory_proto::op::ResponseCode;
    fn queries(&self) -> &[hickory_proto::op::Query];
    fn answers(&self) -> &[hickory_proto::rr::Record];
    fn name_servers(&self) -> &[hickory_proto::rr::Record];
    fn extensions(&self) -> &Option<hickory_proto::op::Edns>;
    fn extensions_mut(&mut self) -> &mut Option<hickory_proto::op::Edns>;
    fn set_id(&mut self, value: u16) -> &mut Self;
    fn set_message_type(&mut self, value: hickory_proto::op::MessageType) -> &mut Self;
    fn set_op_code(&mut self, value: hickory_proto::op::OpCode) -> &mut Self;
    fn set_recursion_desired(&mut self, value: bool) -> &mut Self;
    fn set_recursion_available(&mut self, value: bool) -> &mut Self;
    fn set_checking_disabled(&mut self, value: bool) -> &mut Self;
    fn set_response_code(&mut self, value: hickory_proto::op::ResponseCode) -> &mut Self;
}

impl DnsMessageExt for hickory_proto::op::Message {
    fn id(&self) -> u16 {
        self.metadata.id
    }
    fn message_type(&self) -> hickory_proto::op::MessageType {
        self.metadata.message_type
    }
    fn op_code(&self) -> hickory_proto::op::OpCode {
        self.metadata.op_code
    }
    fn recursion_desired(&self) -> bool {
        self.metadata.recursion_desired
    }
    fn checking_disabled(&self) -> bool {
        self.metadata.checking_disabled
    }
    fn response_code(&self) -> hickory_proto::op::ResponseCode {
        self.metadata.response_code
    }
    fn queries(&self) -> &[hickory_proto::op::Query] {
        &self.queries
    }
    fn answers(&self) -> &[hickory_proto::rr::Record] {
        &self.answers
    }
    fn name_servers(&self) -> &[hickory_proto::rr::Record] {
        &self.authorities
    }
    fn extensions(&self) -> &Option<hickory_proto::op::Edns> {
        &self.edns
    }
    fn extensions_mut(&mut self) -> &mut Option<hickory_proto::op::Edns> {
        &mut self.edns
    }
    fn set_id(&mut self, value: u16) -> &mut Self {
        self.metadata.id = value;
        self
    }
    fn set_message_type(&mut self, value: hickory_proto::op::MessageType) -> &mut Self {
        self.metadata.message_type = value;
        self
    }
    fn set_op_code(&mut self, value: hickory_proto::op::OpCode) -> &mut Self {
        self.metadata.op_code = value;
        self
    }
    fn set_recursion_desired(&mut self, value: bool) -> &mut Self {
        self.metadata.recursion_desired = value;
        self
    }
    fn set_recursion_available(&mut self, value: bool) -> &mut Self {
        self.metadata.recursion_available = value;
        self
    }
    fn set_checking_disabled(&mut self, value: bool) -> &mut Self {
        self.metadata.checking_disabled = value;
        self
    }
    fn set_response_code(&mut self, value: hickory_proto::op::ResponseCode) -> &mut Self {
        self.metadata.response_code = value;
        self
    }
}

use crate::{
    adapter::*,
    app::{dns::DnsClient, outbound::manager::OutboundManager, SyncDnsClient},
    config::Config,
    session::*,
};

// The flat entry point the CLI and FFI call with their own flags.
#[allow(clippy::too_many_arguments)]
pub fn run_with_options(
    rt_id: crate::RuntimeId,
    config_path: String,
    #[cfg(feature = "auto-reload")] auto_reload: bool,
    multi_thread: bool,
    auto_threads: bool,
    threads: usize,
    stack_size: usize,
    runtime: crate::runtime::RuntimeOptions,
    host: crate::runtime::Host,
) -> Result<(), crate::Error> {
    let runtime_opt = if !multi_thread {
        crate::RuntimeOption::SingleThread
    } else if auto_threads {
        crate::RuntimeOption::MultiThreadAuto(stack_size)
    } else {
        crate::RuntimeOption::MultiThread(threads, stack_size)
    };
    let opts = crate::StartOptions {
        config: crate::Config::File(config_path),
        #[cfg(feature = "auto-reload")]
        auto_reload,
        runtime_opt,
        runtime,
        host,
        signals: true,
    };
    crate::start(rt_id, opts)
}

async fn test_tcp_outbound(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> Result<Duration> {
    let sess = Session {
        destination: SocksAddr::Domain("www.google.com".to_string(), 80),
        new_conn_once: true,
        ..Default::default()
    };
    let start = tokio::time::Instant::now();
    let stream = crate::net::connect_stream_outbound(&sess, dns_client, &handler).await?;
    let mut stream = handler.stream()?.handle(&sess, None, stream).await?;
    stream.write_all(b"HEAD / HTTP/1.1\r\n\r\n").await?;
    let mut buf = Vec::new();
    let n = stream.read_buf(&mut buf).await?;
    if n == 0 {
        Err(anyhow!("EOF"))
    } else {
        Ok(tokio::time::Instant::now().duration_since(start))
    }
}

async fn test_udp_outbound(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> Result<Duration> {
    use hickory_proto::{
        op::{Message, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};
    let addr = SocksAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
    let sess = Session {
        destination: addr.clone(),
        new_conn_once: true,
        ..Default::default()
    };
    let start = tokio::time::Instant::now();
    let dgram = crate::net::connect_datagram_outbound(&sess, dns_client, &handler).await?;
    let dgram = handler.datagram()?.handle(&sess, dgram).await?;
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    let name = Name::from_str("www.google.com.")?;
    let query = Query::query(name, RecordType::A);
    msg.add_query(query);
    let mut rng = StdRng::from_entropy();
    let id: u16 = rng.gen();
    msg.set_id(id);
    msg.set_op_code(OpCode::Query);
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    let msg_buf = msg.to_vec()?;
    let (mut recv, mut send) = dgram.split();
    send.send_to(&msg_buf, &addr).await?;
    let mut buf = [0u8; 1500];
    let _ = recv.recv_from(&mut buf).await?;
    Ok(tokio::time::Instant::now().duration_since(start))
}

async fn test_healthcheck_tcp(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> Result<Duration> {
    crate::app::healthcheck::tcp(dns_client, handler).await
}

async fn test_healthcheck_udp(
    dns_client: SyncDnsClient,
    handler: AnyOutboundHandler,
) -> Result<Duration> {
    crate::app::healthcheck::udp(dns_client, handler).await
}

pub async fn test_outbound(
    tag: &str,
    config: &Config,
    to: Option<Duration>,
    env: &crate::runtime::RuntimeEnv,
) -> Result<(Result<Duration>, Result<Duration>)> {
    let to = to.unwrap_or(Duration::from_secs(4));
    let dial_defaults = crate::dial_defaults(config, env)?;
    let dns_client = DnsClient::new(&config.dns, dial_defaults.clone(), env)?.into_shared();
    let outbound_manager =
        OutboundManager::new(&config.outbounds, &dial_defaults, env, dns_client.clone())?;
    let handler = outbound_manager
        .get(tag)
        .ok_or_else(|| anyhow!("outbound {} not found", tag))?;
    let (tcp_res, udp_res) = futures::future::join(
        timeout(to, test_tcp_outbound(dns_client.clone(), handler.clone())),
        timeout(to, test_udp_outbound(dns_client, handler)),
    )
    .await;
    let tcp_res = match tcp_res.map_err(|e| e.into()) {
        Err(e) => Err(e),
        Ok(res) => match res {
            Err(e) => Err(e),
            Ok(duration) => Ok(duration),
        },
    };
    let udp_res = match udp_res.map_err(|e| e.into()) {
        Err(e) => Err(e),
        Ok(res) => match res {
            Err(e) => Err(e),
            Ok(duration) => Ok(duration),
        },
    };
    Ok((tcp_res, udp_res))
}

pub async fn test_outbounds(
    config: &Config,
    to: Option<Duration>,
    concurrency: usize,
    env: &crate::runtime::RuntimeEnv,
) -> Result<HashMap<String, (Result<Duration>, Result<Duration>)>> {
    let to = to.unwrap_or(Duration::from_secs(4));
    let dial_defaults = crate::dial_defaults(config, env)?;
    let dns_client = DnsClient::new(&config.dns, dial_defaults.clone(), env)?.into_shared();
    let outbound_manager =
        OutboundManager::new(&config.outbounds, &dial_defaults, env, dns_client.clone())?;

    let mut tasks = Vec::new();
    for handler in outbound_manager.handlers() {
        let tag = handler.tag().clone();
        let handler = handler.clone();
        let dns_client = dns_client.clone();
        tasks.push(async move {
            let (tcp_res, udp_res) = futures::future::join(
                timeout(to, test_tcp_outbound(dns_client.clone(), handler.clone())),
                timeout(to, test_udp_outbound(dns_client, handler)),
            )
            .await;
            let tcp_res = match tcp_res {
                Ok(res) => res,
                Err(_) => Err(anyhow!("timeout")),
            };
            let udp_res = match udp_res {
                Ok(res) => res,
                Err(_) => Err(anyhow!("timeout")),
            };
            (tag, (tcp_res, udp_res))
        });
    }

    use futures::StreamExt;
    let results = futures::stream::iter(tasks)
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await;

    let mut map = HashMap::new();
    for (tag, res) in results {
        map.insert(tag, res);
    }
    Ok(map)
}

pub async fn stream_outbounds_tests(
    config: &Config,
    to: Option<Duration>,
    concurrency: usize,
    env: &crate::runtime::RuntimeEnv,
) -> Result<impl futures::Stream<Item = (String, (Result<Duration>, Result<Duration>))>> {
    let to = to.unwrap_or(Duration::from_secs(4));
    let dial_defaults = crate::dial_defaults(config, env)?;
    let dns_client = DnsClient::new(&config.dns, dial_defaults.clone(), env)?.into_shared();
    let outbound_manager =
        OutboundManager::new(&config.outbounds, &dial_defaults, env, dns_client.clone())?;

    let mut tasks = Vec::new();
    for handler in outbound_manager.handlers() {
        let tag = handler.tag().clone();
        let handler = handler.clone();
        let dns_client = dns_client.clone();
        tasks.push(async move {
            let (tcp_res, udp_res) = futures::future::join(
                timeout(to, test_tcp_outbound(dns_client.clone(), handler.clone())),
                timeout(to, test_udp_outbound(dns_client, handler)),
            )
            .await;
            let tcp_res = match tcp_res {
                Ok(res) => res,
                Err(_) => Err(anyhow!("timeout")),
            };
            let udp_res = match udp_res {
                Ok(res) => res,
                Err(_) => Err(anyhow!("timeout")),
            };
            (tag, (tcp_res, udp_res))
        });
    }

    use futures::StreamExt;
    Ok(futures::stream::iter(tasks).buffer_unordered(concurrency))
}

pub async fn health_check_outbound(
    tag: &str,
    config: &Config,
    to: Option<Duration>,
    env: &crate::runtime::RuntimeEnv,
) -> Result<(Result<Duration>, Result<Duration>)> {
    let to = to.unwrap_or(Duration::from_secs(4));
    let dial_defaults = crate::dial_defaults(config, env)?;
    let dns_client = DnsClient::new(&config.dns, dial_defaults.clone(), env)?.into_shared();
    let outbound_manager =
        OutboundManager::new(&config.outbounds, &dial_defaults, env, dns_client.clone())?;
    let handler = outbound_manager
        .get(tag)
        .ok_or_else(|| anyhow!("outbound {} not found", tag))?;
    let (tcp_res, udp_res) = futures::future::join(
        timeout(
            to,
            test_healthcheck_tcp(dns_client.clone(), handler.clone()),
        ),
        timeout(to, test_healthcheck_udp(dns_client, handler)),
    )
    .await;
    let tcp_res = match tcp_res.map_err(|e| e.into()) {
        Err(e) => Err(e),
        Ok(res) => match res {
            Err(e) => Err(e),
            Ok(duration) => Ok(duration),
        },
    };
    let udp_res = match udp_res.map_err(|e| e.into()) {
        Err(e) => Err(e),
        Ok(res) => match res {
            Err(e) => Err(e),
            Ok(duration) => Ok(duration),
        },
    };
    Ok((tcp_res, udp_res))
}
