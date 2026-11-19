//! The shard's flows, read for a host's diagnostics.

use super::SingleShardRunner;
use crate::tcp::TcpFlowSample;

impl<I> SingleShardRunner<I> {
    /// A sample of every live TCP flow of this shard.
    #[must_use]
    pub fn tcp_flow_samples(&self) -> Vec<TcpFlowSample> {
        self.tcp.flow_samples()
    }
}
