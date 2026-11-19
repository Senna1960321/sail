# Internal transport diagnostics

`internal-diagnostics` also gives the transport under a TUN, for a host that
reads it about once a second next to its own CPU and memory figures
(sail#69). `Instance::internal_diagnostics_with_transport()` returns the
snapshot of `Instance::internal_diagnostics()` with one field more,
`transport`. Its JSON is the same object with `transport` added.

Counters only grow and saturate at the top of `u64`; take the difference
between two reads. A field whose name ends in `_now` is the value at the
read. Wait times are in nanoseconds.

## `transport`

- `schema_version`: 1.
- `netstack`: the running TUN's stack, summed over its shards. It is null
  without a TUN, or when the stack did not answer. Its fields:
  - packets, bytes, batches and I/O wakeups each way:
    - `rx_*` is the host's packets into the stack;
    - `tx_*` is the stack's packets out to the host.
  - Drops and partial sends.
  - Scheduler rounds and time-budget exhaustions.
  - Pressure entries and new flows refused under pressure.
  - Flows created and closed.
  - Zero-window writes, persist probes, retransmission timeouts and SACK
    recovery, and receive-pressure drops.
  - Budget refusals.
  - The flows, bytes held, queued packets, budget use and pressure level
    at the read.
  - `busiest_flow`: the TCP flow whose client acknowledged the most bytes
    since the previous read. A flow is named by `shard` and `id`; both
    stay the same while it lives. On the first read nothing has moved yet,
    so it is the flow holding the most. Its fields:
    - `acked_bytes`: bytes acknowledged since the flow was first read;
    - `acked_bytes_since_last`;
    - `in_flight_now`, `send_buffered_now`: sent and not acknowledged, and
      everything held for the client, which `netstack.send_buffer` bounds;
    - `peer_window_now`, `congestion_window_now`;
    - `smoothed_rtt_ms_now`, in milliseconds: a round trip under a
      millisecond reads 0, and the field is null before one was measured;
    - `rto_ms_now`.
- `bridge`: the newest packet bridge (`TunPacketFlow`) of the process. It is
  null without one. Its fields:
  - `capacity`;
  - packets sent and received each way, and the depth of each queue
    (sent less received);
  - `uplink_send_waits` / `_ns`: the host's `TunPacketSender::send` found
    the queue full and waited;
  - `downlink_reserve_waits` / `_ns`: the stack found the host's queue full
    and waited.
  - A clock is read only when a queue is full.
- `relay`: over every relay of the process, the waits of each direction and
  their total time:
  - on its writer: data the other side does not take;
  - on its reader: nothing to read.
  - Uplink is the client's side to the outbound; downlink is the reverse.
  - An idle connection's wait on its reader counts too.

## Cost

- With the feature off, nothing of this is compiled.
- With it on:
  - the bridge and the relays add relaxed atomic increments;
  - they read a clock only when a queue is full, or when a relay direction
    starts or ends a wait;
  - the stack is read through its command channel, as its statistics are,
    with one sample of each live TCP flow per read.
- Nothing on a packet's path takes a lock or allocates.
