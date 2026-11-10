//! The DNS rules: which server a query goes to, the responses `evaluate`
//! rules keep for the rules after them, and how each query is sent.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use futures::StreamExt;
use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::{RData, RecordType};
use tracing::debug;

use crate::control::events::{DnsExchange, DnsOutcome, DnsSource, DNS_ANSWERS_TOLD};

use super::cache::{self, AnswerKey, Cached};
use super::server::{Kind, Server};
use super::{DnsClient, LookupContext, QueryOptions, Rule, RuleAction, Subnet};
use crate::app::router::matcher::{Facts, ResponseFacts, Responses};
use crate::config::model::{DnsRuleAction, DnsStrategy, Prefix, ResponseRef};
use crate::session::{Session, SocksAddr};
use crate::util::DnsMessageExt;

/// What the rules make of a query.
pub(super) enum Walked {
    /// A server's response, or one an `evaluate` rule kept.
    Response(Box<Message>),
    /// A rule rejects it.
    Refused,
}

/// Where the rules would send a query, as far as can be told before it is
/// sent: for finding what resolving needs.
pub(super) struct Reach {
    pub servers: Vec<String>,
}

/// How the first rule that matches a query without its response sets the
/// families of a lookup.
enum RuleStrategy {
    /// It sends the query, with a strategy of its own or none.
    Sent(Option<DnsStrategy>),
    Rejected,
}

/// The query a walk sends.
struct Question<'a> {
    request: &'a Message,
    host: &'a str,
    ty: RecordType,
    ctx: &'a LookupContext,
}

/// The evaluated responses a rule matches, and the `evaluate` rule each
/// comes from, none when none before it gives it.
type Bound = Vec<(ResponseRef, Option<usize>)>;

/// The queries of the `evaluate` rules of a walk, in flight or answered.
#[derive(Default)]
struct Evaluations<'a> {
    inflight:
        futures::stream::FuturesUnordered<futures::future::BoxFuture<'a, (usize, Option<Message>)>>,
    /// Their responses, by rule: none for a server that did not answer.
    done: HashMap<usize, Option<Message>>,
    /// The last `evaluate` rule without a tag, and the tagged ones.
    latest: Option<usize>,
    tagged: HashMap<String, usize>,
    /// The race rules not yet judged, with the responses they match.
    races: Vec<(usize, Bound)>,
}

impl Evaluations<'_> {
    /// Which `evaluate` rule gives each of `needs`, as far as the walk has
    /// come.
    fn bind(&self, needs: &[ResponseRef]) -> Bound {
        needs
            .iter()
            .map(|r| {
                let index = match r {
                    ResponseRef::Latest => self.latest,
                    ResponseRef::Tag(tag) => self.tagged.get(tag).copied(),
                };
                (r.clone(), index)
            })
            .collect()
    }

    /// Whether every response `bound` names has come.
    fn ready(&self, bound: &Bound) -> bool {
        bound
            .iter()
            .all(|(_, index)| index.is_none_or(|i| self.done.contains_key(&i)))
    }

    /// The response `r` names, of those bound.
    fn response_of(&self, bound: &Bound, r: &ResponseRef) -> Option<&Message> {
        let (_, index) = bound.iter().find(|(named, _)| named == r)?;
        self.done.get(&(*index)?)?.as_ref()
    }

    /// The responses bound, as the rules a logical one combines name them.
    fn responses(&self, bound: &Bound) -> Responses {
        bound
            .iter()
            .map(|(r, _)| {
                let facts = self.response_of(bound, r).map(|m| ResponseFacts {
                    ips: addresses(m),
                    rcode: u16::from(m.response_code()),
                    message: Arc::new(m.clone()),
                });
                (r.clone(), facts)
            })
            .collect()
    }
}

impl DnsClient {
    pub(super) fn load_rules(
        dns: &crate::config::Dns,
        env: &crate::runtime::RuntimeEnv,
        rule_sets: &crate::app::router::rule_set::RuleSets,
    ) -> Result<Vec<Rule>> {
        let mut rules = Vec::new();
        // sing-box's legacy address filters become the two rules sail has
        // for them.
        let expanded: Vec<(usize, std::borrow::Cow<crate::config::model::DnsRule>)> = dns
            .rules
            .iter()
            .enumerate()
            .flat_map(|(i, rule)| match rule.legacy_split(i) {
                Some((evaluate, respond)) => vec![
                    (i, std::borrow::Cow::Owned(evaluate)),
                    (i, std::borrow::Cow::Owned(respond)),
                ],
                None => vec![(i, std::borrow::Cow::Borrowed(rule))],
            })
            .collect();
        for (i, rule) in expanded.iter() {
            let (i, rule) = (*i, rule.as_ref());
            let matcher = crate::app::router::matcher::Matcher::at(
                &rule.conditions(),
                &format!("dns.rules[{}]", i),
                env,
                rule_sets,
            )?;
            // The servers are checked with the model.
            let server = rule.server.clone().unwrap_or_default();
            let options = QueryOptions::of(rule);
            let action = match rule.action.unwrap_or_default() {
                DnsRuleAction::Route => RuleAction::Route {
                    server,
                    strategy: rule.strategy,
                    options,
                },
                DnsRuleAction::Evaluate => RuleAction::Evaluate {
                    server,
                    tag: rule.tag.clone(),
                    options,
                },
                DnsRuleAction::Respond => RuleAction::Respond,
                DnsRuleAction::RouteOptions => RuleAction::RouteOptions(options),
                DnsRuleAction::Reject => RuleAction::Reject,
                DnsRuleAction::Predefined => {
                    let code = rule.rcode.map_or(0, |r| r.0);
                    let records = |texts: &[String], field: &str| {
                        texts
                            .iter()
                            .enumerate()
                            .map(|(j, text)| {
                                crate::app::dns::parse_record(text).map_err(|e| {
                                    anyhow!("dns.rules[{}].{}[{}]: {}", i, field, j, e)
                                })
                            })
                            .collect::<Result<Vec<_>>>()
                    };
                    RuleAction::Predefined(Box::new(super::Predefined {
                        code: ResponseCode::from((code >> 4) as u8, (code & 0xf) as u8),
                        answer: records(&rule.answer, "answer")?,
                        ns: records(&rule.ns, "ns")?,
                        extra: records(&rule.extra, "extra")?,
                    }))
                }
            };
            rules.push(Rule {
                matcher,
                outbounds: rule.outbound.clone(),
                response: rule.match_response.clone(),
                invert: rule.invert,
                ip_match_all: rule.ip_match_all,
                nested_responses: rule.rules.iter().any(|r| !r.responses().is_empty()),
                needs: rule
                    .response()
                    .into_iter()
                    .chain(rule.rules.iter().flat_map(|r| r.responses()).cloned())
                    .collect(),
                race: rule.race,
                speculative: rule.speculative,
                action,
            });
        }
        Ok(rules)
    }

    /// The facts of a query of type `ty` for `host`, made for `ctx`.
    fn facts(
        &self,
        host: &str,
        ty: RecordType,
        ctx: &LookupContext,
        response: Option<&Message>,
    ) -> Facts {
        match response {
            Some(response) => self
                .response_facts(
                    host,
                    ty,
                    ctx,
                    response.response_code(),
                    &addresses(response),
                )
                .with_response(Arc::new(response.clone())),
            None => self.with_network(
                Facts::new(&Self::session(host, ctx), &[]).with_query_type(ty.into()),
                ctx,
            ),
        }
    }

    /// The facts of a response with `rcode` and the addresses `ips`.
    fn response_facts(
        &self,
        host: &str,
        ty: RecordType,
        ctx: &LookupContext,
        rcode: ResponseCode,
        ips: &[IpAddr],
    ) -> Facts {
        self.with_network(
            Facts::new(&Self::session(host, ctx), ips)
                .with_rcode(u16::from(rcode))
                .with_query_type(ty.into()),
            ctx,
        )
    }

    /// `facts`, with the network the host is on, when a rule needs it: as
    /// the lookup began, or now for one that took none; and with the
    /// servers that prefer the name, when a rule asks.
    fn with_network(&self, facts: Facts, ctx: &LookupContext) -> Facts {
        let preferred = match facts.domain() {
            Some(host) if !self.preferring.is_empty() => Some(
                self.preferring
                    .iter()
                    .filter(|tag| self.servers.get(*tag).is_some_and(|s| s.prefers(host)))
                    .cloned()
                    .collect::<Vec<String>>(),
            ),
            _ => None,
        };
        let facts = match preferred {
            Some(tags) => facts.with_preferred_by(Arc::new(tags)),
            None => facts,
        };
        match (&self.network, &ctx.network) {
            (Some(_), Some(state)) => facts.with_network(state.clone()),
            (Some(network), None) => facts.with_network(network.snapshot()),
            (None, _) => facts,
        }
    }

    /// `ctx` with the network as it is now, when a rule needs it and `ctx`
    /// has none: every rule of a lookup then matches one network.
    pub(super) fn pinned<'a>(&self, ctx: &'a LookupContext) -> std::borrow::Cow<'a, LookupContext> {
        match &self.network {
            Some(network) if ctx.network.is_none() => std::borrow::Cow::Owned(LookupContext {
                network: Some(network.snapshot()),
                ..ctx.clone()
            }),
            _ => std::borrow::Cow::Borrowed(ctx),
        }
    }

    fn session(host: &str, ctx: &LookupContext) -> Session {
        Session {
            destination: SocksAddr::Domain(host.to_string(), 0),
            inbound_tag: ctx.inbound.clone().unwrap_or_default(),
            user: ctx.user.clone(),
            neighbor: ctx.neighbor.clone(),
            owner: ctx.owner.clone(),
            ..Default::default()
        }
    }

    /// Whether `rule` matches `response`: with `ip_match_all`, as each of
    /// its addresses alone.
    fn matches_response(
        &self,
        rule: &Rule,
        host: &str,
        ty: RecordType,
        ctx: &LookupContext,
        response: &Message,
        responses: Option<&Arc<Responses>>,
    ) -> bool {
        if !rule.ip_match_all {
            return rule.matcher.matches(&Self::with_responses(
                self.facts(host, ty, ctx, Some(response)),
                responses,
            ));
        }
        let ips = addresses(response);
        !ips.is_empty()
            && ips.iter().all(|ip| {
                rule.matcher.matches(&Self::with_responses(
                    self.response_facts(
                        host,
                        ty,
                        ctx,
                        response.response_code(),
                        std::slice::from_ref(ip),
                    )
                    .with_response(Arc::new(response.clone())),
                    responses,
                ))
            })
    }

    /// `facts`, with the evaluated responses, if the rules a logical one
    /// combines name some of their own.
    fn with_responses(facts: Facts, responses: Option<&Arc<Responses>>) -> Facts {
        match responses {
            Some(responses) => facts.with_responses(responses.clone()),
            None => facts,
        }
    }

    /// Whether the rule is for the outbound `ctx` dials for.
    fn for_outbound(rule: &Rule, ctx: &LookupContext) -> bool {
        rule.outbounds.is_empty()
            || ctx
                .outbound
                .as_ref()
                .is_some_and(|o| rule.outbounds.contains(o))
    }

    fn is_fake_ip(&self, tag: &str) -> bool {
        self.servers
            .get(tag)
            .is_some_and(|s| matches!(s.kind, Kind::FakeIp(_)))
    }

    /// Sends `request` where the rules say, as sing-box walks them: in
    /// order, each `evaluate` rule that matches sending its query, whose
    /// response the rules after it that name it wait for, until one
    /// answers or rejects; `dns.final` takes the rest. A race rule does not
    /// hold the walk: it is judged as its responses come, and the first to
    /// match decides at once; the actions of the rules after a pending one
    /// wait until none matched (a speculative one's query is sent
    /// meanwhile). A lookup of the instance's own (`fake_ip` false) passes
    /// over the rules that send it to the fakeip server, whose addresses
    /// are for clients alone.
    pub(super) async fn walk(
        &self,
        request: &Message,
        ctx: &LookupContext,
        fake_ip: bool,
    ) -> Result<Walked> {
        let query = request
            .queries()
            .first()
            .ok_or_else(|| anyhow!("a query without a question"))?;
        let ty = query.query_type();
        let host = query.name().to_utf8();
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let q = Question {
            request,
            host: &host,
            ty,
            ctx,
        };
        let mut ev = Evaluations::default();
        let mut options = QueryOptions::of_lookup(&ctx.options);
        options.for_instance = !fake_ip;
        for (i, rule) in self.rules.iter().enumerate() {
            if !Self::for_outbound(rule, ctx) {
                continue;
            }
            if let RuleAction::Route { server, .. } = &rule.action {
                if !fake_ip && self.is_fake_ip(server) {
                    continue;
                }
            }
            let bound = ev.bind(&rule.needs);
            if rule.race {
                ev.races.push((i, bound));
                if let Some(won) = self.judge_races(&mut ev, &q) {
                    return self
                        .act(won, self.responds_with(won, &ev), &options, &q)
                        .await;
                }
                continue;
            }
            for index in bound.iter().filter_map(|(_, index)| *index) {
                if let Some(won) = self.wait(&mut ev, index, &q).await {
                    return self
                        .act(won, self.responds_with(won, &ev), &options, &q)
                        .await;
                }
            }
            if !self.judge(rule, &bound, &ev, &q) {
                continue;
            }
            match &rule.action {
                RuleAction::RouteOptions(set) => {
                    debug!("dns rule {} matches {} {}: route options", i, host, ty);
                    options = options.with(set);
                }
                RuleAction::Evaluate {
                    server,
                    tag,
                    options: own,
                } => {
                    if !ev.races.is_empty() && !rule.speculative {
                        if let Some(won) = self.settle(&mut ev, &q).await {
                            return self
                                .act(won, self.responds_with(won, &ev), &options, &q)
                                .await;
                        }
                    }
                    debug!(
                        "dns rule {} matches {} {}: evaluate [{}]",
                        i, host, ty, server
                    );
                    let (server, options) = (server.clone(), options.with(own));
                    let host = host.clone();
                    // Its type named first: coerced inside the push, the
                    // compiler overflows evaluating it (a warning on
                    // nightly, which may become an error).
                    let asked: futures::future::BoxFuture<'_, (usize, Option<Message>)> =
                        Box::pin(async move {
                            let response = match self.resolve(&server, request, &options).await {
                                Ok(response) => Some(response),
                                Err(e) => {
                                    debug!("{} {}: evaluate [{}]: {}", host, ty, server, e);
                                    None
                                }
                            };
                            (i, response)
                        });
                    ev.inflight.push(asked);
                    match tag {
                        None => ev.latest = Some(i),
                        Some(tag) => {
                            ev.tagged.insert(tag.clone(), i);
                        }
                    }
                }
                _ => {
                    // A decision, which the race rules before it may yet
                    // take from it.
                    if ev.races.is_empty() {
                        return self.act(i, self.responds_with(i, &ev), &options, &q).await;
                    }
                    let early = match &rule.action {
                        RuleAction::Route {
                            server,
                            options: own,
                            ..
                        } if rule.speculative => {
                            let options = options.with(own);
                            Some(Box::pin(async move {
                                self.resolve(server, request, &options).await
                            }))
                        }
                        _ => None,
                    };
                    let Some(mut early) = early else {
                        if let Some(won) = self.settle(&mut ev, &q).await {
                            return self
                                .act(won, self.responds_with(won, &ev), &options, &q)
                                .await;
                        }
                        return self.act(i, self.responds_with(i, &ev), &options, &q).await;
                    };
                    // The speculative query goes on while the races are
                    // judged.
                    let (won, answered) = {
                        let settle = self.settle(&mut ev, &q);
                        tokio::pin!(settle);
                        let mut answered = None;
                        let won = loop {
                            tokio::select! {
                                won = &mut settle => break won,
                                response = &mut early, if answered.is_none() => {
                                    answered = Some(response);
                                }
                            }
                        };
                        (won, answered)
                    };
                    if let Some(won) = won {
                        return self
                            .act(won, self.responds_with(won, &ev), &options, &q)
                            .await;
                    }
                    debug!("dns rule {} matches {} {}: speculative", i, host, ty);
                    let response = match answered {
                        Some(response) => response,
                        None => early.await,
                    };
                    return response.map(|response| Walked::Response(Box::new(response)));
                }
            }
        }
        if let Some(won) = self.settle(&mut ev, &q).await {
            return self
                .act(won, self.responds_with(won, &ev), &options, &q)
                .await;
        }
        self.resolve(&self.final_server, request, &options)
            .await
            .map(|response| Walked::Response(Box::new(response)))
    }

    /// Whether `rule` matches, with the evaluated responses `bound` gives
    /// it, which have come.
    fn judge(&self, rule: &Rule, bound: &Bound, ev: &Evaluations, q: &Question) -> bool {
        let responses = rule.nested_responses.then(|| Arc::new(ev.responses(bound)));
        match rule.response.as_ref().map(|r| ev.response_of(bound, r)) {
            // Without its response, a rule matches only inverted, as in
            // sing-box.
            Some(None) => rule.invert,
            Some(Some(response)) => {
                self.matches_response(rule, q.host, q.ty, q.ctx, response, responses.as_ref())
            }
            None => rule.matcher.matches(&Self::with_responses(
                self.facts(q.host, q.ty, q.ctx, None),
                responses.as_ref(),
            )),
        }
    }

    /// The first pending race rule, in order, whose responses have all
    /// come and which matches; those that do not match go.
    fn judge_races(&self, ev: &mut Evaluations, q: &Question) -> Option<usize> {
        let mut k = 0;
        while k < ev.races.len() {
            let (i, bound) = &ev.races[k];
            if !ev.ready(bound) {
                k += 1;
                continue;
            }
            if self.judge(&self.rules[*i], bound, ev, q) {
                debug!("dns rule {} wins the race for {} {}", i, q.host, q.ty);
                return Some(*i);
            }
            ev.races.remove(k);
        }
        None
    }

    /// Takes the next evaluated response to come, and a race rule that
    /// matches then.
    async fn advance(&self, ev: &mut Evaluations<'_>, q: &Question<'_>) -> Option<usize> {
        let (index, response) = ev.inflight.next().await?;
        ev.done.insert(index, response);
        self.judge_races(ev, q)
    }

    /// Waits for the response of the `evaluate` rule `index`, unless a
    /// race rule matches first.
    async fn wait(
        &self,
        ev: &mut Evaluations<'_>,
        index: usize,
        q: &Question<'_>,
    ) -> Option<usize> {
        while !ev.done.contains_key(&index) {
            if ev.inflight.is_empty() {
                break;
            }
            if let Some(won) = self.advance(ev, q).await {
                return Some(won);
            }
        }
        None
    }

    /// Waits until the pending race rules have all been judged: the first
    /// that matches, or none.
    async fn settle(&self, ev: &mut Evaluations<'_>, q: &Question<'_>) -> Option<usize> {
        loop {
            if let Some(won) = self.judge_races(ev, q) {
                return Some(won);
            }
            if ev.races.is_empty() || ev.inflight.is_empty() {
                return None;
            }
            if let Some(won) = self.advance(ev, q).await {
                return Some(won);
            }
        }
    }

    /// The response rule `index` answers with, if it is a `respond` one.
    fn responds_with(&self, index: usize, ev: &Evaluations) -> Option<Message> {
        let rule = &self.rules[index];
        if !matches!(rule.action, RuleAction::Respond) {
            return None;
        }
        let r = rule.response.as_ref()?;
        ev.response_of(&ev.bind(std::slice::from_ref(r)), r)
            .cloned()
    }

    /// Carries out the action of rule `index`, which decides; a `respond`
    /// one with `responded`.
    async fn act(
        &self,
        index: usize,
        responded: Option<Message>,
        options: &QueryOptions,
        q: &Question<'_>,
    ) -> Result<Walked> {
        let rule = &self.rules[index];
        let (host, ty) = (q.host, q.ty);
        match &rule.action {
            RuleAction::Respond => {
                debug!("dns rule {} matches {} {}: respond", index, host, ty);
                match responded {
                    Some(response) => Ok(Walked::Response(Box::new(response))),
                    None => Err(anyhow!(
                        "{} {}: dns rule {} responds, and there is no evaluated response",
                        host,
                        ty,
                        index
                    )),
                }
            }
            RuleAction::Route {
                server,
                options: own,
                ..
            } => {
                debug!("dns rule {} matches {} {}: [{}]", index, host, ty, server);
                self.resolve(server, q.request, &options.with(own))
                    .await
                    .map(|response| Walked::Response(Box::new(response)))
            }
            RuleAction::Reject => {
                debug!("dns rule {} matches {} {}: reject", index, host, ty);
                self.events.dns_exchanged(|| DnsExchange {
                    outcome: DnsOutcome::Answered {
                        rcode: rcode_name(ResponseCode::Refused),
                        rcode_code: u16::from(ResponseCode::Refused),
                    },
                    ..exchange(
                        q.request,
                        Ok(q.request),
                        DnsSource::Rule,
                        None,
                        options.for_instance,
                    )
                });
                Ok(Walked::Refused)
            }
            RuleAction::Predefined(predefined) => {
                debug!(
                    "dns rule {} matches {} {}: {}",
                    index, host, ty, predefined.code
                );
                let response = predefined.response(q.request);
                self.events.dns_exchanged(|| {
                    exchange(
                        q.request,
                        Ok(&response),
                        DnsSource::Rule,
                        None,
                        options.for_instance,
                    )
                });
                Ok(Walked::Response(Box::new(response)))
            }
            RuleAction::Evaluate { .. } | RuleAction::RouteOptions(_) => {
                unreachable!("an evaluate or route-options rule decides nothing")
            }
        }
    }

    /// The families a lookup of `host` for `ctx` asks for: what `ctx`
    /// says, or the `strategy` of the rule that sends the A query (the AAAA
    /// one when it rejects that), or `dns.strategy`. Rules that set one
    /// match no evaluated response, as the model checks.
    pub(super) fn lookup_strategy(&self, host: &str, ctx: &LookupContext) -> DnsStrategy {
        if let Some(strategy) = ctx.strategy {
            return strategy;
        }
        if !self.rules_set_strategy {
            return self.strategy;
        }
        let of = |ty| self.rule_strategy(host, ty, ctx);
        match (of(RecordType::A), of(RecordType::AAAA)) {
            (RuleStrategy::Sent(strategy), _)
            | (RuleStrategy::Rejected, RuleStrategy::Sent(strategy)) => {
                strategy.unwrap_or(self.strategy)
            }
            (RuleStrategy::Rejected, RuleStrategy::Rejected) => self.strategy,
        }
    }

    /// The families a client's query of `ty` is answered for: a family the
    /// strategy leaves out has no records.
    pub(super) fn query_strategy(
        &self,
        host: &str,
        ty: RecordType,
        ctx: &LookupContext,
    ) -> DnsStrategy {
        if let Some(strategy) = ctx.strategy {
            return strategy;
        }
        match self.rules_set_strategy {
            true => match self.rule_strategy(host, ty, ctx) {
                RuleStrategy::Sent(Some(strategy)) => strategy,
                _ => self.strategy,
            },
            false => self.strategy,
        }
    }

    fn rule_strategy(&self, host: &str, ty: RecordType, ctx: &LookupContext) -> RuleStrategy {
        let facts = self.facts(host, ty, ctx, None);
        for rule in &self.rules {
            if rule.response.is_some()
                || rule.nested_responses
                || !Self::for_outbound(rule, ctx)
                || !rule.matcher.matches(&facts)
            {
                continue;
            }
            match &rule.action {
                RuleAction::Route {
                    server, strategy, ..
                } if !self.is_fake_ip(server) => return RuleStrategy::Sent(*strategy),
                // One with addresses sends none, but answers with them.
                RuleAction::Predefined(p) if !p.answer.is_empty() => {
                    return RuleStrategy::Sent(None)
                }
                RuleAction::Reject | RuleAction::Predefined(_) => return RuleStrategy::Rejected,
                _ => {}
            }
        }
        RuleStrategy::Sent(None)
    }

    /// The servers a lookup of `host` of type `ty` for `ctx` may ask:
    /// those of the `evaluate` rules that match it, and of the rules that
    /// may send it, up to the first that surely does.
    pub(super) fn reach(&self, host: &str, ty: RecordType, ctx: &LookupContext) -> Reach {
        let facts = self.facts(host, ty, ctx, None);
        let mut servers = Vec::new();
        for rule in &self.rules {
            if !Self::for_outbound(rule, ctx) {
                continue;
            }
            // A rule on a response may match it or not.
            let surely = rule.response.is_none() && !rule.nested_responses;
            if surely && !rule.matcher.matches(&facts) {
                continue;
            }
            match &rule.action {
                RuleAction::Evaluate { server, .. } => servers.push(server.clone()),
                RuleAction::Route { server, .. } if !self.is_fake_ip(server) => {
                    servers.push(server.clone());
                    if surely {
                        return Reach { servers };
                    }
                }
                RuleAction::Respond | RuleAction::Reject | RuleAction::Predefined(_) if surely => {
                    return Reach { servers };
                }
                _ => {}
            }
        }
        servers.push(self.final_server.clone());
        Reach { servers }
    }

    /// Asks the server tagged `tag` `request`, sent as `options` says: its
    /// client subnet, its time, its TTLs. An answer comes from the cache
    /// while it lasts, but a fake IP's, whose address its store may have
    /// handed to another domain by then; with `dns.optimistic`, an expired
    /// one does too, while it is asked for again in the background.
    pub(super) async fn resolve(
        &self,
        tag: &str,
        request: &Message,
        options: &QueryOptions,
    ) -> Result<Message> {
        let server = self.server(tag)?.clone();
        let mut request = request.clone();
        match options
            .client_subnet
            .or(self.client_subnet.map(Subnet::Set))
        {
            Some(Subnet::Set(prefix)) => set_client_subnet(&mut request, prefix),
            Some(Subnet::Remove) => remove_client_subnet(&mut request),
            None => {}
        }
        let cached = !self.disable_cache
            && !options.disable_cache
            && !matches!(server.kind, Kind::FakeIp(_))
            && simple_request(&request);
        let key = request.queries().first().filter(|_| cached).map(|q| {
            let name = q.name().to_utf8();
            (
                tag.to_string(),
                name.trim_end_matches('.').to_ascii_lowercase(),
                u16::from(q.query_type()),
                client_subnet(&request),
            )
        });
        let key = key.map(|key| (key, self.answers.generation()));
        if let Some((key, generation)) = &key {
            match self.answers.get(key, request.id()) {
                Cached::Fresh(answer) => {
                    log_answer("cached", tag, &answer, None);
                    self.events.dns_exchanged(|| {
                        exchange(
                            &request,
                            Ok(&answer),
                            DnsSource::Cached,
                            Some(tag),
                            options.for_instance,
                        )
                    });
                    return Ok(for_request(answer, &request));
                }
                Cached::Stale(answer) if !options.disable_optimistic_cache => {
                    log_answer("optimistic", tag, &answer, None);
                    self.events.dns_exchanged(|| {
                        exchange(
                            &request,
                            Ok(&answer),
                            DnsSource::Optimistic,
                            Some(tag),
                            options.for_instance,
                        )
                    });
                    self.refresh(tag, &request, options, key.clone(), *generation);
                    return Ok(for_request(answer, &request));
                }
                Cached::Stale(_) | Cached::Missing => {}
            }
        }
        self.ask_and_keep(&server, &request, options, key).await
    }

    /// Asks `server`, and keeps the answer under `key`, if any, for its
    /// TTL, which every record then carries, as in sing-box: its own, or
    /// `rewrite_ttl`.
    async fn ask_and_keep(
        &self,
        server: &Server,
        request: &Message,
        options: &QueryOptions,
        key: Option<(AnswerKey, u64)>,
    ) -> Result<Message> {
        let timeout = options.timeout.unwrap_or(self.timeout);
        let started = tokio::time::Instant::now();
        let asked = self
            .query(server, request, timeout, options.for_instance)
            .await;
        let took = started.elapsed();
        let ms = took.as_millis();
        let asked = match asked {
            Ok(asked) => asked,
            Err(e) => {
                let (name, ty) = question(request);
                let line = format!("dns: [{}] {} {}: {}", server.tag, name, ty, e);
                logged(&line);
                debug!(server = %server.tag, ms, "{}", line);
                self.events.dns_exchanged(|| DnsExchange {
                    duration: Some(took),
                    ..exchange(
                        request,
                        Err(&e),
                        DnsSource::Exchanged,
                        Some(&server.tag),
                        options.for_instance,
                    )
                });
                return Err(e);
            }
        };
        let (member, attempt) = (asked.member, asked.attempt);
        let mut response = match asked.answer {
            super::Answer::Message(message) => message,
            super::Answer::Ips(ips) => {
                Self::reply(request, &ips, super::LOCAL_TTL.as_secs() as u32)
            }
        };
        response.set_id(request.id());
        // Padding is the server's, for its own link: not kept, nor passed on.
        strip_padding(&mut response);
        let ttl = options
            .rewrite_ttl
            .unwrap_or_else(|| cache::ttl_of(&response));
        cache::set_ttl(&mut response, ttl);
        let keeps = matches!(
            response.response_code(),
            ResponseCode::NoError | ResponseCode::NXDomain
        );
        if let (true, Some((key, generation))) = (keeps, key) {
            self.answers.put(key, &response, ttl, generation);
        }
        log_answer("exchanged", &server.tag, &response, Some(ms));
        self.events.dns_exchanged(|| DnsExchange {
            duration: Some(took),
            attempt,
            ..exchange(
                request,
                Ok(&response),
                DnsSource::Exchanged,
                Some(member.as_deref().unwrap_or(&server.tag)),
                options.for_instance,
            )
        });
        fit_edns(&mut response, request);
        Ok(response)
    }

    /// Asks the server tagged `tag` `request` again in the background, for
    /// the answer kept under `key`, which has expired: once at a time.
    fn refresh(
        &self,
        tag: &str,
        request: &Message,
        options: &QueryOptions,
        key: AnswerKey,
        generation: u64,
    ) {
        let Some(me) = self.me.upgrade() else {
            return;
        };
        if !self.answers.start_refresh(&key, generation) {
            return;
        }
        let (tag, request, options) = (tag.to_owned(), request.clone(), options.clone());
        crate::runtime::scope::spawn("dns optimistic refresh", async move {
            let asked = match me.server(&tag) {
                Ok(server) => {
                    let server = server.clone();
                    me.ask_and_keep(&server, &request, &options, Some((key.clone(), generation)))
                        .await
                        .map(drop)
                }
                Err(e) => Err(e),
            };
            if let Err(e) = asked {
                debug!(
                    "{}: optimistic refresh failed: {}",
                    Self::question(&request),
                    e
                );
            }
            me.answers.refreshed(&key, generation);
        });
    }
}

/// The addresses a response carries.
pub(super) fn addresses(response: &Message) -> Vec<IpAddr> {
    response
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(ip) => Some(IpAddr::V4(ip.0)),
            RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
            _ => None,
        })
        .collect()
}

/// The client subnet `request` carries.
pub(super) fn client_subnet(request: &Message) -> Option<Prefix> {
    let option = request.extensions().as_ref()?.option(EdnsCode::Subnet)?;
    let EdnsOption::Subnet(subnet) = option else {
        return None;
    };
    // FAMILY, SOURCE PREFIX-LENGTH, SCOPE PREFIX-LENGTH, ADDRESS.
    let bytes = Vec::<u8>::try_from(subnet).ok()?;
    let (head, address) = bytes.split_at_checked(4)?;
    let len = head[2];
    let addr = match u16::from_be_bytes([head[0], head[1]]) {
        1 => {
            let mut octets = [0u8; 4];
            octets.get_mut(..address.len())?.copy_from_slice(address);
            IpAddr::from(octets)
        }
        2 => {
            let mut octets = [0u8; 16];
            octets.get_mut(..address.len())?.copy_from_slice(address);
            IpAddr::from(octets)
        }
        _ => return None,
    };
    Some(Prefix { addr, len })
}

/// The name and type a query asks, as logs write them.
fn question(m: &Message) -> (String, String) {
    m.queries()
        .first()
        .map(|q| {
            let name = q.name().to_utf8();
            (
                name.trim_end_matches('.').to_string(),
                q.query_type().to_string(),
            )
        })
        .unwrap_or_default()
}

impl DnsClient {
    /// Tells of a sequential server's `member` failing attempt `attempt`
    /// of `request` with `error`, which took `took`.
    pub(super) fn member_failed(
        &self,
        request: &Message,
        member: &str,
        error: &anyhow::Error,
        took: std::time::Duration,
        attempt: u32,
        for_instance: bool,
    ) {
        self.events.dns_exchanged(|| DnsExchange {
            duration: Some(took),
            attempt: Some(attempt),
            ..exchange(
                request,
                Err(error),
                DnsSource::Exchanged,
                Some(member),
                for_instance,
            )
        });
    }
}

/// What an event tells of the query of `request`, answered with `answered`
/// or failed: its name and type, the answer's code, records and TTL; the
/// time and attempt are the caller's to set.
fn exchange(
    request: &Message,
    answered: std::result::Result<&Message, &anyhow::Error>,
    source: DnsSource,
    server: Option<&str>,
    for_instance: bool,
) -> DnsExchange {
    let (name, qtype, qtype_code) = request
        .queries()
        .first()
        .map(|q| {
            let name = q.name().to_utf8();
            (
                name.trim_end_matches('.').to_string(),
                q.query_type().to_string(),
                u16::from(q.query_type()),
            )
        })
        .unwrap_or_default();
    let (outcome, answers, answers_total, ttl) = match answered {
        Ok(answer) => {
            let records = answer.answers();
            (
                DnsOutcome::Answered {
                    rcode: rcode_name(answer.response_code()),
                    rcode_code: u16::from(answer.response_code()),
                },
                records
                    .iter()
                    .take(DNS_ANSWERS_TOLD)
                    .map(|r| r.data.to_string())
                    .collect(),
                u32::try_from(records.len()).unwrap_or(u32::MAX),
                records.iter().map(|r| r.ttl).min(),
            )
        }
        Err(e) => (
            DnsOutcome::Failed {
                error: e.to_string(),
            },
            Vec::new(),
            0,
            None,
        ),
    };
    DnsExchange {
        name,
        qtype,
        qtype_code,
        server: server.map(str::to_string),
        source,
        outcome,
        answers,
        answers_total,
        ttl,
        duration: None,
        attempt: None,
        for_instance,
    }
}

/// One line at debug for each query a server answered or the cache did:
/// `how` (sing-box's words: `exchanged`, `cached`, `optimistic`), the name,
/// type, code, the records and the TTL, with the server and, for a server's,
/// the time it took. The records themselves are not logged, which sing-box
/// does at info: a name a client asks for is the client's business.
fn log_answer(how: &str, server: &str, answer: &Message, ms: Option<u128>) {
    let (name, ty) = question(answer);
    let ttl = answer.answers().iter().map(|r| r.ttl).min().unwrap_or(0);
    let rcode = rcode_name(answer.response_code());
    let records = answer.answers().len();
    let line = format!("dns: {} {} {} {} {}", how, name, ty, rcode, ttl);
    logged(&format!(
        "{} server={} records={} ms={:?}",
        line, server, records, ms
    ));
    match ms {
        Some(ms) => debug!(server = %server, ms, records, "{}", line),
        None => debug!(server = %server, records, "{}", line),
    }
}

#[cfg(test)]
thread_local! {
    /// The query lines this thread logged, for tests to read: tracing's own
    /// state is the process's, which tests running at once share.
    pub(super) static LOGGED: std::cell::RefCell<Vec<String>> = Default::default();
}

/// Keeps `line` for tests; nothing outside them.
fn logged(line: &str) {
    #[cfg(test)]
    LOGGED.with(|l| l.borrow_mut().push(line.to_string()));
    let _ = line;
}

/// A response code as sing-box logs it (miekg/dns's RcodeToString).
fn rcode_name(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR".into(),
        ResponseCode::FormErr => "FORMERR".into(),
        ResponseCode::ServFail => "SERVFAIL".into(),
        ResponseCode::NXDomain => "NXDOMAIN".into(),
        ResponseCode::NotImp => "NOTIMP".into(),
        ResponseCode::Refused => "REFUSED".into(),
        other => u16::from(other).to_string(),
    }
}

/// Whether `request` may be answered from the cache and its answer kept, as
/// sing-box decides it (dns/client.go `isSimpleRequest`): one question, no
/// authority, and no additional record but an OPT of version 0, with no DO
/// bit, a payload size, and no option but a client subnet, which the cache
/// keys by. Anything else of EDNS is the asking client's own: a cookie, which
/// an answer kept for another client would carry wrong and the client then
/// drops, padding, the DO bit, a later version. Such a query is asked of its
/// server each time, and the server answers it for this client.
pub(super) fn simple_request(request: &Message) -> bool {
    if request.queries().len() != 1
        || !request.name_servers().is_empty()
        || !request.additionals.is_empty()
    {
        return false;
    }
    let Some(edns) = request.extensions() else {
        return true;
    };
    edns.version() == 0
        && edns.rcode_high() == 0
        && !edns.flags().dnssec_ok
        && edns.max_payload() > 0
        && edns
            .options()
            .as_ref()
            .iter()
            .all(|(code, _)| *code == EdnsCode::Subnet)
}

/// A kept answer as it answers `request`: its ID, and its question as the
/// client wrote it (a resolver that randomizes the letters' case checks
/// them), with the EDNS `request` takes.
fn for_request(mut answer: Message, request: &Message) -> Message {
    answer.set_id(request.id());
    answer.queries = request.queries().to_vec();
    fit_edns(&mut answer, request);
    answer
}

/// An answer's EDNS as a client that sent `request` takes it, as sing-box
/// fits it (dns/client.go finishExchange): none to one that sent none, and
/// no later version than its own.
fn fit_edns(response: &mut Message, request: &Message) {
    match (request.extensions(), response.extensions_mut()) {
        (None, edns) => *edns = None,
        (Some(asked), Some(answered)) if answered.version() > asked.version() => {
            answered.set_version(asked.version());
        }
        _ => {}
    }
}

/// Takes out EDNS padding (RFC 7830), as sing-box does before it keeps an
/// answer.
fn strip_padding(response: &mut Message) {
    if let Some(edns) = response.extensions_mut() {
        edns.options_mut().remove(EdnsCode::Padding);
    }
}

/// Makes `request` carry `prefix` as its client subnet, in place of any it
/// has; the address's bits past the prefix are cleared, as RFC 7871 wants.
pub(super) fn set_client_subnet(request: &mut Message, prefix: Prefix) {
    let addr = match prefix.addr {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - prefix.len as u32).unwrap_or(0);
            IpAddr::from((u32::from(v4) & mask).to_be_bytes())
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - prefix.len as u32).unwrap_or(0);
            IpAddr::from((u128::from(v6) & mask).to_be_bytes())
        }
    };
    let edns = request.extensions_mut().get_or_insert_with(|| {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns
    });
    let options = edns.options_mut();
    options.remove(EdnsCode::Subnet);
    options.insert(EdnsOption::Subnet(ClientSubnet::new(addr, prefix.len, 0)));
}

fn remove_client_subnet(request: &mut Message) {
    if let Some(edns) = request.extensions_mut() {
        edns.options_mut().remove(EdnsCode::Subnet);
    }
}

impl super::Predefined {
    /// The answer to `request`: its code, and its records, one named
    /// `*.suffix.` taking the name asked for when it ends in the suffix, as
    /// sing-box answers.
    fn response(&self, request: &Message) -> Message {
        let mut response = DnsClient::status(request, self.code);
        response.metadata.authoritative = true;
        let Some(question) = request.queries().first() else {
            return response;
        };
        let asked = question.name();
        let named = |records: &[hickory_proto::rr::Record]| {
            records
                .iter()
                .map(|record| {
                    let mut record = record.clone();
                    // `*.example.` is for the names under `example.`.
                    let base = record.name.base_name();
                    if record.name.is_wildcard()
                        && asked.num_labels() > base.num_labels()
                        && base.zone_of(asked)
                    {
                        record.name = asked.clone();
                    }
                    record
                })
                .collect::<Vec<_>>()
        };
        response.answers = named(&self.answer);
        response.authorities = named(&self.ns);
        response.additionals = named(&self.extra);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};

    #[test]
    fn a_client_subnet_is_set_masked_and_read_back() {
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        let prefix: Prefix = "223.5.5.77/24".parse().unwrap();
        set_client_subnet(&mut request, prefix);
        let read = client_subnet(&Message::from_vec(&request.to_vec().unwrap()).unwrap());
        assert_eq!(read, Some("223.5.5.0/24".parse().unwrap()));

        let prefix: Prefix = "2001:db8:1:2::5/56".parse().unwrap();
        set_client_subnet(&mut request, prefix);
        let read = client_subnet(&Message::from_vec(&request.to_vec().unwrap()).unwrap());
        assert_eq!(read, Some("2001:db8:1::/56".parse().unwrap()));

        remove_client_subnet(&mut request);
        assert_eq!(client_subnet(&request), None);
    }
}
