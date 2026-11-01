use super::*;
impl ConsoleApps {
    pub(super) async fn poll_channel(
        &self,
        session: &DataSession<'_>,
        device: Option<&DeviceIdentity>,
        channel: &str,
        after: &str,
        wait: u64,
        tail: Option<u32>,
    ) -> Result<ChannelPollResp, DataError> {
        if !is_valid_resource_id(channel) {
            return Err(invalid("invalid channel_id"));
        }
        let device = device
            .ok_or_else(|| invalid("unlock and enroll this console before reading its channels"))?;
        let (bearer, actor) = self.resolve_console(session, device).await?;
        let console_session = DataSession {
            bearer: &bearer,
            operator_omni: session.operator_omni,
            actor_omni: &actor,
            device,
            now_unix_seconds: session.now_unix_seconds,
        };
        let cap=self.data.cap_mint(&console_session,CapMintOp::ChannelSubscribe,&service_channel_sub(channel)).await.map_err(|error|invalid(format!("console channel read denied; approve this console's channel grants in the app bindings: {error}")))?;
        ChannelWorkerClient::new(&self.config.channel_url)
            .poll(&ChannelPollBody {
                cap,
                after: after.into(),
                wait_seconds: wait.min(25),
                tail,
            })
            .await
            .map_err(broker_error)
    }
    async fn publish(
        &self,
        session: &DataSession<'_>,
        channel: &str,
        kind: ChannelEventKind,
        body: &[u8],
        audio: Option<ChannelAudioParams>,
        stream: Option<bool>,
    ) -> Result<Value, DataError> {
        if !is_valid_resource_id(channel) {
            return Err(invalid("invalid channel_id"));
        }
        let cap = self
            .data
            .cap_mint(
                session,
                CapMintOp::ChannelPublish,
                &service_channel_pub(channel),
            )
            .await?;
        let receipt = ChannelWorkerClient::new(&self.config.channel_url)
            .publish(&ChannelPublishBody {
                cap,
                kind,
                direction: ChannelDirection::In,
                body_b64: Some(STANDARD.encode(body)),
                body_ref: None,
                correlation: None,
                audio,
                partial: None,
                seq: None,
                stream,
                contact: None,
                content_type: None,
                relay_of: None,
                addressee: None,
            })
            .await
            .map_err(broker_error)?;
        encode(receipt)
    }
    pub(super) async fn channels_request(
        &self,
        session: &DataSession<'_>,
        console_device: Option<&DeviceIdentity>,
        method: &str,
        path: &str,
        body: Value,
    ) -> Result<Option<Value>, DataError> {
        if method == "GET" && path.starts_with("/v1/master/agent/lifecycle?") {
            let query = path
                .split_once('?')
                .map(|(_, query)| query)
                .unwrap_or_default();
            let channel = url::form_urlencoded::parse(query.as_bytes())
                .find(|(key, _)| key == "channel_id")
                .map(|(_, value)| value.into_owned())
                .ok_or_else(|| invalid("channel_id required"))?;
            let feed = self
                .poll_channel(
                    session,
                    console_device,
                    &channel,
                    "",
                    0,
                    Some(LIFECYCLE_FEED_TAIL),
                )
                .await?;
            let latest = feed
                .events
                .iter()
                .rev()
                .filter(|event| event.kind == ChannelEventKind::Lifecycle)
                .find_map(|event| {
                    event
                        .body
                        .as_deref()
                        .and_then(|body| STANDARD.decode(body).ok())
                        .and_then(|bytes| serde_json::from_slice::<DelegateLifecycle>(&bytes).ok())
                        .map(|report| (report, event.ts_millis))
                });
            return Ok(Some(
                json!({"channel_id":channel,"lifecycle":latest.as_ref().map(|(report,_)|report),"event_ts_millis":latest.as_ref().map(|(_,timestamp)|timestamp)}),
            ));
        }
        let result = match (method, path) {
            ("GET", "/v1/master/gateway/device") => {
                self.gateway(session, HostedGatewayRequest::DeviceStatus)
                    .await?
            }
            ("GET", "/v1/agent/inheritable-namespaces") => {
                let manifest: VersionedConfig<BindingManifest> = self
                    .documents
                    .config_read(session, BINDING_MANIFEST_SERVICE)
                    .await?;
                inheritable_namespaces(&manifest)
            }
            ("GET", "/v1/master/console/device") => {
                let actor = self.console_actor(session, console_device).await?;
                let hash = console_device
                    .map(DeviceIdentity::device_key_hash)
                    .transpose()
                    .map_err(invalid)?;
                let label = console_device.map(console_label).transpose()?;
                json!({"enrolled":actor.is_some(),"actor_omni":actor,"device_key_hash":hash,"label":label,"suggested_label":label})
            }
            ("POST", "/v1/master/console/device/enroll/build") => {
                let device = console_device
                    .ok_or_else(|| invalid("unlock this console with Touch ID first"))?;
                if self.console_actor(session, Some(device)).await?.is_some() {
                    return Err(http_error(
                        409,
                        json!({"error":"console is already enrolled"}),
                    ));
                }
                let request: ConsoleEnrollRequest = decode(body)?;
                let label = request
                    .label
                    .filter(|label| !label.trim().is_empty())
                    .unwrap_or(console_label(device)?);
                let services = super::lifecycle::console_services_for_apps(
                    &self.fleet(session).await?,
                    &self.apps(session).await?.document,
                    session.operator_omni,
                    None,
                )?;
                let (enrollment, request_id) = self.claim_console(session, device, &label).await?;
                let mut build: Value = self
                    .post(
                        session,
                        "/v1/accept/build",
                        &BuildAcceptUserOpRequest {
                            operator_omni: normalize_omni_0x(session.operator_omni),
                            actor_omni: enrollment.actor_omni.clone(),
                            device_key_hash: enrollment.device_key_hash.clone(),
                            agent_pop_sig: enrollment.pop_sig.clone(),
                            link_code_redemption: String::new(),
                            services: services.clone(),
                            read_only: false,
                            max_per_call: "0".into(),
                            max_per_period: "0".into(),
                            max_total: "0".into(),
                            period_seconds: 86400,
                            is_device: true,
                        },
                    )
                    .await?;
                build["endpoint_scopes"] = encode(vec![EndpointScope {
                    actor_omni: enrollment.actor_omni.clone(),
                    services,
                    preserve_service_ids: vec![],
                }])?;
                self.pending.borrow_mut().insert(
                    operation_key(&build)?,
                    PendingApp {
                        operator: norm(session.operator_omni),
                        route: "/v1/master/console/device/enroll/submit".into(),
                        build: build.clone(),
                        row: None,
                        previous: None,
                        label: label.clone(),
                        enrollments: vec![(enrollment.clone(), request_id)],
                        resources_kept: false,
                        seals: vec![],
                        receipt: None,
                    },
                );
                let mut result = build;
                result["label"] = json!(label);
                result["actor_omni"] = json!(enrollment.actor_omni);
                result
            }
            ("POST", "/v1/master/console/device/enroll/submit") => {
                self.submit(session, path, body).await?
            }
            ("POST", "/v1/master/agent/chat/send") => {
                let request: ChatSendRequest = decode(body)?;
                if request.text.trim().is_empty() {
                    return Err(invalid("text is required"));
                }
                let kind = if request.kind.as_deref() == Some("command") {
                    ChannelEventKind::Command
                } else {
                    ChannelEventKind::Text
                };
                let audio = match request.voice.filter(|voice| !voice.is_empty()) {
                    Some(voice) => Some(decode(
                        json!({"voice":voice,"speech_rate":request.speech_rate}),
                    )?),
                    None => None,
                };
                let device = console_device
                    .ok_or_else(|| invalid("unlock and enroll this console before sending"))?;
                let (bearer, actor) = self.resolve_console(session, device).await?;
                let console_session = DataSession {
                    bearer: &bearer,
                    operator_omni: session.operator_omni,
                    actor_omni: &actor,
                    device,
                    now_unix_seconds: session.now_unix_seconds,
                };
                self.publish(
                    &console_session,
                    &request.channel_id,
                    kind,
                    request.text.as_bytes(),
                    audio,
                    request.stream.filter(|stream| *stream),
                )
                .await?
            }
            ("POST", "/v1/master/agent/chat/poll") => {
                let request: ChatPollRequest = decode(body)?;
                let response = self
                    .poll_channel(
                        session,
                        console_device,
                        &request.channel_id,
                        &request.after,
                        request.wait_seconds,
                        request
                            .after
                            .trim()
                            .is_empty()
                            .then_some(CHAT_HISTORY_TAIL_DEFAULT),
                    )
                    .await?;
                let events=response.events.into_iter().map(|event|{let producer=match &event.producer{ChannelProducer::Actor{actor_omni}=>actor_omni.clone(),ChannelProducer::Contact{contact_id,..}=>contact_id.clone()};let text=event.body.as_deref().and_then(|body|STANDARD.decode(body).ok()).map(|bytes|String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default();json!({"event_id":event.event_id,"channel_id":event.channel_id,"direction":event.direction,"text":text,"producer_omni":producer,"ts_millis":event.ts_millis,"correlation":event.correlation,"partial":event.partial,"seq":event.seq,"kind":event.kind})}).collect::<Vec<_>>();
                json!({"events":events,"cursor":response.cursor})
            }
            _ => return Ok(None),
        };
        Ok(Some(result))
    }
    async fn resolve_console(
        &self,
        session: &DataSession<'_>,
        device: &DeviceIdentity,
    ) -> Result<(String, String), DataError> {
        let expected_actor = self
            .console_actor(session, Some(device))
            .await?
            .ok_or_else(|| {
                invalid("enroll this console and approve the app's channel grants first")
            })?;
        let resolved = self
            .broker
            .agent_resolve(&ResolveBody {
                device_pubkey: device.address(),
                pop_sig: device.agent_pop_sig().map_err(invalid)?,
                is_device: true,
            })
            .await
            .map_err(broker_error)?;
        let bearer = resolved
            .session_jwt
            .ok_or_else(|| invalid("console has no device session"))?;
        let actor = resolved
            .actor_omni
            .ok_or_else(|| invalid("console has no actor"))?;
        if norm(&actor) != norm(&expected_actor)
            || resolved
                .operator_omni
                .as_ref()
                .is_none_or(|owner| norm(owner) != norm(session.operator_omni))
        {
            return Err(invalid("console resolves to another account"));
        }
        Ok((bearer, actor))
    }
    pub(super) async fn claim_console(
        &self,
        session: &DataSession<'_>,
        device: &DeviceIdentity,
        label: &str,
    ) -> Result<(EndpointEnrollment, String), DataError> {
        let request = self
            .broker
            .pairing_request(&PairingRequestBody {
                device_pubkey: device.address(),
                pop_sig: device.agent_pop_sig().map_err(invalid)?,
            })
            .await
            .map_err(broker_error)?;
        let claim = self
            .broker
            .pairing_claim(
                session.bearer,
                &PairingClaimRequest {
                    pairing_code: request.pairing_code,
                    label: label.into(),
                    requested_scope: Some(service_channel_sub(label)),
                },
            )
            .await
            .map_err(broker_error)?;
        if norm(&claim.operator_omni) != norm(session.operator_omni)
            || norm(&claim.device_key_hash) != norm(&device.device_key_hash().map_err(invalid)?)
        {
            return Err(invalid(
                "console claim differs from this session and device",
            ));
        }
        Ok((
            EndpointEnrollment {
                actor_omni: normalize_omni_0x(&claim.child_omni),
                device_key_hash: claim.device_key_hash,
                pop_sig: claim.pop_sig,
                label: claim.label,
                kind: "console".into(),
                transport: String::new(),
            },
            claim.request_id,
        ))
    }
    pub(super) async fn command(
        &self,
        session: &DataSession<'_>,
        console_device: Option<&DeviceIdentity>,
        label: &str,
        request: AppCommandRequest,
    ) -> Result<Value, DataError> {
        let row = self.app(session, label).await?;
        if row.status != AppInstanceStatus::Installed {
            return Err(invalid("app is not installed"));
        }
        let channel = row
            .bound_channels
            .iter()
            .find(|channel| {
                channel.kind == ChannelEndpointKind::Display
                    && request
                        .channel_id
                        .as_ref()
                        .is_none_or(|id| id == &channel.channel_id)
            })
            .ok_or_else(|| invalid("display channel is not bound to this app"))?;
        if request.action.trim().is_empty() || request.command.trim().is_empty() {
            return Err(invalid("action and command are required"));
        }
        let device =
            console_device.ok_or_else(|| invalid("unlock this console with Touch ID first"))?;
        let expected_actor = self
            .console_actor(session, Some(device))
            .await?
            .ok_or_else(|| invalid("enroll this console before sending display commands"))?;
        let resolved = self
            .broker
            .agent_resolve(&ResolveBody {
                device_pubkey: device.address(),
                pop_sig: device.agent_pop_sig().map_err(invalid)?,
                is_device: true,
            })
            .await
            .map_err(broker_error)?;
        let bearer = resolved
            .session_jwt
            .ok_or_else(|| invalid("console has no device session"))?;
        let actor = resolved
            .actor_omni
            .ok_or_else(|| invalid("console has no actor"))?;
        if norm(&actor) != norm(&expected_actor)
            || resolved
                .operator_omni
                .as_ref()
                .is_none_or(|owner| norm(owner) != norm(session.operator_omni))
        {
            return Err(invalid("console resolves to another account"));
        }
        let device_session = DataSession {
            bearer: &bearer,
            operator_omni: session.operator_omni,
            actor_omni: &actor,
            device,
            now_unix_seconds: session.now_unix_seconds,
        };
        let body = serde_json::to_vec(&CardCommand {
            card: CARD_SCHEMA,
            action: request.action,
            command: request.command,
            args: request.args,
            card_updated_at: request.card_updated_at,
        })
        .map_err(invalid)?;
        let mut receipt = self
            .publish(
                &device_session,
                &channel.channel_id,
                ChannelEventKind::Command,
                &body,
                None,
                None,
            )
            .await?;
        receipt["producer"] = json!("console");
        receipt["actor_omni"] = json!(actor);
        Ok(receipt)
    }
    pub(super) async fn dashboard(
        &self,
        session: &DataSession<'_>,
        console_device: Option<&DeviceIdentity>,
        label: &str,
    ) -> Result<Value, DataError> {
        let row = self.app(session, label).await?;
        let display = row
            .bound_channels
            .iter()
            .find(|channel| channel.kind == ChannelEndpointKind::Display);
        let mut view = DisplayFeedView::default();
        if let Some(display) = display.filter(|_| row.status == AppInstanceStatus::Installed) {
            let feed = self
                .poll_channel(
                    session,
                    console_device,
                    &display.channel_id,
                    "",
                    0,
                    Some(DISPLAY_FEED_TAIL_DEFAULT),
                )
                .await?;
            view = fold_display_feed(
                &feed
                    .events
                    .iter()
                    .map(encode)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        Ok(
            json!({"app":row,"activity":crate::console_audit::ConsoleAudit::new(self.broker.clone(),self.data.clone(),self.config.clone()).recent(session,Some(&row.actor_omni),30).await?,"card":view.card.as_ref().map(|(card,_)|card),"card_event_id":view.card.as_ref().map(|(_,id)|id),"card_channel_id":display.map(|channel|&channel.channel_id),"annotations":annotations_for(&row),"console_actor_omni":self.console_actor(session,console_device).await?,"commands":view.commands,"non_card_docs":view.non_card_docs,"last_doc_preview":view.last_doc_preview,"non_card_reason":view.non_card_reason}),
        )
    }
}
pub(super) fn console_label(device: &DeviceIdentity) -> Result<String, DataError> {
    Ok(format!(
        "console-{}",
        &norm(&device.device_key_hash().map_err(invalid)?)[..16]
    ))
}
#[derive(Debug, Default)]
pub struct DisplayFeedView {
    pub card: Option<(CardDocument, String)>,
    pub commands: Vec<serde_json::Value>,
    pub non_card_docs: u32,
    pub last_doc_preview: Option<String>,
    pub non_card_reason: Option<String>,
}

/// Fold a display feed's events (oldest first) into a [`DisplayFeedView`] —
/// pure, so the card / non-card accounting is testable.
pub fn fold_display_feed(events: &[serde_json::Value]) -> DisplayFeedView {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut view = DisplayFeedView::default();
    let mut commands = Vec::new();
    for ev in events {
        let kind = ev.get("kind").and_then(|k| k.as_str()).unwrap_or("");
        match kind {
            "doc" => {
                let bytes = ev
                    .get("body")
                    .and_then(|b| b.as_str())
                    .and_then(|b64| STANDARD.decode(b64).ok())
                    .unwrap_or_default();
                match agentkeys_protocol::parse_card(&bytes) {
                    Ok(c) => {
                        let id = ev
                            .get("event_id")
                            .and_then(|e| e.as_str())
                            .unwrap_or("")
                            .to_string();
                        view.card = Some((c, id));
                        view.non_card_docs = 0;
                        view.last_doc_preview = None;
                        view.non_card_reason = None;
                    }
                    Err(reason) => {
                        view.non_card_docs += 1;
                        view.non_card_reason = Some(reason);
                        let text = String::from_utf8_lossy(&bytes);
                        view.last_doc_preview = Some(text.chars().take(160).collect::<String>());
                    }
                }
            }
            "command" => {
                let mut row = ev.clone();
                if let Some(b64) = ev.get("body").and_then(|b| b.as_str()) {
                    if let Ok(bytes) = STANDARD.decode(b64) {
                        if let Ok(cmd) = agentkeys_protocol::parse_card_command(&bytes) {
                            row["command"] = serde_json::to_value(cmd).unwrap_or_default();
                        }
                    }
                }
                commands.push(row);
            }
            _ => {}
        }
    }
    let keep = commands.len().saturating_sub(20);
    view.commands = commands.split_off(keep);
    view
}

pub fn annotations_for(row: &AppInstanceRow) -> Vec<ServiceAnnotation> {
    row.services
        .iter()
        .map(|s| {
            let lower = s.to_ascii_lowercase();
            let (role, slot, resource, sensitivity) =
                if lower.contains(&format!(":{}", row.chat_channel_id)) {
                    ("opchat", None, None, None)
                } else if let Some(b) = row
                    .bound_channels
                    .iter()
                    .find(|b| lower.ends_with(&format!(":{}", b.channel_id)))
                {
                    ("slot", Some(b.slot.clone()), None, None)
                } else if lower == format!("knowledge:{}", row.memory_ns) {
                    ("own-knowledge", None, None, None)
                } else if lower == format!("proposal:{}", row.memory_ns) {
                    ("own-proposals", None, None, None)
                } else if let Some(rb) = row
                    .bindings
                    .resources
                    .iter()
                    .find(|rb| lower == format!("knowledge:{}", rb.ns))
                {
                    (
                        "resource",
                        None,
                        Some(rb.name.clone()),
                        Some(rb.sensitivity),
                    )
                } else if lower.starts_with("tool:") {
                    ("tool", None, None, None)
                } else if lower.starts_with("plugin:") {
                    ("plugin", None, None, None)
                } else {
                    ("other", None, None, None)
                };
            ServiceAnnotation {
                service: s.clone(),
                role: role.to_string(),
                slot,
                resource,
                sensitivity,
            }
        })
        .collect()
}

pub fn inheritable_namespaces(manifest: &BindingManifest) -> Value {
    let live = manifest
        .bindings
        .iter()
        .filter(|entry| entry.kind == "delegate" && entry.archived_at.is_none())
        .filter_map(|entry| entry.memory_ns.as_deref())
        .collect::<Vec<_>>();
    let mut namespaces = BTreeMap::<String, (String, u64)>::new();
    for entry in &manifest.bindings {
        if let (Some(at), Some(true), Some(namespace)) = (
            entry.archived_at,
            entry.resources_kept,
            entry.memory_ns.as_ref(),
        ) {
            if !live.contains(&namespace.as_str())
                && namespaces
                    .get(namespace)
                    .is_none_or(|(_, previous)| *previous < at)
            {
                namespaces.insert(namespace.clone(), (entry.label.clone(), at));
            }
        }
    }
    let mut values = namespaces
        .into_iter()
        .map(|(namespace, (label, at))| json!({"ns":namespace,"from_label":label,"archived_at":at}))
        .collect::<Vec<_>>();
    values.sort_by(|left, right| {
        right["archived_at"]
            .as_u64()
            .cmp(&left["archived_at"].as_u64())
    });
    json!({"namespaces":values})
}
