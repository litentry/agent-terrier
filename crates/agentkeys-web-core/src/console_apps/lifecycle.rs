use super::channels::console_label;
use super::*;

struct PreparedApp {
    bindings: AppInstallBindings,
    compiled: CompiledApp,
    enrollments: Vec<(EndpointEnrollment, String)>,
    scopes: Vec<EndpointScope>,
}
impl ConsoleApps {
    async fn bundle(&self, id: &str) -> Result<PresetBundle, DataError> {
        if id.is_empty()
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid("invalid template id"));
        }
        let bundle: PresetBundle = self
            .broker
            .get_json(&format!("/v1/presets/{id}"), None)
            .await
            .map_err(broker_error)?;
        validate_template(
            &bundle.manifest,
            &bundle.skill_filenames(),
            &bundle.knowledge_filenames(),
        )
        .map_err(|rows| http_error(400, json!({"error":"template_invalid","rows":rows})))?;
        Ok(bundle)
    }
    #[allow(clippy::too_many_arguments)]
    async fn prepare(
        &self,
        session: &DataSession<'_>,
        device: Option<&DeviceIdentity>,
        manifest: &PresetSummary,
        label: &str,
        memory: Option<&str>,
        mut bindings: AppInstallBindings,
        enroll: bool,
        previous: Option<&AppInstanceRow>,
    ) -> Result<PreparedApp, DataError> {
        let registry: VersionedConfig<ChannelRegistry> = self
            .documents
            .config_read(session, CHANNEL_REGISTRY_SERVICE)
            .await?;
        let resources = self.resources(session).await?;
        for binding in &mut bindings.resources {
            let item = resources
                .find(&binding.item_id)
                .ok_or_else(|| invalid(format!("resource {} no longer exists", binding.item_id)))?;
            binding.ns = item.ns.clone();
            binding.kind = item.kind;
            binding.sensitivity = item.sensitivity;
        }
        let needs_gate = bindings.slots.iter().any(|binding| {
            slot_kind(manifest, &binding.slot) == Some(ChannelEndpointKind::Messaging)
        });
        let gate = if needs_gate {
            Some(
                self.gateway(session, HostedGatewayRequest::DeviceStatus)
                    .await?,
            )
        } else {
            None
        };
        for binding in &mut bindings.slots {
            if let Some(channel) = registry
                .channels
                .iter()
                .find(|channel| channel.id == binding.channel_id)
            {
                binding.endpoint_actor_omni = channel.endpoint_actor_omni.clone();
            }
            if slot_kind(manifest, &binding.slot) == Some(ChannelEndpointKind::Messaging) {
                binding.endpoint_actor_omni = Some(
                    required(
                        gate.as_ref()
                            .ok_or_else(|| invalid("contact gate unavailable"))?,
                        "actor_omni",
                    )?
                    .into(),
                );
            }
        }
        seed_slot_descriptions(manifest, &mut bindings);
        let mut console = self.console_actor(session, device).await?;
        let mut enrollments = vec![];
        if enroll && console.is_none() {
            let device = device.ok_or_else(|| {
                invalid("unlock this console with Touch ID before installing an app")
            })?;
            let pending = self
                .claim_console(session, device, &console_label(device)?)
                .await?;
            console = Some(pending.0.actor_omni.clone());
            enrollments.push(pending);
        }
        let compiled = compile_app(manifest, label, memory, &bindings).map_err(|rows| {
            http_error(
                400,
                json!({"error":"template_bindings_invalid","rows":rows}),
            )
        })?;
        let mut next = compiled.bound_channels.clone();
        next.push(console_chat(&compiled.chat_channel_id));
        let mut before = previous
            .map(|row| row.bound_channels.clone())
            .unwrap_or_default();
        if let Some(previous) = previous {
            before.push(console_chat(&previous.chat_channel_id));
        }
        let scopes = self
            .endpoint_scopes(
                session,
                &compiled.endpoint_grants,
                &next,
                &before,
                console.as_deref(),
                Some(label),
                &enrollments,
            )
            .await?;
        Ok(PreparedApp {
            bindings,
            compiled,
            enrollments,
            scopes,
        })
    }
    #[allow(clippy::too_many_arguments)]
    async fn endpoint_scopes(
        &self,
        session: &DataSession<'_>,
        deltas: &[EndpointGrantDelta],
        next: &[BoundChannel],
        previous: &[BoundChannel],
        console: Option<&str>,
        exclude: Option<&str>,
        enrollments: &[(EndpointEnrollment, String)],
    ) -> Result<Vec<EndpointScope>, DataError> {
        let fleet = self.fleet(session).await?;
        let manifest: VersionedConfig<BindingManifest> = self
            .documents
            .config_read(session, BINDING_MANIFEST_SERVICE)
            .await?;
        let apps = self.apps(session).await?;
        plan_endpoint_scopes(
            &fleet,
            &manifest,
            &apps,
            session.operator_omni,
            EndpointChange {
                deltas,
                next,
                previous,
                current_console: console,
                exclude,
                enrollments,
            },
        )
    }
    pub(super) async fn install_build(
        &self,
        session: &DataSession<'_>,
        device: Option<&DeviceIdentity>,
        request: AppInstallBuildRequest,
    ) -> Result<Value, DataError> {
        let label = request.label.trim().to_lowercase();
        if self
            .apps(session)
            .await?
            .live()
            .any(|app| app.label == label)
        {
            return Err(http_error(
                409,
                json!({"error":"application already exists"}),
            ));
        }
        let bundle = self.bundle(request.template_id.trim()).await?;
        let prepared = self
            .prepare(
                session,
                device,
                &bundle.manifest,
                &label,
                request.memory_ns.as_deref(),
                request.bindings,
                request.enroll_endpoints,
                None,
            )
            .await?;
        let build_request = BuildSpawnUserOpRequest {
            operator_omni: normalize_omni_0x(session.operator_omni),
            label: label.clone(),
            preset_id: request.template_id.clone(),
            memory_ns: request.memory_ns,
            memory_inherited: request.memory_inherited,
            bindings: Some(prepared.bindings.clone()),
            endpoint_scopes: prepared.scopes.clone(),
            endpoint_enrollments: prepared
                .enrollments
                .iter()
                .map(|(enrollment, _)| enrollment.clone())
                .collect(),
        };
        let build: Value = self
            .post(session, "/v1/agent/spawn/build", &build_request)
            .await?;
        let parsed: BuildSpawnUserOpResponse = decode(build.clone())?;
        if parsed.services != prepared.compiled.services
            || parsed.bound_channels != prepared.compiled.bound_channels
        {
            return Err(invalid(
                "broker build differs from the compiled application",
            ));
        }
        let row = AppInstanceRow {
            label: label.clone(),
            template_id: request.template_id.clone(),
            template_version: bundle.manifest.version.clone(),
            template_schema: bundle.manifest.app.schema,
            actor_omni: parsed.actor_omni,
            device_key_hash: parsed.device_key_hash,
            memory_ns: parsed.memory_ns,
            chat_channel_id: parsed.chat_channel_id,
            bindings: prepared.bindings,
            bound_channels: parsed.bound_channels,
            services: parsed.services,
            availability: parsed.availability,
            status: AppInstanceStatus::Installed,
            installed_at: session.now_unix_seconds,
            uninstalled_at: None,
            resources_kept: None,
            reach_aliases: vec![label.clone()],
            anchor: None,
        };
        self.pending.borrow_mut().insert(
            operation_key(&build)?,
            PendingApp {
                operator: norm(session.operator_omni),
                route: "/v1/master/apps/install/submit".into(),
                build: build.clone(),
                row: Some(row),
                previous: None,
                label,
                enrollments: prepared.enrollments,
                resources_kept: false,
                seals: vec![],
                receipt: None,
            },
        );
        Ok(
            json!({"build":build,"template_id":request.template_id,"template_version":bundle.manifest.version,"endpoint_scopes":prepared.scopes,"endpoint_enrollments":build_request.endpoint_enrollments,"manifest":bundle.manifest}),
        )
    }
    pub(super) async fn spawn_build(
        &self,
        session: &DataSession<'_>,
        device: Option<&DeviceIdentity>,
        mut body: Value,
    ) -> Result<Value, DataError> {
        body["operator_omni"] = json!(normalize_omni_0x(session.operator_omni));
        let mut request: BuildSpawnUserOpRequest = decode(body)?;
        if request.bindings.is_some()
            || !request.endpoint_scopes.is_empty()
            || !request.endpoint_enrollments.is_empty()
        {
            return Err(invalid("application bindings use the install route"));
        }
        let device =
            device.ok_or_else(|| invalid("unlock this console before creating a delegate"))?;
        let mut console = self.console_actor(session, Some(device)).await?;
        let mut enrollments = vec![];
        if console.is_none() {
            let pending = self
                .claim_console(session, device, &console_label(device)?)
                .await?;
            console = Some(pending.0.actor_omni.clone());
            enrollments.push(pending);
        }
        request.endpoint_scopes = self
            .endpoint_scopes(
                session,
                &[],
                &[console_chat(&opchat_channel_id(&request.label))],
                &[],
                console.as_deref(),
                None,
                &enrollments,
            )
            .await?;
        request.endpoint_enrollments = enrollments
            .iter()
            .map(|(enrollment, _)| enrollment.clone())
            .collect();
        let mut build: Value = self
            .post(session, "/v1/agent/spawn/build", &request)
            .await?;
        build["label"] = json!(request.label);
        build["preset_id"] = json!(request.preset_id);
        self.pending.borrow_mut().insert(
            operation_key(&build)?,
            PendingApp {
                operator: norm(session.operator_omni),
                route: "/v1/agent/spawn/submit".into(),
                build: build.clone(),
                row: None,
                previous: None,
                label: request.label,
                enrollments,
                resources_kept: false,
                seals: vec![],
                receipt: None,
            },
        );
        Ok(build)
    }
    pub(super) async fn archive_build(
        &self,
        session: &DataSession<'_>,
        mut body: Value,
        row: Option<AppInstanceRow>,
        device: Option<&DeviceIdentity>,
    ) -> Result<Value, DataError> {
        body["operator_omni"] = json!(normalize_omni_0x(session.operator_omni));
        let mut request: BuildArchiveUserOpRequest = decode(body)?;
        let fleet = self.fleet(session).await?;
        if !fleet.devices.iter().any(|entry| {
            norm(&entry.device.device_key_hash) == norm(&request.device_key_hash)
                && entry.device.tier == 2
                && !entry.device.revoked
        }) {
            return Err(invalid("active delegate not found"));
        }
        if let Some(row) = &row {
            if row.status != AppInstanceStatus::Installed {
                return Err(invalid("application is not installed"));
            }
            let console = self.console_actor(session, device).await?;
            let mut previous = row.bound_channels.clone();
            previous.push(console_chat(&row.chat_channel_id));
            request.endpoint_scopes = self
                .endpoint_scopes(
                    session,
                    &[],
                    &[],
                    &previous,
                    console.as_deref(),
                    Some(&row.label),
                    &[],
                )
                .await?;
        }
        if row.is_none() {
            let manifest: VersionedConfig<BindingManifest> = self
                .documents
                .config_read(session, BINDING_MANIFEST_SERVICE)
                .await?;
            if let Some(entry) = manifest.entry_for("", &request.device_key_hash) {
                let console = self.console_actor(session, device).await?;
                request.endpoint_scopes = self
                    .endpoint_scopes(
                        session,
                        &[],
                        &[],
                        &[console_chat(&opchat_channel_id(&entry.label))],
                        console.as_deref(),
                        None,
                        &[],
                    )
                    .await?;
            }
        }
        let mut build: Value = self
            .post(session, "/v1/agent/archive/build", &request)
            .await?;
        build["endpoint_scopes"] = encode(&request.endpoint_scopes)?;
        let route = row
            .as_ref()
            .map(|row| format!("/v1/master/apps/{}/uninstall/submit", row.label))
            .unwrap_or_else(|| "/v1/agent/archive/submit".into());
        self.pending.borrow_mut().insert(
            operation_key(&build)?,
            PendingApp {
                operator: norm(session.operator_omni),
                route,
                build: build.clone(),
                row: row.clone(),
                previous: row.clone(),
                label: row
                    .as_ref()
                    .map(|row| row.label.clone())
                    .unwrap_or_default(),
                enrollments: vec![],
                resources_kept: request.resources_kept,
                seals: vec![],
                receipt: None,
            },
        );
        let mut result = build;
        result["endpoint_scopes"] = encode(request.endpoint_scopes)?;
        if let Some(row) = row {
            result["label"] = json!(row.label);
        }
        Ok(result)
    }
    pub(super) async fn rebind_build(
        &self,
        session: &DataSession<'_>,
        device: Option<&DeviceIdentity>,
        label: &str,
        request: AppRebindBuildRequest,
    ) -> Result<Value, DataError> {
        let previous = self.app(session, label).await?;
        if previous.status != AppInstanceStatus::Installed {
            return Err(invalid("application is not installed"));
        }
        let bundle = self.bundle(&previous.template_id).await?;
        let mut bindings = previous.bindings.clone();
        let mut changes = vec![];
        for mut wanted in request.slots {
            if slot_kind(&bundle.manifest, &wanted.slot).is_none() {
                return Err(invalid(format!("unknown slot {}", wanted.slot)));
            }
            if wanted.channel_id.trim().is_empty() {
                return Err(invalid("channel_id required"));
            }
            let prior = bindings
                .slots
                .iter()
                .find(|slot| slot.slot == wanted.slot)
                .cloned();
            if wanted.description.is_none() {
                wanted.description = prior.as_ref().and_then(|slot| slot.description.clone());
            }
            if prior.as_ref() != Some(&wanted) {
                changes.push(format!(
                    "{}: {} → {}",
                    wanted.slot,
                    prior
                        .as_ref()
                        .map(|slot| slot.channel_id.as_str())
                        .unwrap_or("(unbound)"),
                    wanted.channel_id
                ));
            }
            bindings.slots.retain(|slot| slot.slot != wanted.slot);
            bindings.slots.push(wanted);
        }
        if bundle.manifest.version != previous.template_version {
            changes.push(format!(
                "template: {} → {}",
                previous.template_version, bundle.manifest.version
            ));
        }
        let prepared = self
            .prepare(
                session,
                device,
                &bundle.manifest,
                label,
                Some(&previous.memory_ns),
                bindings,
                request.enroll_endpoints,
                Some(&previous),
            )
            .await?;
        if changes.is_empty() {
            let fleet = self.fleet(session).await?;
            let console_change = !prepared.enrollments.is_empty()
                || prepared.scopes.iter().any(|scope| {
                    fleet
                        .devices
                        .iter()
                        .find(|entry| norm(&entry.device.actor_omni) == norm(&scope.actor_omni))
                        .is_none_or(|entry| {
                            scope.services.iter().any(|service| {
                                !entry
                                    .scope
                                    .service_ids
                                    .iter()
                                    .any(|hash| norm(hash) == norm(&service_hash(service)))
                            })
                        })
                });
            if !console_change {
                return Err(invalid("nothing to change"));
            }
            changes.push("console channel access".into());
        }
        let request = RebindBuildRequest {
            operator_omni: normalize_omni_0x(session.operator_omni),
            device_key_hash: previous.device_key_hash.clone(),
            services: prepared.compiled.services.clone(),
            preserve_service_ids: preserve_delegate_services(
                &self.fleet(session).await?,
                &previous,
            )?,
            endpoint_scopes: prepared.scopes.clone(),
            endpoint_enrollments: prepared
                .enrollments
                .iter()
                .map(|(enrollment, _)| enrollment.clone())
                .collect(),
            bound_channels: prepared.compiled.bound_channels.clone(),
        };
        let build: Value = self
            .post(session, "/v1/agent/rebind/build", &request)
            .await?;
        let mut row = previous.clone();
        row.bindings = prepared.bindings;
        row.bound_channels = prepared.compiled.bound_channels;
        row.services = prepared.compiled.services;
        row.template_version = bundle.manifest.version;
        self.pending.borrow_mut().insert(
            operation_key(&build)?,
            PendingApp {
                operator: norm(session.operator_omni),
                route: format!("/v1/master/apps/{label}/rebind/submit"),
                build: build.clone(),
                row: Some(row.clone()),
                previous: Some(previous),
                label: label.into(),
                enrollments: prepared.enrollments,
                resources_kept: false,
                seals: vec![],
                receipt: None,
            },
        );
        Ok(
            json!({"build":build,"label":label,"services":row.services,"bound_channels":row.bound_channels,"endpoint_scopes":request.endpoint_scopes,"endpoint_enrollments":request.endpoint_enrollments,"changes":changes}),
        )
    }
    pub(super) async fn seal_build(
        &self,
        session: &DataSession<'_>,
        request: AppAnchorsSealRequest,
    ) -> Result<Value, DataError> {
        let apps = self.apps(session).await?;
        let rows = apps
            .live()
            .filter(|row| {
                row.anchor.is_none()
                    && (request.labels.is_empty() || request.labels.contains(&row.label))
            })
            .cloned()
            .collect::<Vec<_>>();
        if rows.is_empty() {
            return Err(invalid("no unsealed applications"));
        }
        let build: Value = self
            .post(
                session,
                "/v1/agent/anchors/build",
                &AnchorsBuildRequest {
                    operator_omni: normalize_omni_0x(session.operator_omni),
                    device_key_hashes: rows.iter().map(|row| row.device_key_hash.clone()).collect(),
                },
            )
            .await?;
        let seals = build
            .get("seals")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("missing context seals"))?
            .iter()
            .map(|seal| {
                let hash = required(seal, "device_key_hash")?;
                let row = rows
                    .iter()
                    .find(|row| norm(&row.device_key_hash) == norm(hash))
                    .ok_or_else(|| invalid("seal does not match requested delegate"))?;
                Ok((row.clone(), decode::<ContextSeal>(seal.clone())?))
            })
            .collect::<Result<Vec<_>, DataError>>()?;
        if seals.len() != rows.len() {
            return Err(invalid("incomplete context seal build"));
        }
        self.pending.borrow_mut().insert(
            operation_key(&build)?,
            PendingApp {
                operator: norm(session.operator_omni),
                route: "/v1/master/apps/anchors/seal/submit".into(),
                build: build.clone(),
                row: None,
                previous: None,
                label: String::new(),
                enrollments: vec![],
                resources_kept: false,
                seals,
                receipt: None,
            },
        );
        Ok(build)
    }
    pub(super) async fn submit(
        &self,
        session: &DataSession<'_>,
        route: &str,
        body: Value,
    ) -> Result<Value, DataError> {
        let request: SubmitAcceptUserOpRequest = decode(body.clone())?;
        let key = operation_key(&body)?;
        let mut pending = self.pending.borrow().get(&key).cloned().ok_or_else(|| {
            http_error(
                409,
                json!({"error":"rebuild this action in the current session before submitting"}),
            )
        })?;
        if pending.operator != norm(session.operator_omni) || pending.route != route {
            return Err(http_error(
                403,
                json!({"error":"approval belongs to another account or action"}),
            ));
        }
        let endpoint = if route.ends_with("uninstall/submit") || route == "/v1/agent/archive/submit"
        {
            "/v1/agent/archive/submit"
        } else if route.ends_with("install/submit") || route == "/v1/agent/spawn/submit" {
            "/v1/agent/spawn/submit"
        } else if route == "/v1/master/console/device/enroll/submit" {
            "/v1/accept/submit"
        } else {
            "/v1/scope/submit"
        };
        let receipt = match pending.receipt.clone() {
            Some(receipt) if !receipt_needs_refresh(&receipt) => receipt,
            Some(_) => {
                let context_docs = pending
                    .build
                    .get("context_seal")
                    .and_then(|seal| seal.get("context_doc"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .into_iter()
                    .collect();
                self.post(
                    session,
                    "/v1/accept/receipt",
                    &AcceptReceiptRequest {
                        user_op: request.user_op.clone(),
                        context_docs,
                    },
                )
                .await?
            }
            None => {
                pending.receipt = Some(json!({"pending":true}));
                self.pending
                    .borrow_mut()
                    .insert(key.clone(), pending.clone());
                match self.post(session, endpoint, &request).await {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        if matches!(
                            error,
                            DataError::Http {
                                status: 400 | 401 | 403 | 404 | 422,
                                ..
                            }
                        ) {
                            pending.receipt = None;
                            self.pending.borrow_mut().insert(key.clone(), pending);
                        }
                        return Err(error);
                    }
                }
            }
        };
        pending.receipt = Some(receipt.clone());
        self.pending
            .borrow_mut()
            .insert(key.clone(), pending.clone());
        if receipt.get("pending").and_then(Value::as_bool) == Some(true) {
            return Ok(receipt);
        }
        if receipt.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(invalid("broker did not confirm the operation"));
        }

        let result=self.after_confirm(session,&pending,receipt).await.map_err(|error|http_error(502,json!({"error":"post_confirm_failed","chain_confirmed":true,"detail":error.to_string(),"retry":"retry this same signed action to finish metadata without broadcasting again"})))?;
        self.pending.borrow_mut().remove(&key);
        Ok(result)
    }
    async fn after_confirm(
        &self,
        session: &DataSession<'_>,
        pending: &PendingApp,
        mut receipt: Value,
    ) -> Result<Value, DataError> {
        if receipt_needs_refresh(&receipt) {
            return Err(invalid(format!(
                "confirmed operation needs ceremony recovery: {receipt}"
            )));
        }
        let archived = pending.route.ends_with("uninstall/submit")
            || pending.route == "/v1/agent/archive/submit";
        let spawned = pending.route.ends_with("install/submit") && !archived
            || pending.route == "/v1/agent/spawn/submit";
        let fleet = self.fleet(session).await?;
        let mut manifest: VersionedConfig<BindingManifest> = self
            .documents
            .config_read(session, BINDING_MANIFEST_SERVICE)
            .await?;
        for (enrollment, _) in &pending.enrollments {
            require_fleet_device(
                &fleet,
                &enrollment.device_key_hash,
                &enrollment.actor_omni,
                false,
            )?;
            manifest.upsert(BindingManifestEntry {
                actor_omni: enrollment.actor_omni.clone(),
                device_key_hash: enrollment.device_key_hash.clone(),
                label: enrollment.label.clone(),
                kind: if enrollment.kind == "console" {
                    "console"
                } else {
                    "device"
                }
                .into(),
                updated_at: session.now_unix_seconds,
                ..Default::default()
            });
        }
        if let Some(scopes) = pending.build.get("endpoint_scopes") {
            let scopes: Vec<EndpointScope> = decode(scopes.clone())?;
            for scope in scopes {
                let confirmed = fleet
                    .devices
                    .iter()
                    .find(|entry| {
                        owned_device(entry, session.operator_omni, 3)
                            && norm(&entry.device.actor_omni) == norm(&scope.actor_omni)
                    })
                    .ok_or_else(|| invalid("confirmed console endpoint is missing"))?;
                if scope.services.iter().any(|service| {
                    !confirmed
                        .scope
                        .service_ids
                        .iter()
                        .any(|hash| norm(hash) == norm(&service_hash(service)))
                }) || scope.preserve_service_ids.iter().any(|hash| {
                    !confirmed
                        .scope
                        .service_ids
                        .iter()
                        .any(|current| norm(current) == norm(hash))
                }) {
                    return Err(invalid("confirmed endpoint grants differ from approval"));
                }
                if let Some(entry) = manifest.bindings.iter_mut().find(|entry| {
                    norm(&entry.actor_omni) == norm(&scope.actor_omni)
                        && norm(&entry.device_key_hash) == norm(&confirmed.device.device_key_hash)
                }) {
                    entry.granted_service_names = scope.services;
                    entry.updated_at = session.now_unix_seconds;
                }
            }
        }
        if pending.route == "/v1/master/console/device/enroll/submit" {
            self.documents
                .config_write(session, BINDING_MANIFEST_SERVICE, &manifest)
                .await?;
            for (_, request_id) in &pending.enrollments {
                self.broker
                    .ack_binding(session.bearer, request_id)
                    .await
                    .map_err(broker_error)?;
            }
            let enrollment = &pending
                .enrollments
                .first()
                .ok_or_else(|| invalid("missing console enrollment"))?
                .0;
            receipt["ok"] = json!(true);
            receipt["actor_omni"] = json!(enrollment.actor_omni);
            receipt["device_key_hash"] = json!(enrollment.device_key_hash);
            receipt["label"] = json!(enrollment.label);
            return Ok(receipt);
        }
        let mut registry = self.apps(session).await?;
        let mut row = pending.row.clone();
        if let Some(row) = row.as_mut() {
            require_fleet_device(&fleet, &row.device_key_hash, &row.actor_omni, archived)?;
            if let Some(current) = registry.find(&row.label) {
                if Some(current) != pending.previous.as_ref()
                    && !same_applied_row(
                        current,
                        row,
                        archived,
                        pending.resources_kept,
                        pending.build.get("context_seal"),
                    )
                {
                    return Err(http_error(
                        409,
                        json!({"error":"app metadata changed while approval was open"}),
                    ));
                }
            }
            if archived {
                row.status = AppInstanceStatus::Uninstalled;
                row.uninstalled_at = Some(session.now_unix_seconds);
                row.resources_kept = Some(pending.resources_kept);
            } else {
                let chain = fleet
                    .devices
                    .iter()
                    .find(|entry| norm(&entry.device.device_key_hash) == norm(&row.device_key_hash))
                    .ok_or_else(|| invalid("delegate missing from chain"))?;
                if row.services.iter().any(|service| {
                    !chain
                        .scope
                        .service_ids
                        .iter()
                        .any(|hash| norm(hash) == norm(&service_hash(service)))
                }) {
                    return Err(invalid("confirmed delegate grants differ from build"));
                }
                if let Some(seal) = pending
                    .build
                    .get("context_seal")
                    .filter(|seal| !seal.is_null())
                {
                    let seal: ContextSeal = decode(seal.clone())?;
                    self.store_context(session, &row.memory_ns, &seal).await?;
                    row.anchor = Some(anchor(&seal, &receipt, session.now_unix_seconds));
                }
            }
            registry.upsert(row.clone());
        }
        if spawned {
            let built: BuildSpawnUserOpResponse = decode(pending.build.clone())?;
            require_fleet_device(&fleet, &built.device_key_hash, &built.actor_omni, false)?;
            let outcome = receipt
                .pointer("/ceremony/spawned")
                .and_then(Value::as_array)
                .and_then(|rows| {
                    rows.iter().find(|value| {
                        value
                            .get("device_key_hash")
                            .and_then(Value::as_str)
                            .is_some_and(|hash| norm(hash) == norm(&built.device_key_hash))
                    })
                })
                .ok_or_else(|| invalid("receipt does not confirm the requested delegate"))?;
            if let Some(error) = outcome.get("error").and_then(Value::as_str) {
                return Err(invalid(error));
            }
            manifest.upsert(BindingManifestEntry {
                actor_omni: built.actor_omni.clone(),
                device_key_hash: built.device_key_hash.clone(),
                label: pending.label.clone(),
                kind: "delegate".into(),
                granted_service_names: built.services,
                updated_at: session.now_unix_seconds,
                preset_id: Some(
                    row.as_ref()
                        .map(|row| row.template_id.clone())
                        .unwrap_or_else(|| {
                            pending
                                .build
                                .get("preset_id")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .into()
                        }),
                ),
                agent_url: outcome
                    .pointer("/sandbox/agent_url")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                memory_ns: Some(built.memory_ns),
                runtime: Some(ApiRuntimeStatus {
                    gate_status: outcome
                        .pointer("/gate/status")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .into(),
                    gate_error: outcome
                        .pointer("/gate/error")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    spawn_error: outcome
                        .pointer("/sandbox/error")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                }),
                ..Default::default()
            });
        } else if archived {
            let hash = required(&pending.build, "device_key_hash")?;
            require_fleet_device(&fleet, hash, "", true)?;
            let entry = manifest
                .entry_for("", hash)
                .cloned()
                .ok_or_else(|| invalid("archived delegate metadata is missing"))?;
            let mut entry = entry;
            entry.archived_at = Some(session.now_unix_seconds);
            entry.resources_kept = Some(pending.resources_kept);
            manifest.upsert(entry);
        } else if let Some(row) = &row {
            let mut entry = manifest
                .entry_for(&row.actor_omni, &row.device_key_hash)
                .cloned()
                .ok_or_else(|| invalid("delegate metadata is missing"))?;
            entry.granted_service_names = row.services.clone();
            entry.updated_at = session.now_unix_seconds;
            manifest.upsert(entry);
        }
        for (original, seal) in &pending.seals {
            let mut sealed = original.clone();
            require_fleet_device(&fleet, &sealed.device_key_hash, &sealed.actor_omni, false)?;
            self.store_context(session, &sealed.memory_ns, seal).await?;
            sealed.anchor = Some(anchor(seal, &receipt, session.now_unix_seconds));
            self.update_runtime(session, &sealed, Some(seal)).await?;
            registry.upsert(sealed);
        }
        self.documents
            .config_write(session, BINDING_MANIFEST_SERVICE, &manifest)
            .await?;
        for (_, request_id) in &pending.enrollments {
            self.broker
                .ack_binding(session.bearer, request_id)
                .await
                .map_err(broker_error)?;
        }
        if row.is_some() || !pending.seals.is_empty() {
            self.documents
                .config_write(session, APP_REGISTRY_SERVICE, &registry)
                .await?;
        }
        if let Some(row) = &row {
            self.update_channels(session, row, pending.previous.as_ref(), !archived)
                .await?;
            if !archived {
                let seal = pending
                    .build
                    .get("context_seal")
                    .filter(|seal| !seal.is_null())
                    .cloned()
                    .map(decode::<ContextSeal>)
                    .transpose()?;
                receipt["runtime"] = self.update_runtime(session, row, seal.as_ref()).await?;
            }
            let mut refresh_channels = row
                .bound_channels
                .iter()
                .chain(
                    pending
                        .previous
                        .iter()
                        .flat_map(|previous| previous.bound_channels.iter()),
                )
                .filter(|channel| channel.kind == ChannelEndpointKind::Messaging)
                .map(|channel| channel.channel_id.clone())
                .collect::<Vec<_>>();
            refresh_channels.sort();
            refresh_channels.dedup();
            for channel in refresh_channels {
                self.refresh_channel_defaults(session, &channel).await?;
            }
            let summary = json!({"label":row.label,"registry_storage":"ok","bound_channels":row.bound_channels,"anchor":row.anchor});
            receipt[if archived {
                "uninstalled"
            } else if spawned {
                "installed"
            } else {
                "rebound"
            }] = if spawned { json!([summary]) } else { summary };
        } else if spawned {
            let built: BuildSpawnUserOpResponse = decode(pending.build.clone())?;
            self.name_channel(
                session,
                &built.chat_channel_id,
                &opchat_display_name(&pending.label),
                ChannelEndpointKind::Chat,
                None,
            )
            .await?;
        }
        if !archived
            && (spawned
                || pending
                    .previous
                    .as_ref()
                    .zip(row.as_ref())
                    .is_some_and(|(old, new)| old.template_version != new.template_version))
        {
            let actor = row
                .as_ref()
                .map(|row| row.actor_omni.as_str())
                .or_else(|| pending.build.get("actor_omni").and_then(Value::as_str))
                .ok_or_else(|| invalid("actor missing"))?;
            let hash = row
                .as_ref()
                .map(|row| row.device_key_hash.as_str())
                .or_else(|| pending.build.get("device_key_hash").and_then(Value::as_str))
                .ok_or_else(|| invalid("device missing"))?;
            let preset = row
                .as_ref()
                .map(|row| row.template_id.as_str())
                .or_else(|| pending.build.get("preset_id").and_then(Value::as_str))
                .unwrap_or("");
            if !preset.is_empty() {
                receipt["preset_apply"] = crate::console_runtime::apply_preset(
                    &self.broker,
                    &self.data,
                    session,
                    actor,
                    hash,
                    preset,
                )
                .await?;
            }
        }
        if !pending.seals.is_empty() {
            receipt["sealed"]=json!(pending.seals.iter().map(|(row,seal)|json!({"label":row.label,"version":seal.context_version,"hash":seal.context_hash,"context_storage":"durable"})).collect::<Vec<_>>());
            receipt["registry_storage"] = json!("ok");
        }
        Ok(receipt)
    }
    async fn store_context(
        &self,
        session: &DataSession<'_>,
        namespace: &str,
        seal: &ContextSeal,
    ) -> Result<(), DataError> {
        if blob_hash(seal.context_doc.as_bytes()) != seal.context_hash {
            return Err(invalid("context document hash differs from seal"));
        }
        let mut entries = self.documents.namespace_read(session, namespace).await?;
        entries.retain(|entry| entry.key != CONTEXT_ENTRY_KEY);
        entries.push(StoredMemoryEntry {
            key: CONTEXT_ENTRY_KEY.into(),
            title: format!("runtime context v{}", seal.context_version),
            body: seal.context_doc.clone(),
            updated: today(session.now_unix_seconds),
            bytes: seal.context_doc.len() as u64,
            version: format!("v{}", seal.context_version),
            kind: ContextKind::Context,
        });
        self.documents
            .namespace_write(session, namespace, &entries)
            .await
    }
    async fn update_runtime(
        &self,
        session: &DataSession<'_>,
        row: &AppInstanceRow,
        seal: Option<&ContextSeal>,
    ) -> Result<Value, DataError> {
        let mut response: Value = self
            .post(
                session,
                "/v1/agent/spawn/context/update",
                &SpawnContextUpdateRequest {
                    operator_omni: normalize_omni_0x(session.operator_omni),
                    device_key_hash: row.device_key_hash.clone(),
                    bound_channels: row.bound_channels.clone(),
                    context_version: seal.map(|seal| seal.context_version),
                    context_hash: seal.map(|seal| seal.context_hash.clone()),
                },
            )
            .await?;
        if response.pointer("/runtime/mode").and_then(Value::as_str) == Some("failed") {
            return Err(invalid(format!(
                "runtime refused updated bindings: {response}"
            )));
        }
        if response.pointer("/runtime/mode").and_then(Value::as_str) == Some("unsupported") {
            let updated = crate::console_runtime::request(
                &self.broker,
                &self.data,
                session,
                "POST",
                "/v1/agent/update",
                encode(DaemonAgentUpdateRequest {
                    device_key_hash: row.device_key_hash.clone(),
                    force: false,
                })?,
            )
            .await?
            .ok_or_else(|| invalid("runtime recreation unavailable"))?;
            if updated
                .get("sandbox_error")
                .is_some_and(|error| !error.is_null())
            {
                return Err(invalid(format!("runtime recreation failed: {updated}")));
            }
            response["runtime"]["recreate"] = updated;
        }
        Ok(response)
    }
    pub(super) async fn context(
        &self,
        session: &DataSession<'_>,
        label: &str,
    ) -> Result<Value, DataError> {
        let row = self.app(session, label).await?;
        let entries = self
            .documents
            .namespace_read(session, &row.memory_ns)
            .await?;
        let raw = entries
            .iter()
            .find(|entry| entry.key == CONTEXT_ENTRY_KEY)
            .map(|entry| entry.body.clone());
        let hash = raw.as_ref().map(|raw| blob_hash(raw.as_bytes()));
        let doc = raw
            .as_ref()
            .map(|raw| serde_json::from_str::<DelegateContextDoc>(raw).map_err(invalid))
            .transpose()?;
        Ok(
            json!({"label":label,"source":if raw.is_some(){"memory-plane"}else{"absent"},"matches_anchor":hash.as_ref().zip(row.anchor.as_ref()).is_some_and(|(hash,anchor)|hash.eq_ignore_ascii_case(&anchor.hash)),"matches_row":doc.as_ref().is_some_and(|doc|doc.bound_channels==row.bound_channels),"doc":doc,"doc_json":raw,"hash":hash,"anchor":row.anchor}),
        )
    }
    pub(super) async fn rehydrate(
        &self,
        session: &DataSession<'_>,
        request: AppAnchorsSealRequest,
    ) -> Result<Value, DataError> {
        let apps = self.apps(session).await?;
        let mut results = vec![];
        for row in apps
            .live()
            .filter(|row| request.labels.is_empty() || request.labels.contains(&row.label))
        {
            let entries = self
                .documents
                .namespace_read(session, &row.memory_ns)
                .await?;
            let raw = entries
                .iter()
                .find(|entry| entry.key == CONTEXT_ENTRY_KEY)
                .ok_or_else(|| invalid(format!("{} has no sealed context document", row.label)))?;
            let result: Value = self
                .post(
                    session,
                    "/v1/agent/spawn/context/rehydrate",
                    &RehydrateRequest {
                        operator_omni: normalize_omni_0x(session.operator_omni),
                        context_doc: raw.body.clone(),
                    },
                )
                .await?;
            results.push(json!({"label":row.label,"status":200,"result":result}));
        }
        Ok(json!({"ok":true,"results":results}))
    }
}
fn service_hash(service: &str) -> String {
    blob_hash(service.to_ascii_lowercase().as_bytes())
}
fn require_fleet_device(
    fleet: &ConsoleFleet,
    hash: &str,
    actor: &str,
    archived: bool,
) -> Result<(), DataError> {
    let entry = fleet
        .devices
        .iter()
        .find(|entry| norm(&entry.device.device_key_hash) == norm(hash));
    if archived {
        if entry.is_some_and(|entry| !entry.device.revoked) {
            return Err(invalid("archive is not confirmed on chain"));
        }
    } else if entry.is_none_or(|entry| {
        entry.device.revoked
            || norm(&entry.device.actor_omni) != norm(actor)
            || norm(&entry.device.operator_omni) != norm(&fleet.operator_omni)
    }) {
        return Err(invalid("requested binding is not confirmed on chain"));
    }
    Ok(())
}
fn anchor(seal: &ContextSeal, receipt: &Value, now: u64) -> AppAnchor {
    AppAnchor {
        version: seal.context_version,
        hash: seal.context_hash.clone(),
        tx_hash: receipt
            .get("tx_hash")
            .and_then(Value::as_str)
            .map(str::to_owned),
        sealed_at: now,
    }
}
fn slot_kind(manifest: &PresetSummary, name: &str) -> Option<ChannelEndpointKind> {
    manifest
        .app
        .slots
        .iter()
        .find(|slot| slot.slot == name)
        .map(|slot| slot.kind)
}
fn seed_slot_descriptions(manifest: &PresetSummary, bindings: &mut AppInstallBindings) {
    for binding in &mut bindings.slots {
        if binding
            .description
            .as_deref()
            .is_some_and(|description| !description.trim().is_empty())
        {
            continue;
        }
        if let Some(slot) =
            manifest.app.slots.iter().find(|slot| {
                slot.slot == binding.slot && slot.kind == ChannelEndpointKind::Messaging
            })
        {
            let description = seed_binding_description(
                &slot.reason_zh,
                &slot.reason,
                &manifest.description_zh,
                &manifest.description,
                &manifest.route_examples,
            );
            binding.description = (!description.is_empty()).then_some(description);
        }
    }
}

impl ConsoleApps {
    pub(super) async fn name_channel(
        &self,
        session: &DataSession<'_>,
        id: &str,
        name: &str,
        kind: ChannelEndpointKind,
        actor: Option<String>,
    ) -> Result<(), DataError> {
        let mut registry: VersionedConfig<ChannelRegistry> = self
            .documents
            .config_read(session, CHANNEL_REGISTRY_SERVICE)
            .await?;
        let changed = if let Some(channel) = registry
            .channels
            .iter_mut()
            .find(|channel| channel.id == id)
        {
            let mut changed = false;
            if channel.kind.is_none() {
                channel.kind = Some(kind);
                changed = true;
            }
            if channel.endpoint_actor_omni.is_none() && actor.is_some() {
                channel.endpoint_actor_omni = actor;
                changed = true;
            }
            changed
        } else {
            registry.channels.push(ApiChannel {
                id: id.into(),
                name: name.into(),
                note: None,
                created_at: session.now_unix_seconds,
                kind: Some(kind),
                endpoint_actor_omni: actor,
            });
            true
        };
        if changed {
            self.documents
                .config_write(session, CHANNEL_REGISTRY_SERVICE, &registry)
                .await?;
        }
        Ok(())
    }
    async fn gateway_mutate(
        &self,
        session: &DataSession<'_>,
        request: HostedGatewayRequest,
    ) -> Result<Value, DataError> {
        let backup: VersionedConfig<ContactRegistry> = self
            .documents
            .config_read(session, GATEWAY_CONTACTS_SERVICE)
            .await?;
        let current: ContactRegistry = decode(
            self.gateway(session, HostedGatewayRequest::RegistryExport)
                .await?,
        )?;
        if registry_empty(&current) && !registry_empty(&backup.document) {
            self.gateway(
                session,
                HostedGatewayRequest::RegistryRestore {
                    registry: Box::new(backup.document.clone()),
                },
            )
            .await?;
        }
        let response = self.gateway(session, request).await?;
        let registry: ContactRegistry = decode(
            self.gateway(session, HostedGatewayRequest::RegistryExport)
                .await?,
        )?;
        self.documents
            .config_write(
                session,
                GATEWAY_CONTACTS_SERVICE,
                &VersionedConfig::new(registry, backup.revision),
            )
            .await
            .map_err(|error| {
                invalid(format!(
                    "contact gate changed; durable backup failed: {error}"
                ))
            })?;
        Ok(response)
    }
    async fn update_channels(
        &self,
        session: &DataSession<'_>,
        row: &AppInstanceRow,
        previous: Option<&AppInstanceRow>,
        add: bool,
    ) -> Result<(), DataError> {
        for bound in &row.bound_channels {
            self.name_channel(
                session,
                &bound.channel_id,
                &bound.channel_id,
                bound.kind,
                bound.endpoint_actor_omni.clone(),
            )
            .await?;
        }
        if !row.chat_channel_id.is_empty() {
            self.name_channel(
                session,
                &row.chat_channel_id,
                &opchat_display_name(&row.label),
                ChannelEndpointKind::Chat,
                None,
            )
            .await?;
        }
        let registry: VersionedConfig<ChannelRegistry> = self
            .documents
            .config_read(session, CHANNEL_REGISTRY_SERVICE)
            .await?;
        let old_channels = previous
            .map(|row| row.bound_channels.as_slice())
            .unwrap_or_default();
        for bound in old_channels.iter().filter(|bound| {
            bound.kind == ChannelEndpointKind::Messaging
                && !row
                    .bound_channels
                    .iter()
                    .any(|current| current.channel_id == bound.channel_id)
        }) {
            self.gateway_mutate(
                session,
                HostedGatewayRequest::ChannelsUpdate(Box::new(GatewayChannelUpdateRequest {
                    channel_id: bound.channel_id.clone(),
                    remove_app: Some(row.label.clone()),
                    ..Default::default()
                })),
            )
            .await?;
        }
        for bound in row
            .bound_channels
            .iter()
            .filter(|bound| bound.kind == ChannelEndpointKind::Messaging)
        {
            let update = if add {
                let name = registry
                    .channels
                    .iter()
                    .find(|channel| channel.id == bound.channel_id);
                GatewayChannelUpdateRequest {
                    channel_id: bound.channel_id.clone(),
                    name: name.map(|channel| channel.name.clone()),
                    purpose: name.and_then(|channel| channel.note.clone()),
                    app: Some(ChannelApp {
                        alias: row.label.clone(),
                        slot: bound.slot.clone(),
                        description: row
                            .bindings
                            .slots
                            .iter()
                            .find(|slot| slot.slot == bound.slot)
                            .and_then(|slot| slot.description.clone())
                            .unwrap_or_default(),
                        takes: bound.event_kinds.clone(),
                        audience: row
                            .bindings
                            .audience
                            .iter()
                            .find(|audience| audience.slot == bound.slot)
                            .map(|audience| audience.tiers.clone())
                            .unwrap_or_default(),
                    }),
                    ..Default::default()
                }
            } else {
                GatewayChannelUpdateRequest {
                    channel_id: bound.channel_id.clone(),
                    remove_app: Some(row.label.clone()),
                    ..Default::default()
                }
            };
            self.gateway_mutate(
                session,
                HostedGatewayRequest::ChannelsUpdate(Box::new(update)),
            )
            .await?;
            if add {
                let contacts: ContactRegistry = decode(
                    self.gateway(session, HostedGatewayRequest::RegistryExport)
                        .await?,
                )?;
                let tiers = row
                    .bindings
                    .audience
                    .iter()
                    .find(|audience| audience.slot == bound.slot)
                    .map(|audience| audience.tiers.as_slice())
                    .unwrap_or_default();
                for contact in contacts
                    .bound
                    .iter()
                    .filter(|contact| tiers.contains(&contact.tier))
                {
                    self.gateway_mutate(
                        session,
                        HostedGatewayRequest::ChannelsUpdate(Box::new(
                            GatewayChannelUpdateRequest {
                                channel_id: bound.channel_id.clone(),
                                member: Some(ChannelMember {
                                    contact_id: contact.contact_id.clone(),
                                    speak: true,
                                    read: true,
                                }),
                                ..Default::default()
                            },
                        )),
                    )
                    .await?;
                }
            }
        }
        if !row.chat_channel_id.is_empty() {
            let update = if add {
                GatewayChannelUpdateRequest {
                    channel_id: row.chat_channel_id.clone(),
                    name: Some(opchat_display_name(&row.label)),
                    purpose: Some(opchat_purpose(&row.label)),
                    operator_of: Some(row.label.clone()),
                    app: Some(ChannelApp {
                        alias: row.label.clone(),
                        slot: OPCHAT_SLOT_NAME.into(),
                        description: OPCHAT_DESCRIPTION_ZH.into(),
                        takes: vec![],
                        audience: vec![ContactTier::Owner],
                    }),
                    ..Default::default()
                }
            } else {
                GatewayChannelUpdateRequest {
                    channel_id: row.chat_channel_id.clone(),
                    remove: true,
                    ..Default::default()
                }
            };
            self.gateway_mutate(
                session,
                HostedGatewayRequest::ChannelsUpdate(Box::new(update)),
            )
            .await?;
        }
        Ok(())
    }
}
fn registry_empty(registry: &ContactRegistry) -> bool {
    registry.bound.is_empty()
        && registry.pending.is_empty()
        && registry.invites.is_empty()
        && registry.apps.is_empty()
        && registry.channels.is_empty()
        && registry.router.is_none()
}

fn same_applied_row(
    current: &AppInstanceRow,
    prepared: &AppInstanceRow,
    archived: bool,
    resources_kept: bool,
    seal: Option<&Value>,
) -> bool {
    let mut expected = prepared.clone();
    if archived {
        expected.status = AppInstanceStatus::Uninstalled;
        expected.uninstalled_at = current.uninstalled_at;
        expected.resources_kept = Some(resources_kept);
    }
    if let Some(seal) = seal
        .filter(|seal| !seal.is_null())
        .and_then(|seal| serde_json::from_value::<ContextSeal>(seal.clone()).ok())
    {
        if current.anchor.as_ref().is_none_or(|anchor| {
            anchor.hash != seal.context_hash || anchor.version != seal.context_version
        }) {
            return false;
        }
        expected.anchor = current.anchor.clone();
    }
    for channel in &mut expected.bound_channels {
        if let Some(applied) = current.bound_channels.iter().find(|applied| {
            applied.slot == channel.slot && applied.channel_id == channel.channel_id
        }) {
            channel.default_app = applied.default_app;
        }
    }
    expected == *current
}

fn console_chat(channel: &str) -> BoundChannel {
    BoundChannel {
        slot: OPCHAT_SLOT_NAME.into(),
        kind: ChannelEndpointKind::Chat,
        direction: SlotDirection::Duplex,
        channel_id: channel.into(),
        event_kinds: vec![ChannelEventKind::Text, ChannelEventKind::Command],
        endpoint_actor_omni: None,
        default_app: None,
    }
}

impl ConsoleApps {
    pub async fn refresh_channel_defaults(
        &self,
        session: &DataSession<'_>,
        channel_id: &str,
    ) -> Result<(), DataError> {
        if !valid_channel_id(channel_id) {
            return Err(invalid("invalid channel id"));
        }
        let gate: ContactRegistry = decode(
            self.gateway(session, HostedGatewayRequest::RegistryExport)
                .await?,
        )?;
        let mut registry = self.apps(session).await?;
        if !known_channel(&gate, &registry, channel_id) {
            return Err(http_error(
                404,
                json!({"error":"channel is not registered to this account"}),
            ));
        }
        let selected = gate
            .channels
            .iter()
            .find(|channel| channel.id == channel_id)
            .and_then(|channel| channel.default_or_only_app())
            .map(str::to_owned);
        let mut changed = false;
        for row in registry
            .apps
            .iter_mut()
            .filter(|row| row.status == AppInstanceStatus::Installed)
        {
            let mut row_changed = false;
            for channel in row.bound_channels.iter_mut().filter(|channel| {
                channel.kind == ChannelEndpointKind::Messaging && channel.channel_id == channel_id
            }) {
                let next = Some(
                    selected
                        .as_ref()
                        .is_some_and(|selected| selected.eq_ignore_ascii_case(&row.label)),
                );
                if channel.default_app != next {
                    channel.default_app = next;
                    row_changed = true;
                }
            }
            if row_changed {
                self.update_runtime(session, row, None).await?;
                changed = true;
            }
        }
        if changed {
            self.documents
                .config_write(session, APP_REGISTRY_SERVICE, &registry)
                .await?;
        }
        Ok(())
    }
}

fn receipt_needs_refresh(receipt: &Value) -> bool {
    receipt.get("pending").and_then(Value::as_bool) == Some(true)
        || receipt
            .pointer("/ceremony/spawned")
            .and_then(Value::as_array)
            .is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.get("error").is_some_and(|error| !error.is_null())
                        || row
                            .pointer("/sandbox/error")
                            .is_some_and(|error| !error.is_null())
                        || row
                            .pointer("/gate/error")
                            .is_some_and(|error| !error.is_null())
                })
            })
}
fn preserve_delegate_services(
    fleet: &ConsoleFleet,
    previous: &AppInstanceRow,
) -> Result<Vec<String>, DataError> {
    let device = fleet
        .devices
        .iter()
        .find(|entry| {
            norm(&entry.device.device_key_hash) == norm(&previous.device_key_hash)
                && norm(&entry.device.actor_omni) == norm(&previous.actor_omni)
                && !entry.device.revoked
        })
        .ok_or_else(|| invalid("active delegate not found"))?;
    let owned = previous
        .services
        .iter()
        .map(|service| norm(&service_hash(service)))
        .collect::<Vec<_>>();
    Ok(device
        .scope
        .service_ids
        .iter()
        .filter(|hash| !owned.contains(&norm(hash)))
        .cloned()
        .collect())
}
fn known_channel(gate: &ContactRegistry, apps: &AppRegistryDoc, channel_id: &str) -> bool {
    gate.channels.iter().any(|channel| channel.id == channel_id)
        || apps.apps.iter().any(|app| {
            app.bound_channels.iter().any(|channel| {
                channel.channel_id == channel_id && channel.kind == ChannelEndpointKind::Messaging
            })
        })
}

struct EndpointChange<'a> {
    deltas: &'a [EndpointGrantDelta],
    next: &'a [BoundChannel],
    previous: &'a [BoundChannel],
    current_console: Option<&'a str>,
    exclude: Option<&'a str>,
    enrollments: &'a [(EndpointEnrollment, String)],
}
fn owned_device(entry: &ConsoleFleetEntry, operator: &str, tier: u8) -> bool {
    !entry.device.revoked
        && entry.device.tier == tier
        && norm(&entry.device.operator_omni) == norm(operator)
}
fn active_owned_apps<'a>(
    fleet: &ConsoleFleet,
    apps: &'a AppRegistryDoc,
    operator: &str,
    exclude: Option<&str>,
) -> Vec<&'a AppInstanceRow> {
    apps.apps
        .iter()
        .filter(|app| {
            app.status == AppInstanceStatus::Installed
                && Some(app.label.as_str()) != exclude
                && fleet.devices.iter().any(|entry| {
                    owned_device(entry, operator, 2)
                        && norm(&entry.device.actor_omni) == norm(&app.actor_omni)
                        && norm(&entry.device.device_key_hash) == norm(&app.device_key_hash)
                })
        })
        .collect()
}
fn add_console_channel_services(
    services: &mut Vec<String>,
    channel: &BoundChannel,
) -> Result<(), DataError> {
    if !valid_channel_id(&channel.channel_id) {
        return Err(invalid("invalid application channel id"));
    }
    services.push(service_channel_sub(&channel.channel_id));
    if matches!(
        channel.kind,
        ChannelEndpointKind::Display | ChannelEndpointKind::Chat
    ) {
        services.push(service_channel_pub(&channel.channel_id));
    }
    Ok(())
}
pub(super) fn console_services_for_apps(
    fleet: &ConsoleFleet,
    apps: &AppRegistryDoc,
    operator: &str,
    exclude: Option<&str>,
) -> Result<Vec<String>, DataError> {
    if norm(&fleet.operator_omni) != norm(operator) {
        return Err(invalid("fleet belongs to another account"));
    }
    let mut services = vec![];
    for app in active_owned_apps(fleet, apps, operator, exclude) {
        for channel in &app.bound_channels {
            add_console_channel_services(&mut services, channel)?;
        }
        if !app.chat_channel_id.is_empty() {
            add_console_channel_services(&mut services, &console_chat(&app.chat_channel_id))?;
        }
    }
    services.sort();
    services.dedup();
    Ok(services)
}
fn plan_endpoint_scopes(
    fleet: &ConsoleFleet,
    manifest: &BindingManifest,
    apps: &AppRegistryDoc,
    operator: &str,
    change: EndpointChange<'_>,
) -> Result<Vec<EndpointScope>, DataError> {
    let mut common_console_services =
        console_services_for_apps(fleet, apps, operator, change.exclude)?;
    for channel in change.next {
        add_console_channel_services(&mut common_console_services, channel)?;
    }
    let mut additions = BTreeMap::<String, Vec<String>>::new();
    for delta in change.deltas {
        additions
            .entry(normalize_omni_0x(&delta.actor_omni))
            .or_default()
            .extend(delta.add.clone());
    }
    let mut consoles = manifest
        .bindings
        .iter()
        .filter(|binding| {
            binding.kind == "console"
                && binding.archived_at.is_none()
                && fleet.devices.iter().any(|entry| {
                    owned_device(entry, operator, 3)
                        && norm(&entry.device.actor_omni) == norm(&binding.actor_omni)
                        && norm(&entry.device.device_key_hash) == norm(&binding.device_key_hash)
                })
        })
        .map(|binding| normalize_omni_0x(&binding.actor_omni))
        .collect::<Vec<_>>();
    if let Some(current) = change.current_console {
        let is_owned = fleet.devices.iter().any(|entry| {
            owned_device(entry, operator, 3) && norm(&entry.device.actor_omni) == norm(current)
        });
        let enrolling = change.enrollments.iter().any(|(enrollment, _)| {
            enrollment.kind == "console" && norm(&enrollment.actor_omni) == norm(current)
        });
        if !is_owned && !enrolling {
            return Err(invalid("console is not an active device of this account"));
        }
        consoles.push(normalize_omni_0x(current));
    }
    consoles.sort();
    consoles.dedup();
    for console in consoles {
        additions
            .entry(console)
            .or_default()
            .extend(common_console_services.clone());
    }
    let other_apps = active_owned_apps(fleet, apps, operator, change.exclude);
    let dropped = change
        .previous
        .iter()
        .filter(|old| {
            !change
                .next
                .iter()
                .any(|new| new.channel_id == old.channel_id)
                && !other_apps.iter().any(|app| {
                    app.chat_channel_id == old.channel_id
                        || app
                            .bound_channels
                            .iter()
                            .any(|bound| bound.channel_id == old.channel_id)
                })
        })
        .flat_map(|channel| {
            [
                service_channel_pub(&channel.channel_id),
                service_channel_sub(&channel.channel_id),
            ]
        })
        .collect::<Vec<_>>();
    for channel in change.previous {
        if let Some(actor) = &channel.endpoint_actor_omni {
            additions.entry(normalize_omni_0x(actor)).or_default();
        }
    }
    let mut scopes = vec![];
    for (actor, added) in additions {
        let existing = fleet.devices.iter().find(|entry| {
            owned_device(entry, operator, 3) && norm(&entry.device.actor_omni) == norm(&actor)
        });
        if existing.is_none()
            && !change
                .enrollments
                .iter()
                .any(|(enrollment, _)| norm(&enrollment.actor_omni) == norm(&actor))
        {
            return Err(invalid("endpoint is not an active device of this account"));
        }
        let mut services = manifest
            .bindings
            .iter()
            .find(|binding| {
                norm(&binding.actor_omni) == norm(&actor)
                    && existing.is_some_and(|entry| {
                        norm(&binding.device_key_hash) == norm(&entry.device.device_key_hash)
                    })
            })
            .map(|binding| binding.granted_service_names.clone())
            .unwrap_or_default();
        services.retain(|service| {
            !dropped.contains(service)
                && existing.is_some_and(|entry| {
                    entry
                        .scope
                        .service_ids
                        .iter()
                        .any(|hash| norm(hash) == norm(&service_hash(service)))
                })
        });
        services.extend(added);
        services.sort();
        services.dedup();
        let named_hashes = services
            .iter()
            .chain(dropped.iter())
            .map(|service| service_hash(service))
            .collect::<Vec<_>>();
        let preserve_service_ids = existing
            .map(|entry| {
                entry
                    .scope
                    .service_ids
                    .iter()
                    .filter(|hash| !named_hashes.iter().any(|named| norm(named) == norm(hash)))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        scopes.push(EndpointScope {
            actor_omni: actor,
            services,
            preserve_service_ids,
        });
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row() -> AppInstanceRow {
        serde_json::from_value(json!({"label":"fixture-app","template_id":"fixture","template_version":"1","actor_omni":"0xaaaa","device_key_hash":"0xbbbb","memory_ns":"fixture","chat_channel_id":"opchat-fixture","installed_at":1,"services":["channel-pub:family"],"bound_channels":[{"slot":"family","kind":"messaging","direction":"duplex","channel_id":"family","event_kinds":[],"endpoint_actor_omni":null,"default_app":null}]})).unwrap()
    }
    fn chain_device(actor: &str, hash: &str, operator: &str, tier: u8) -> ConsoleFleetEntry {
        ConsoleFleetEntry {
            device: ConsoleChainDevice {
                actor_omni: actor.into(),
                device_key_hash: hash.into(),
                operator_omni: operator.into(),
                tier,
                revoked: false,
            },
            scope: ConsoleChainScope::default(),
        }
    }
    fn app(label: &str, actor: &str, hash: &str, kind: ChannelEndpointKind) -> AppInstanceRow {
        let mut app = row();
        app.label = label.into();
        app.actor_omni = actor.into();
        app.device_key_hash = hash.into();
        app.chat_channel_id = format!("opchat-{label}");
        app.bound_channels[0].channel_id = label.into();
        app.bound_channels[0].kind = kind;
        app
    }
    fn console_binding(actor: &str, hash: &str) -> BindingManifestEntry {
        BindingManifestEntry {
            actor_omni: actor.into(),
            device_key_hash: hash.into(),
            label: actor.into(),
            kind: "console".into(),
            ..Default::default()
        }
    }
    #[test]
    fn console_enrollment_aggregates_only_exact_active_owned_app_bindings() {
        let mut revoked = chain_device("revoked-actor", "revoked-key", "owner", 2);
        revoked.device.revoked = true;
        let fleet = ConsoleFleet {
            operator_omni: "owner".into(),
            account: "account".into(),
            devices: vec![
                chain_device("display-actor", "display-key", "owner", 2),
                chain_device("chat-actor", "chat-key", "owner", 2),
                chain_device("foreign-actor", "foreign-key", "someone-else", 2),
                revoked,
                chain_device("archived-actor", "archived-key", "owner", 2),
                chain_device("mismatch-actor", "other-key", "owner", 2),
                chain_device("device-actor", "device-key", "owner", 3),
            ],
        };
        let mut archived = app(
            "archived",
            "archived-actor",
            "archived-key",
            ChannelEndpointKind::Display,
        );
        archived.status = AppInstanceStatus::Uninstalled;
        let registry = AppRegistryDoc {
            apps: vec![
                app(
                    "display",
                    "display-actor",
                    "display-key",
                    ChannelEndpointKind::Display,
                ),
                app(
                    "family",
                    "chat-actor",
                    "chat-key",
                    ChannelEndpointKind::Messaging,
                ),
                app(
                    "foreign",
                    "foreign-actor",
                    "foreign-key",
                    ChannelEndpointKind::Display,
                ),
                app(
                    "revoked",
                    "revoked-actor",
                    "revoked-key",
                    ChannelEndpointKind::Display,
                ),
                archived,
                app(
                    "mismatch",
                    "mismatch-actor",
                    "claimed-key",
                    ChannelEndpointKind::Display,
                ),
                app(
                    "device",
                    "device-actor",
                    "device-key",
                    ChannelEndpointKind::Display,
                ),
            ],
            ..Default::default()
        };
        assert_eq!(
            console_services_for_apps(&fleet, &registry, "owner", None).unwrap(),
            vec![
                "channel-pub:display",
                "channel-pub:opchat-display",
                "channel-pub:opchat-family",
                "channel-sub:display",
                "channel-sub:family",
                "channel-sub:opchat-display",
                "channel-sub:opchat-family"
            ]
        );
        assert!(console_services_for_apps(&fleet, &registry, "someone-else", None).is_err());
    }
    #[test]
    fn app_grants_fan_out_only_to_owned_console_devices_and_preserve_other_grants() {
        let mut first = chain_device("first", "first-key", "owner", 3);
        first.scope.service_ids = vec![service_hash("channel-sub:manual"), "0xunknown".into()];
        let mut revoked = chain_device("revoked", "revoked-key", "owner", 3);
        revoked.device.revoked = true;
        let fleet = ConsoleFleet {
            operator_omni: "owner".into(),
            account: "account".into(),
            devices: vec![
                first,
                chain_device("second", "second-key", "owner", 3),
                chain_device("plain-device", "plain-key", "owner", 3),
                chain_device("foreign", "foreign-key", "other", 3),
                revoked,
                chain_device("mismatch", "correct-key", "owner", 3),
                chain_device("delegate", "delegate-key", "owner", 2),
            ],
        };
        let mut first = console_binding("first", "first-key");
        first.granted_service_names = vec!["channel-sub:manual".into(), "channel-sub:stale".into()];
        let mut plain = console_binding("plain-device", "plain-key");
        plain.kind = "device".into();
        let manifest = BindingManifest {
            bindings: vec![
                first,
                console_binding("second", "second-key"),
                plain,
                console_binding("foreign", "foreign-key"),
                console_binding("revoked", "revoked-key"),
                console_binding("mismatch", "wrong-key"),
                console_binding("delegate", "delegate-key"),
            ],
            ..Default::default()
        };
        let next = vec![console_chat("opchat-new")];
        let scopes = plan_endpoint_scopes(
            &fleet,
            &manifest,
            &AppRegistryDoc::default(),
            "owner",
            EndpointChange {
                deltas: &[],
                next: &next,
                previous: &[],
                current_console: Some("first"),
                exclude: None,
                enrollments: &[],
            },
        )
        .unwrap();
        assert_eq!(
            scopes
                .iter()
                .map(|scope| scope.actor_omni.as_str())
                .collect::<Vec<_>>(),
            vec!["0xfirst", "0xsecond"]
        );
        assert_eq!(
            scopes[0].services,
            vec![
                "channel-pub:opchat-new",
                "channel-sub:manual",
                "channel-sub:opchat-new"
            ]
        );
        assert_eq!(scopes[0].preserve_service_ids, vec!["0xunknown"]);
        assert_eq!(
            scopes[1].services,
            vec!["channel-pub:opchat-new", "channel-sub:opchat-new"]
        );
        assert!(plan_endpoint_scopes(
            &fleet,
            &manifest,
            &AppRegistryDoc::default(),
            "owner",
            EndpointChange {
                deltas: &[],
                next: &next,
                previous: &[],
                current_console: Some("foreign"),
                exclude: None,
                enrollments: &[]
            }
        )
        .is_err());
    }
    #[test]
    fn newly_enrolled_console_receives_other_apps_while_removed_channels_are_revoked_everywhere() {
        let existing_app = app(
            "existing",
            "app-actor",
            "app-key",
            ChannelEndpointKind::Messaging,
        );
        let mut existing_console = chain_device("existing-console", "console-key", "owner", 3);
        existing_console.scope.service_ids = vec![
            service_hash("channel-pub:removed"),
            service_hash("channel-sub:removed"),
            service_hash("channel-sub:manual"),
        ];
        let fleet = ConsoleFleet {
            operator_omni: "owner".into(),
            account: "account".into(),
            devices: vec![
                existing_console,
                chain_device("app-actor", "app-key", "owner", 2),
            ],
        };
        let manifest = BindingManifest {
            bindings: vec![console_binding("existing-console", "console-key")],
            ..Default::default()
        };
        let enrollment = EndpointEnrollment {
            actor_omni: "new-console".into(),
            device_key_hash: "new-key".into(),
            pop_sig: "fixture".into(),
            label: "console".into(),
            kind: "console".into(),
            transport: String::new(),
        };
        let next = vec![console_chat("opchat-new")];
        let previous = vec![console_chat("removed")];
        let enrollments = vec![(enrollment, "request".into())];
        let scopes = plan_endpoint_scopes(
            &fleet,
            &manifest,
            &AppRegistryDoc {
                apps: vec![existing_app],
                ..Default::default()
            },
            "owner",
            EndpointChange {
                deltas: &[],
                next: &next,
                previous: &previous,
                current_console: Some("new-console"),
                exclude: Some("changed-app"),
                enrollments: &enrollments,
            },
        )
        .unwrap();
        assert_eq!(scopes.len(), 2);
        for scope in &scopes {
            assert!(scope.services.contains(&"channel-sub:existing".into()));
            assert!(scope
                .services
                .contains(&"channel-pub:opchat-existing".into()));
            assert!(scope.services.contains(&"channel-pub:opchat-new".into()));
            assert!(!scope
                .services
                .iter()
                .any(|service| service.ends_with(":removed")));
        }
        assert_eq!(
            scopes[0].preserve_service_ids,
            vec![service_hash("channel-sub:manual")]
        );
    }
    #[test]
    fn rebind_retains_unknown_and_manual_grants_but_replaces_app_grants() {
        let previous = row();
        let owned = service_hash("channel-pub:family");
        let manual = service_hash("channel-sub:manual");
        let unknown = "0x1234".to_owned();
        let mut fleet = ConsoleFleet {
            operator_omni: "owner".into(),
            account: "account".into(),
            devices: vec![ConsoleFleetEntry {
                device: ConsoleChainDevice {
                    device_key_hash: previous.device_key_hash.clone(),
                    actor_omni: previous.actor_omni.clone(),
                    operator_omni: "owner".into(),
                    tier: 2,
                    revoked: false,
                },
                scope: ConsoleChainScope {
                    service_ids: vec![owned, manual.clone(), unknown.clone()],
                    ..Default::default()
                },
            }],
        };
        assert_eq!(
            preserve_delegate_services(&fleet, &previous).unwrap(),
            vec![manual, unknown]
        );
        fleet.devices[0].device.revoked = true;
        assert!(preserve_delegate_services(&fleet, &previous).is_err());
    }
    #[test]
    fn default_refresh_rejects_unknown_channel_and_accepts_owned_removed_binding() {
        let registry = AppRegistryDoc {
            apps: vec![row()],
            ..Default::default()
        };
        let gate = ContactRegistry::default();
        assert!(!known_channel(&gate, &registry, "another-household"));
        assert!(known_channel(&gate, &registry, "family"));
        let mut gate = gate;
        gate.channels.push(ChannelDoc {
            id: "own-empty-channel".into(),
            ..Default::default()
        });
        assert!(known_channel(&gate, &registry, "own-empty-channel"));
    }
    #[test]
    fn metadata_retry_accepts_derived_default_flag_but_not_changed_user_binding() {
        let prepared = row();
        let mut applied = prepared.clone();
        applied.bound_channels[0].default_app = Some(true);
        assert!(same_applied_row(&applied, &prepared, false, false, None));
        applied.bound_channels[0].channel_id = "changed".into();
        assert!(!same_applied_row(&applied, &prepared, false, false, None));
    }
    #[test]
    fn nested_spawn_failures_require_ceremony_recovery() {
        assert!(receipt_needs_refresh(
            &json!({"ok":true,"ceremony":{"spawned":[{"sandbox":{"error":"offline"}}]}})
        ));
        assert!(receipt_needs_refresh(
            &json!({"ok":true,"ceremony":{"spawned":[{"gate":{"error":"unavailable"}}]}})
        ));
        assert!(!receipt_needs_refresh(
            &json!({"ok":true,"ceremony":{"spawned":[{"sandbox":{"error":null}}]}})
        ));
    }
}
