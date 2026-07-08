//! VPN Manager — subprocess control for aivpn-client.exe
//!
//! Launches the Rust client binary in the background (no console window),
//! monitors its process state, reads traffic stats and recording status from file.
//!
//! SECURITY NOTE: The device public key (X25519) must NEVER be shown in the UI.
//! Exposing it would allow correlation attacks linking the user's device to VPN sessions.

use base64::Engine as _;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
}

pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub quality_score: u8,
    pub server_adaptive_level: u8,
}

// ── Recording ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum RecordingState {
    Idle,
    Starting(String),
    Recording(String),
    Stopping(String),
    Analyzing(String),
    Success(String, Option<String>), // service, mask_id
    Failed(String, String),          // service, reason
}

#[derive(Debug, Clone)]
pub struct RecordingResult {
    pub succeeded: bool,
    pub details: String,
}

/// Benchmark result parsed from `aivpn-client bench --json` output.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct BenchResult {
    pub latency_p50_ms: f64,
    pub latency_p95_ms: f64,
    pub latency_p99_ms: f64,
    pub packet_loss_pct: f64,
    pub quality_score: u8,
}

pub struct VpnManager {
    state: ConnectionState,
    child: Option<Child>,
    stats: TrafficStats,
    last_poll: Option<Instant>,
    pub client_binary: PathBuf,
    /// Server address extracted from the connection key at connect time.
    pub server_addr: Option<String>,
    // Recording
    pub recording_state: RecordingState,
    pub can_record_masks: bool,
    pub recording_capability_known: bool,
    pub last_recording_result: Option<RecordingResult>,
    minimum_recording_ts: u64,
    last_recording_poll: Option<Instant>,
    pub last_error: Option<String>,
    recording_refresh_in_flight: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Timestamp when we entered Connected state — used to detect a stalled tunnel
    /// (process alive but Wintun failing in its reconnect loop).
    connected_since: Option<Instant>,
    /// Whether the current session was started with --kill-switch. Used to run
    /// `kill-switch clear` after TerminateProcess so firewall rules don't stay active.
    kill_switch_active: bool,
    /// Windows Job Object handle (stored as usize) created with
    /// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. The client child is assigned to it so the OS
    /// force-terminates the tunnel process if the GUI dies without running Drop (crash,
    /// abort, or Task Manager kill), preventing an orphaned client and a duplicate client
    /// on the next launch. Best-effort: None means fall back to unmanaged child spawning.
    #[cfg(windows)]
    job_handle: Option<usize>,
}

impl Drop for VpnManager {
    fn drop(&mut self) {
        if let Some(ref mut c) = self.child {
            let _ = c.kill();
            let _ = c.wait();
        }
        if self.kill_switch_active {
            Self::run_kill_switch_clear(&self.client_binary);
        }
    }
}

impl VpnManager {
    pub fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            child: None,
            stats: TrafficStats {
                bytes_sent: 0,
                bytes_received: 0,
                quality_score: 0,
                server_adaptive_level: 0,
            },
            last_poll: None,
            client_binary: Self::find_client_binary(),
            server_addr: None,
            recording_state: RecordingState::Idle,
            can_record_masks: false,
            recording_capability_known: false,
            last_recording_result: None,
            minimum_recording_ts: 0,
            last_recording_poll: None,
            last_error: None,
            recording_refresh_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
                false,
            )),
            connected_since: None,
            kill_switch_active: false,
            #[cfg(windows)]
            job_handle: create_kill_on_close_job(),
        }
    }

    pub fn state(&self) -> ConnectionState {
        self.state
    }

    pub fn stats(&self) -> &TrafficStats {
        &self.stats
    }

    pub fn is_connected(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    pub fn is_busy(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Connecting | ConnectionState::Disconnecting
        )
    }

    /// Connect using a connection key
    pub fn connect(
        &mut self,
        connection_key: &str,
        full_tunnel: bool,
        proxy_listen: Option<&str>,
        mtls_cert_path: Option<&str>,
        exclude_routes: &[String],
        include_routes: &[String],
        kill_switch: bool,
        adaptive_level: u8,
        dns_proxy: Option<&str>,
        preferred_mask: Option<&str>,
        bootstrap_cdn_url: Option<&str>,
        bootstrap_telegram_token: Option<&str>,
        bootstrap_telegram_chat: Option<&str>,
        bootstrap_github: Option<&str>,
        server_signing_key: Option<&str>,
        polymorphic_base: Option<&str>,
        share_mask_feedback: bool,
        receive_mask_hints: bool,
        country_code: Option<&str>,
    ) -> Result<(), String> {
        if self.child.is_some() {
            return Err("Already running".to_string());
        }

        if !self.client_binary.exists() {
            return Err(format!(
                "Client binary not found: {}",
                self.client_binary.display()
            ));
        }

        // Validate dns_proxy before any state mutations so a bad address doesn't silently
        // wipe last_error and delete stats files when no connection is actually attempted.
        if let Some(addr) = dns_proxy {
            if !addr.is_empty() && addr.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!("Invalid dns-proxy address: {addr}"));
            }
        }

        self.state = ConnectionState::Connecting;
        self.server_addr = extract_server_addr(connection_key);
        // Reset all per-session state on new connection
        self.last_error = None;
        self.recording_state = RecordingState::Idle;
        self.can_record_masks = false;
        self.recording_capability_known = false;
        self.last_recording_result = None;
        self.minimum_recording_ts = current_timestamp_ms();
        // Delete stale stats files so the first Connected poll reads zeros
        let _ = std::fs::remove_file(Self::stats_file_path());
        let _ = std::fs::remove_file(std::env::temp_dir().join("aivpn-traffic.stats"));

        let mut cmd = Command::new(&self.client_binary);
        cmd.env("AIVPN_CONNECTION_KEY", connection_key);

        if full_tunnel {
            cmd.arg("--full-tunnel");
        }

        if let Some(addr) = proxy_listen {
            cmd.arg("--proxy-listen").arg(addr);
        }

        if let Some(cert) = mtls_cert_path {
            cmd.arg("--mtls-cert").arg(cert);
        }

        for route in exclude_routes {
            if !route.trim().is_empty() {
                cmd.arg("--exclude-routes").arg(route.trim());
            }
        }

        for route in include_routes {
            if !route.trim().is_empty() {
                cmd.arg("--include-routes").arg(route.trim());
            }
        }

        if kill_switch {
            cmd.arg("--kill-switch");
        }

        if adaptive_level > 0 {
            cmd.arg("--adaptive-level").arg(adaptive_level.to_string());
        }

        if let Some(addr) = dns_proxy {
            if !addr.is_empty() {
                cmd.arg("--dns-proxy").arg(addr);
            }
        }

        // Polymorphic per-session mask variant takes precedence over the plain
        // preferred-mask selection: when a concrete preset is chosen and the
        // polymorphic toggle is on, request a per-session perturbed variant of
        // it instead of the static preset.
        let polymorphic_active = polymorphic_base
            .map(|m| !m.is_empty() && m != "auto")
            .unwrap_or(false);
        if polymorphic_active {
            cmd.arg("--polymorphic-base").arg(polymorphic_base.unwrap());
        } else if let Some(mask) = preferred_mask {
            if !mask.is_empty() && mask != "auto" {
                cmd.arg("--preferred-mask").arg(mask);
            }
        }

        // §2 crowdsourced mask feedback opt-ins
        if share_mask_feedback {
            cmd.arg("--share-mask-feedback");
        }
        if receive_mask_hints {
            cmd.arg("--receive-mask-hints");
        }
        if let Some(cc) = country_code {
            if !cc.is_empty() {
                cmd.arg("--country-code").arg(cc);
            }
        }

        if let Some(url) = bootstrap_cdn_url {
            if !url.is_empty() {
                cmd.arg("--bootstrap-cdn-url").arg(url);
            }
        }

        if let Some(token) = bootstrap_telegram_token {
            if !token.is_empty() {
                // Via env, not argv — the token is a real credential and the
                // command line is visible to other users (Process Explorer /
                // Task Manager "Command line" column). Matches the connection-key.
                cmd.env("AIVPN_BOOTSTRAP_TELEGRAM_TOKEN", token);
            }
        }

        if let Some(chat) = bootstrap_telegram_chat {
            if !chat.is_empty() {
                cmd.arg("--bootstrap-telegram-chat").arg(chat);
            }
        }

        if let Some(repo) = bootstrap_github {
            if !repo.is_empty() {
                cmd.arg("--bootstrap-github").arg(repo);
            }
        }

        if let Some(key) = server_signing_key {
            if !key.is_empty() {
                cmd.arg("--server-signing-key").arg(key);
            }
        }

        // Run from the directory containing the client binary so wintun.dll is found
        // via the default relative path ("wintun.dll") used by the tun crate.
        if let Some(dir) = self.client_binary.parent() {
            if dir != std::path::Path::new("") {
                cmd.current_dir(dir);
            }
        }

        // The client binary writes its log directly to %LOCALAPPDATA%\AIVPN\client.log
        // (tracing_subscriber opened from inside the process). Stderr redirect via
        // Stdio::from(File) is unreliable for MinGW cross-compiled binaries with
        // CREATE_NO_WINDOW — we no longer rely on it.
        cmd.env("RUST_LOG", "info");
        cmd.stderr(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::null());

        // Hide console window on Windows
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        match cmd.spawn() {
            Ok(child) => {
                // Assign the client to the kill-on-close Job Object so it dies with the
                // GUI even on an abnormal exit that skips Drop. Best-effort — on failure
                // the child still runs, just without the crash-cleanup guarantee.
                #[cfg(windows)]
                if let Some(job) = self.job_handle {
                    use std::os::windows::io::AsRawHandle;
                    use winapi::um::jobapi2::AssignProcessToJobObject;
                    let h = child.as_raw_handle();
                    if unsafe { AssignProcessToJobObject(job as _, h as _) } == 0 {
                        eprintln!(
                            "job: AssignProcessToJobObject failed; client will not be                              auto-killed if the GUI crashes"
                        );
                    }
                }
                self.child = Some(child);
                self.kill_switch_active = kill_switch;
                // Stay in Connecting — poll_status() transitions to Connected once
                // the process survives its first liveness check, preventing the UI
                // from briefly showing Connected before the TUN device is up.
                self.stats.bytes_sent = 0;
                self.stats.bytes_received = 0;
                // Request initial recording status
                self.request_recording_status_refresh();
                Ok(())
            }
            Err(e) => {
                self.state = ConnectionState::Disconnected;
                Err(format!("Failed to start client: {}", e))
            }
        }
    }

    /// Spawn `aivpn-client kill-switch clear` to remove firewall rules left by
    /// TerminateProcess (child.kill() on Windows bypasses the graceful shutdown cleanup path).
    ///
    /// Fire-and-forget: callers (disconnect(), poll_status(), Drop) all run on the egui
    /// render/update thread, so blocking on `.status()` would freeze the whole window for
    /// as long as the child takes — indefinitely if it hangs. `spawn()` is quick and
    /// synchronous, so it also still works from Drop during app exit; dropping the Child
    /// handle detaches the process, which keeps running until the rules are cleared.
    fn run_kill_switch_clear(binary: &std::path::Path) {
        let mut cmd = std::process::Command::new(binary);
        cmd.args(["kill-switch", "clear"]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        if let Err(e) = cmd.spawn() {
            eprintln!("kill-switch clear: spawn failed: {e}");
        }
    }

    /// Disconnect — kill the client process
    pub fn disconnect(&mut self) {
        self.state = ConnectionState::Disconnecting;

        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;

        // child.kill() on Windows calls TerminateProcess which bypasses KillSwitch::deactivate()
        // in the client. Run `kill-switch clear` explicitly so the user is not left without
        // internet access after clicking Disconnect while kill-switch was enabled.
        if self.kill_switch_active {
            Self::run_kill_switch_clear(&self.client_binary.clone());
            self.kill_switch_active = false;
        }

        self.state = ConnectionState::Disconnected;
        self.stats.bytes_sent = 0;
        self.stats.bytes_received = 0;
        self.connected_since = None;
        self.last_error = None;
        // Reset recording
        self.recording_state = RecordingState::Idle;
        self.can_record_masks = false;
        self.recording_capability_known = false;
        self.last_recording_result = None;
        self.minimum_recording_ts = 0;
    }

    /// Run a benchmark against the server using `aivpn-client bench --json`.
    /// Blocks until the bench completes (call from a background thread).
    pub fn run_bench_blocking(binary: &PathBuf, server_addr: &str) -> Option<BenchResult> {
        if server_addr.is_empty() {
            return None;
        }
        let mut cmd = Command::new(binary);
        cmd.args(["bench", "--server", server_addr, "--json"]);
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let out = match cmd.output() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("bench: spawn failed: {e}");
                return None;
            }
        };
        if !out.status.success() {
            eprintln!("bench: exit {}", out.status);
            return None;
        }
        match serde_json::from_slice(&out.stdout) {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("bench: JSON parse error: {e}");
                None
            }
        }
    }

    /// Return the current server address (set when connect() was called).
    pub fn server_addr(&self) -> Option<&str> {
        self.server_addr.as_deref()
    }

    /// Poll process status and read traffic stats
    pub fn poll_status(&mut self) {
        // Only poll every 500ms
        if let Some(last) = self.last_poll {
            if last.elapsed() < std::time::Duration::from_millis(500) {
                return;
            }
        }
        self.last_poll = Some(Instant::now());

        // Check if process is still alive
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // All exits seen by poll_status() are unexpected — intentional disconnects
                    // go through disconnect() which kills and waits before returning, so child
                    // is already None by the time poll_status() runs.
                    let detail = Self::read_last_log_line()
                        .map(|l| format!(": {l}"))
                        .unwrap_or_default();
                    if status.success() {
                        self.last_error =
                            Some(format!("Client disconnected unexpectedly{}", detail));
                    } else {
                        self.last_error = Some(format!("Client exited ({}){}", status, detail));
                    }
                    self.child = None;
                    if self.kill_switch_active {
                        Self::run_kill_switch_clear(&self.client_binary);
                        self.kill_switch_active = false;
                    }
                    self.state = ConnectionState::Disconnected;
                    self.connected_since = None;
                    self.stats.bytes_sent = 0;
                    self.stats.bytes_received = 0;
                    return;
                }
                Ok(None) => {
                    // Still running
                    if self.state == ConnectionState::Connecting {
                        self.state = ConnectionState::Connected;
                        self.connected_since = Some(Instant::now());
                    }
                }
                Err(e) => {
                    self.last_error = Some(format!("Connection lost (OS error): {e}"));
                    self.child = None;
                    if self.kill_switch_active {
                        Self::run_kill_switch_clear(&self.client_binary);
                        self.kill_switch_active = false;
                    }
                    self.state = ConnectionState::Disconnected;
                    self.connected_since = None;
                    return;
                }
            }
        }

        // Read traffic stats from file
        if self.state == ConnectionState::Connected {
            self.read_traffic_stats();
            self.poll_recording_status();

            // Once traffic is flowing, a previous stall error is no longer relevant.
            if self.stats.bytes_sent > 0 || self.stats.bytes_received > 0 {
                self.last_error = None;
            }

            // If the tunnel has been "Connected" for >2s but traffic is still zero,
            // the client process is alive but stuck in its Wintun reconnect loop.
            // Surface the last log line unconditionally (no keyword filter) so the user
            // sees the real cause (e.g. "WintunCreateAdapter failed: Access Denied")
            // even when the log line doesn't contain "warn"/"error"/"failed".
            if self.last_error.is_none()
                && self.stats.bytes_sent == 0
                && self.stats.bytes_received == 0
            {
                let stalled = self
                    .connected_since
                    .map(|t| t.elapsed().as_secs() >= 2)
                    .unwrap_or(false);
                if stalled {
                    if let Some(line) = Self::read_last_log_line() {
                        self.last_error = Some(line);
                    } else {
                        self.last_error = Some("No tunnel traffic after 2s".to_string());
                    }
                }
            }
        }
    }

    // ── Recording ───────────────────────────────────────────────────────

    /// Start mask recording for a given service name
    pub fn start_recording(&mut self, service_name: &str) {
        let service = service_name.trim().to_string();
        if service.is_empty() {
            return;
        }
        self.minimum_recording_ts = current_timestamp_ms();
        self.last_recording_result = None;
        self.recording_state = RecordingState::Starting(service.clone());

        // Run: aivpn-client record start --service <name>
        self.run_client_subcommand(&["record", "start", "--service", &service]);
    }

    /// Stop current mask recording
    pub fn stop_recording(&mut self) {
        let current_service = match &self.recording_state {
            RecordingState::Recording(s) | RecordingState::Starting(s) => s.clone(),
            _ => return,
        };
        self.minimum_recording_ts = current_timestamp_ms();
        self.recording_state = RecordingState::Stopping(current_service);

        // Run: aivpn-client record stop
        self.run_client_subcommand(&["record", "stop"]);
    }

    /// Clear the result banner
    pub fn clear_recording_result(&mut self) {
        self.last_recording_result = None;
    }

    /// Whether the record button should be disabled
    pub fn recording_button_disabled(&self) -> bool {
        matches!(
            self.recording_state,
            RecordingState::Stopping(_) | RecordingState::Analyzing(_)
        )
    }

    /// Whether we're actively recording or starting
    pub fn is_recording(&self) -> bool {
        matches!(
            self.recording_state,
            RecordingState::Recording(_) | RecordingState::Starting(_)
        )
    }

    /// Run a subcommand via the client binary in the background
    fn run_client_subcommand(&self, args: &[&str]) {
        let binary = self.client_binary.clone();
        let args_owned: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        std::thread::spawn(move || {
            let mut cmd = Command::new(&binary);
            for arg in &args_owned {
                cmd.arg(arg);
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            match cmd.output() {
                Ok(out) if !out.status.success() => {
                    eprintln!(
                        "record subcommand failed (exit {}): {}",
                        out.status,
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
                Err(e) => {
                    eprintln!("record subcommand spawn error: {e}");
                }
                _ => {}
            }
        });
    }

    /// Ask the client to refresh the recording status file (at most one subprocess at a time)
    fn request_recording_status_refresh(&self) {
        use std::sync::atomic::Ordering;
        if self
            .recording_refresh_in_flight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return; // previous refresh still running
        }
        let flag = std::sync::Arc::clone(&self.recording_refresh_in_flight);
        let binary = self.client_binary.clone();
        std::thread::spawn(move || {
            let mut cmd = std::process::Command::new(&binary);
            cmd.args(["record", "status"]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                cmd.creation_flags(CREATE_NO_WINDOW);
            }
            let _ = cmd.output();
            flag.store(false, Ordering::Release);
        });
    }

    /// Poll recording status from the status file on disk
    fn poll_recording_status(&mut self) {
        // Only poll every 2 seconds
        if let Some(last) = self.last_recording_poll {
            if last.elapsed() < std::time::Duration::from_secs(2) {
                return;
            }
        }
        self.last_recording_poll = Some(Instant::now());

        if let Some(snapshot) = self.load_recording_status() {
            let applied = self.apply_recording_info(&snapshot);
            if !applied || snapshot.can_record.is_none() {
                self.request_recording_status_refresh();
            }
        } else {
            self.request_recording_status_refresh();
        }
    }

    fn recording_status_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(local_app) = dirs::data_local_dir() {
            paths.push(local_app.join("AIVPN").join("recording.status"));
        }
        paths.push(std::env::temp_dir().join("aivpn-recording.status"));
        paths
    }

    fn load_recording_status(&self) -> Option<RecordingSnapshot> {
        for path in Self::recording_status_paths() {
            if let Ok(data) = std::fs::read(&path) {
                if let Ok(snapshot) = serde_json::from_slice::<RecordingSnapshot>(&data) {
                    return Some(snapshot);
                }
            }
        }
        None
    }

    fn apply_recording_info(&mut self, snapshot: &RecordingSnapshot) -> bool {
        if snapshot.updated_at_ms < self.minimum_recording_ts {
            return false;
        }

        self.minimum_recording_ts = snapshot.updated_at_ms;
        self.recording_capability_known = snapshot.can_record.is_some();
        self.can_record_masks = snapshot.can_record.unwrap_or(false);

        let service = snapshot
            .service
            .clone()
            .unwrap_or_else(|| "mask".to_string());
        match snapshot.state.as_str() {
            "recording" => {
                self.recording_state = RecordingState::Recording(service);
            }
            "stopping" => {
                self.recording_state = RecordingState::Stopping(service);
            }
            "analyzing" => {
                self.recording_state = RecordingState::Analyzing(service);
            }
            "success" => {
                self.recording_state = RecordingState::Success(service, snapshot.mask_id.clone());
                let details = if let Some(ref mask_id) = snapshot.mask_id {
                    format!("Mask saved. ID: {}", mask_id)
                } else {
                    "Mask saved successfully.".to_string()
                };
                self.last_recording_result = Some(RecordingResult {
                    succeeded: true,
                    details,
                });
            }
            "failed" => {
                let reason = snapshot
                    .message
                    .clone()
                    .unwrap_or_else(|| "Recording failed".to_string());
                self.recording_state = RecordingState::Failed(service, reason.clone());
                self.last_recording_result = Some(RecordingResult {
                    succeeded: false,
                    details: reason,
                });
            }
            _ => {
                self.recording_state = RecordingState::Idle;
            }
        }

        true
    }

    // ── Traffic stats ───────────────────────────────────────────────────

    fn read_traffic_stats(&mut self) {
        // Try standard path first, then fallback
        let paths = [
            Self::stats_file_path(),
            std::env::temp_dir().join("aivpn-traffic.stats"),
        ];

        for path in &paths {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Some((sent, recv)) = Self::parse_stats(&content) {
                    // Only update if new values are >= current (avoid jumps down)
                    if sent >= self.stats.bytes_sent || self.stats.bytes_sent == 0 {
                        self.stats.bytes_sent = sent;
                    }
                    if recv >= self.stats.bytes_received || self.stats.bytes_received == 0 {
                        self.stats.bytes_received = recv;
                    }
                    let (qs, sal) = Self::read_quality_json();
                    self.stats.quality_score = qs;
                    self.stats.server_adaptive_level = sal;
                    return;
                }
            }
        }
    }

    fn read_quality_json() -> (u8, u8) {
        let path = std::env::temp_dir().join("aivpn-quality.json");
        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (0, 0),
            Err(e) => {
                eprintln!("read_quality_json: {e}");
                return (0, 0);
            }
        };
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            let quality = v["quality"].as_u64().unwrap_or(0) as u8;
            let adaptive = v["adaptive"].as_u64().unwrap_or(0) as u8;
            return (quality, adaptive);
        }
        (0, 0)
    }

    fn parse_stats(content: &str) -> Option<(u64, u64)> {
        // Format: "sent:12345,received:67890"
        let content = content.trim();
        let mut sent = None;
        let mut recv = None;

        for part in content.split(',') {
            let mut kv = part.splitn(2, ':');
            match (kv.next(), kv.next()) {
                (Some("sent"), Some(v)) => sent = v.trim().parse().ok(),
                (Some("received"), Some(v)) => recv = v.trim().parse().ok(),
                _ => {}
            }
        }

        match (sent, recv) {
            (Some(s), Some(r)) => Some((s, r)),
            _ => None,
        }
    }

    fn client_log_path() -> PathBuf {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("AIVPN")
            .join("client.log")
    }

    /// Read the last non-empty line of the client log (for error surfacing).
    fn read_last_log_line() -> Option<String> {
        use std::io::{Read, Seek, SeekFrom};
        const TAIL: u64 = 65536;
        let mut f = std::fs::File::open(Self::client_log_path()).ok()?;
        let len = f.seek(SeekFrom::End(0)).ok()?;
        f.seek(SeekFrom::Start(len.saturating_sub(TAIL))).ok()?;
        let mut buf = String::new();
        f.read_to_string(&mut buf).ok()?;
        buf.lines()
            .filter(|l| !l.trim().is_empty())
            .last()
            .map(|l| l.trim().to_string())
    }

    fn stats_file_path() -> PathBuf {
        if cfg!(windows) {
            dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("AIVPN")
                .join("traffic.stats")
        } else {
            PathBuf::from("/var/run/aivpn/traffic.stats")
        }
    }

    fn find_client_binary() -> PathBuf {
        // 1. Next to this executable
        if let Ok(exe) = std::env::current_exe() {
            let dir = exe.parent().unwrap_or(std::path::Path::new("."));
            let candidate = dir.join("aivpn-client.exe");
            if candidate.exists() {
                return candidate;
            }
            // Also check without .exe for non-windows dev
            let candidate = dir.join("aivpn-client");
            if candidate.exists() {
                return candidate;
            }
        }

        // 2. Program Files
        if cfg!(windows) {
            let pf = PathBuf::from(r"C:\Program Files\AIVPN\aivpn-client.exe");
            if pf.exists() {
                return pf;
            }
        }

        // 3. Fallback — a TRUSTED ABSOLUTE path, never a bare relative name.
        // The GUI runs elevated (requireAdministrator manifest); returning
        // "aivpn-client.exe" would let Windows search the current directory and
        // PATH, so an attacker-planted binary in an writable CWD/PATH entry
        // would run as admin (binary planting → EoP). An absolute path that
        // doesn't exist simply fails to spawn — safe.
        if cfg!(windows) {
            PathBuf::from(r"C:\Program Files\AIVPN\aivpn-client.exe")
        } else {
            // Dev/non-windows: resolve next to our own exe, absolute, or a
            // clearly-invalid absolute path (never a bare relative name).
            std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(|d| d.join("aivpn-client")))
                .unwrap_or_else(|| PathBuf::from("/nonexistent/aivpn-client"))
        }
    }
}

// ── Recording status file format (matches aivpn-client record_cmd.rs) ───

#[derive(Debug, serde::Deserialize)]
struct RecordingSnapshot {
    can_record: Option<bool>,
    state: String,
    service: Option<String>,
    message: Option<String>,
    mask_id: Option<String>,
    #[allow(dead_code)]
    confidence: Option<f32>,
    updated_at_ms: u64,
}

/// Extract the server address from an `aivpn://` connection key.
/// Connection key format: `aivpn://` + base64url(JSON) where JSON["s"] = "host:port".
fn extract_server_addr(key: &str) -> Option<String> {
    let b64 = key.strip_prefix("aivpn://")?;
    // Try multiple Base64 formats just in case padding or standard charset is used
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(b64))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64))
        .ok()?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json["s"].as_str().map(|s| s.to_string())
}

/// Create a Windows Job Object configured to terminate all assigned processes when the
/// job handle closes. The GUI process holds this handle for its whole lifetime, so if it
/// exits for any reason (including a crash that skips Drop) the OS closes the handle and
/// kills the assigned client. Returns None on any failure (caller falls back gracefully).
#[cfg(windows)]
fn create_kill_on_close_job() -> Option<usize> {
    use std::{mem, ptr};
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::jobapi2::{CreateJobObjectW, SetInformationJobObject};
    use winapi::um::winnt::{
        JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    unsafe {
        let job = CreateJobObjectW(ptr::null_mut(), ptr::null());
        if job.is_null() {
            return None;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let ok = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &mut info as *mut _ as *mut _,
            mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if ok == 0 {
            CloseHandle(job);
            return None;
        }
        Some(job as usize)
    }
}

fn current_timestamp_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Format byte count for display
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
