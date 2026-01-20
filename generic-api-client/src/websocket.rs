use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, StreamExt},
};
use parking_lot::Mutex as SyncMutex;
use std::{
    collections::hash_map::{Entry, HashMap},
    collections::VecDeque,
    mem,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpStream,
    sync::{mpsc as tokio_mpsc, Mutex as AsyncMutex, Notify},
    task::JoinHandle,
    time::{timeout, MissedTickBehavior},
};
use tokio_tungstenite::{tungstenite, MaybeTlsStream};
use tungstenite::client::IntoClientRequest;
pub use tungstenite::Error as TungsteniteError;

type WebSocketStream = tokio_tungstenite::WebSocketStream<MaybeTlsStream<TcpStream>>;
type WebSocketSplitSink = SplitSink<WebSocketStream, tungstenite::Message>;

#[derive(Debug)]
struct ActiveSink {
    // 現在この sink が紐づいている接続ID（true/false の2値）。
    // 再接続で sink が差し替わるときに id も同時に差し替えることで、
    // 「どの接続に送ったか」と送信履歴の紐付けをズラさない。
    id: bool,
    sink: WebSocketSplitSink,
}

// WebSocket の下にある実体は TCP(Plain/TLS) なので、そこから local/peer addr を取り出して
// 「どの TCP 接続でエラーが起きたか」をログに出せるようにする。
fn socket_addrs_from_stream(
    stream: &MaybeTlsStream<TcpStream>,
) -> (Option<SocketAddr>, Option<SocketAddr>) {
    let tcp_stream = match stream {
        MaybeTlsStream::Plain(tcp_stream) => Some(tcp_stream),
        #[cfg(feature = "native-tls")]
        MaybeTlsStream::NativeTls(tls_stream) => Some(tls_stream.get_ref().get_ref().get_ref()),
        #[cfg(any(
            feature = "rustls-tls-native-roots",
            feature = "rustls-tls-webpki-roots"
        ))]
        MaybeTlsStream::Rustls(tls_stream) => Some(tls_stream.get_ref().0),
        #[allow(unreachable_patterns)]
        _ => None,
    };
    tcp_stream.map_or((None, None), |tcp_stream| {
        (tcp_stream.local_addr().ok(), tcp_stream.peer_addr().ok())
    })
}

/// A `struct` that holds a websocket connection.
///
/// Dropping this `struct` terminates the connection.
///
/// # Reconnecting
/// `WebSocketConnection` automatically reconnects when an [TungsteniteError] occurs.
/// Note, that during reconnection, it is **possible** that the [WebSocketHandler] receives multiple identical messages
/// even though the message was sent only once by the server, or receives only one message even though
/// multiple identical messages were sent by the server, because there could be a time difference in the new connection and
/// the old connection.
///
/// You can use the [reconnect_state()][Self::reconnect_state()] method to check if the connection is under
/// a reconnection, or manually request a reconnection.
#[derive(Debug)]
#[must_use = "dropping WebSocketConnection closes the connection"]
pub struct WebSocketConnection<H: WebSocketHandler> {
    task_reconnect: JoinHandle<()>,
    sink: Arc<AsyncMutex<ActiveSink>>,
    inner: Arc<ConnectionInner<H>>,
    reconnect_state: ReconnectState,
}

// Two ways connections end:
// - User drops WebSocketConnection
//     1. feed_handler receives a message and closes the connection, then terminates
//     2. start_connection notices that the connection is closed, and attempts to notify feed_handler, then terminates
// - Reconnection
//     This happens when:
//     - the user requests so
//     - message timeout
//     - the server closes the connection
//     - some kind of error occurs while receiving the message
//
//     1. task_reconnect starts a new connection
//     2. task_reconnect closes the old connection
//     3. start_connection (old) notices that the connection is closed, and notifies feed_handler, then terminates
//     4. feed_handler receives the message, but ignores it because it is from the old connection
#[derive(Debug)]
struct ConnectionInner<H: WebSocketHandler> {
    base_url: String,
    handler: Arc<SyncMutex<H>>,
    message_tx: tokio_mpsc::UnboundedSender<(bool, FeederMessage)>,
    next_connection_id: AtomicBool,
    // 接続試行ごとのメタ情報を conn_id(bool) で保持する。
    // 再接続が発生すると conn_id がトグルされ、古い接続の情報と区別できる。
    attempt_info: SyncMutex<HashMap<bool, ConnectionAttemptInfo>>,
}

#[derive(Debug, Clone)]
struct ConnectionAttemptInfo {
    // 実際に接続した URL（url_prefix を含む完全な URL）。
    url: String,
    // どのローカルポート/宛先に繋がっていたか（TCPレベル）。
    local_addr: Option<SocketAddr>,
    peer_addr: Option<SocketAddr>,
    // その接続(conn_id)で送ったメッセージの要約履歴（直近 N 件）。
    // subscribe/auth の内容を「どの接続が送っていたか」追跡する目的。
    sent_messages: VecDeque<String>,
}

impl ConnectionAttemptInfo {
    // ログに載せる送信履歴の最大件数（多すぎるとログが爆発するため上限を設ける）。
    const SENT_HISTORY_LIMIT: usize = 50;

    // ログ用にメッセージを短く要約する。
    // Text は先頭だけ、Binary/Ping/Pong は長さのみ。
    fn summarize_message(message: &WebSocketMessage) -> String {
        match message {
            WebSocketMessage::Text(text) => {
                // 送信メッセージには auth 情報（APIキー/署名/トークン等）が含まれ得る。
                // それを error ログ等に載せると漏洩するので、怪しい文字列が含まれる場合は本文を出さない。
                let lower = text.to_ascii_lowercase();
                let looks_sensitive = [
                    "api_key",
                    "apikey",
                    "api-secret",
                    "apisecret",
                    "secret",
                    "signature",
                    "passphrase",
                    "token",
                ]
                .into_iter()
                .any(|needle| lower.contains(needle));
                if looks_sensitive {
                    return format!("Text(len={}, redacted=true)", text.len());
                }
                const LIMIT_BYTES: usize = 256;
                let mut end = std::cmp::min(text.len(), LIMIT_BYTES);
                while !text.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                let prefix = &text[..end];
                if end == text.len() {
                    format!("Text({prefix})")
                } else {
                    format!("Text({prefix}…)")
                }
            }
            WebSocketMessage::Binary(data) => format!("Binary(len={})", data.len()),
            WebSocketMessage::Ping(data) => format!("Ping(len={})", data.len()),
            WebSocketMessage::Pong(data) => format!("Pong(len={})", data.len()),
        }
    }

    // 送信履歴に追加（リングバッファ）。
    fn record_sent(&mut self, message: &WebSocketMessage) {
        if self.sent_messages.len() >= Self::SENT_HISTORY_LIMIT {
            self.sent_messages.pop_front();
        }
        self.sent_messages
            .push_back(Self::summarize_message(message));
    }

    fn sent_messages_snapshot(&self) -> Vec<String> {
        self.sent_messages.iter().cloned().collect()
    }
}

enum FeederMessage {
    Message(tungstenite::Result<tungstenite::Message>),
    ConnectionClosed,
    DropConnectionRequest,
}

impl<H: WebSocketHandler> WebSocketConnection<H> {
    /// Starts a new `WebSocketConnection` to the given url using the given [handler][WebSocketHandler].
    pub async fn new(url: &str, handler: H) -> Result<Self, TungsteniteError> {
        let config = handler.websocket_config();
        let handler = Arc::new(SyncMutex::new(handler));
        let base_url = url.to_owned();

        let (message_tx, message_rx) = tokio_mpsc::unbounded_channel();
        let reconnect_manager = ReconnectState::new();

        let connection = Arc::new(ConnectionInner {
            base_url,
            handler: Arc::clone(&handler),
            message_tx,
            next_connection_id: AtomicBool::new(false),
            attempt_info: SyncMutex::new(HashMap::new()),
        });

        async fn feed_handler(
            connection: Arc<ConnectionInner<impl WebSocketHandler>>,
            mut message_rx: tokio_mpsc::UnboundedReceiver<(bool, FeederMessage)>,
            reconnect_manager: ReconnectState,
            config: WebSocketConfig,
            sink: Arc<AsyncMutex<ActiveSink>>,
        ) {
            let mut messages: HashMap<WebSocketMessage, isize> = HashMap::new();

            let timeout_duration = if config.message_timeout.is_zero() {
                Duration::MAX
            } else {
                config.message_timeout
            };

            loop {
                match timeout(timeout_duration, message_rx.recv()).await {
                    // message successfully received
                    Ok(Some((id, FeederMessage::Message(Ok(message))))) => {
                        // message successfully received
                        if let Some(message) = WebSocketMessage::from_message(message) {
                            if reconnect_manager.is_reconnecting() {
                                // reconnecting
                                let id_sign: isize = if id { 1 } else { -1 };
                                let entry = messages.entry(message.clone());
                                match entry {
                                    Entry::Occupied(mut occupied) => {
                                        if config.ignore_duplicate_during_reconnection {
                                            log::debug!("Skipping duplicate message.");
                                            continue;
                                        }

                                        *occupied.get_mut() += id_sign;
                                        if id_sign != occupied.get().signum() {
                                            // same message which comes from different connections, so we assume it's a duplicate.
                                            log::debug!("Skipping duplicate message.");
                                            continue;
                                        }
                                        // comes from the same connection, which means the message was sent twice.
                                    }
                                    Entry::Vacant(vacant) => {
                                        // new message
                                        vacant.insert(id_sign);
                                    }
                                }
                            } else {
                                messages.clear();
                            }
                            let messages = connection.handler.lock().handle_message(message);
                            // handler が「返信として送りたい」メッセージ（例: auth成功後の subscribe）を返すことがある。
                            // その場合も「この接続(conn_id)で何を送ったか」を追えるよう履歴に残す。
                            let mut sink_lock = sink.lock().await;
                            let current_id = sink_lock.id;
                            for message in messages {
                                if let Some(attempt) =
                                    connection.attempt_info.lock().get_mut(&current_id)
                                {
                                    attempt.record_sent(&message);
                                }
                                if let Err(error) =
                                    sink_lock.sink.send(message.into_message()).await
                                {
                                    log::error!(
                                        "Failed to send message because of an error: {}",
                                        error
                                    );
                                };
                            }
                            if let Err(error) = sink_lock.sink.flush().await {
                                log::error!(
                                    "An error occurred while flushing WebSocket sink: {error:?}"
                                );
                            }
                        }
                    }
                    // failed to receive message
                    Ok(Some((id, FeederMessage::Message(Err(error))))) => {
                        let current_id = !connection.next_connection_id.load(Ordering::SeqCst);
                        let attempt = connection.attempt_info.lock().get(&id).cloned();
                        let (local_addr, peer_addr, sent_messages, url) = attempt
                            .as_ref()
                            .map(|attempt| {
                                (
                                    attempt.local_addr,
                                    attempt.peer_addr,
                                    attempt.sent_messages_snapshot(),
                                    attempt.url.as_str(),
                                )
                            })
                            .unwrap_or((None, None, Vec::new(), connection.base_url.as_str()));
                        if id != current_id {
                            // 再接続中は古い接続の read loop からもエラーが飛んでくることがあるので、
                            // それで現在の接続を誤って再接続させないよう「古い接続のエラー」は詳細だけ debug にして無視する。
                            log::debug!(
                                "WebSocket receive error from old connection; url={} local_addr={local_addr:?} peer_addr={peer_addr:?} conn_id={} current_id={} sent_messages={sent_messages:?} error={error:?}",
                                url,
                                id,
                                current_id,
                            );
                            continue;
                        }
                        // 「どの TCP 接続(local/peer)で」「何を送っていたか(sent_messages)」を一緒に出す。
                        log::error!(
                            "Failed to receive message because of an error; url={} local_addr={local_addr:?} peer_addr={peer_addr:?} conn_id={} reconnecting={} sent_messages={sent_messages:?} error={error:?}",
                            url,
                            id,
                            reconnect_manager.is_reconnecting(),
                        );
                        if reconnect_manager.request_reconnect() {
                            log::info!("Reconnecting WebSocket because there was an error while receiving a message");
                        }
                    }
                    // timeout
                    Err(_) => {
                        log::debug!("WebSocket message timeout");
                        if reconnect_manager.request_reconnect() {
                            log::info!("Reconnecting WebSocket because of timeout");
                        }
                    }
                    // connection was closed
                    Ok(Some((id, FeederMessage::ConnectionClosed))) => {
                        let current_id = !connection.next_connection_id.load(Ordering::SeqCst);
                        if id != current_id {
                            // old connection, ignore
                            continue;
                        }
                        log::debug!("WebSocket connection closed by server");
                        if reconnect_manager.request_reconnect() {
                            let attempt = connection.attempt_info.lock().get(&id).cloned();
                            let (sent_messages, url) = attempt
                                .as_ref()
                                .map(|attempt| {
                                    (attempt.sent_messages_snapshot(), attempt.url.as_str())
                                })
                                .unwrap_or((Vec::new(), connection.base_url.as_str()));
                            log::info!(
                                "Reconnecting WebSocket because it was disconnected by the server; url={} conn_id={} sent_messages={sent_messages:?}",
                                url,
                                id,
                            );
                        }
                    }
                    // the connection is no longer needed because WebSocketConnection was dropped
                    Ok(Some((_, FeederMessage::DropConnectionRequest))) => {
                        if let Err(error) = sink.lock().await.sink.close().await {
                            log::debug!("Failed to close WebSocket connection: {error:?}");
                        }
                        break;
                    }
                    // message_tx has been dropped, which should never happen because it's always accessible by connection.message_tx.
                    Ok(None) => unreachable!("message_rx should never be closed"),
                }
            }
            connection.handler.lock().handle_close(false);
        }

        async fn reconnect<H: WebSocketHandler>(
            interval: Duration,
            cooldown: Duration,
            connection: Arc<ConnectionInner<H>>,
            sink: Arc<AsyncMutex<ActiveSink>>,
            reconnect_manager: ReconnectState,
            no_duplicate: bool,
            wait: Duration,
        ) {
            let mut cooldown = tokio::time::interval(cooldown);
            cooldown.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                let timer = if interval.is_zero() {
                    // never completes
                    tokio::time::sleep(Duration::MAX)
                } else {
                    tokio::time::sleep(interval)
                };
                tokio::select! {
                    _ = reconnect_manager.inner.reconnect_notify.notified() => {},
                    _ = timer => {},
                }
                log::debug!("Reconnection requested");
                cooldown.tick().await;
                reconnect_manager
                    .inner
                    .reconnecting
                    .store(true, Ordering::SeqCst);

                // reconnect_notify might have been notified while waiting the cooldown,
                // so we consume any existing permits on reconnect_notify
                reconnect_manager.inner.reconnect_notify.notify_one();
                // this completes immediately because we just added a permit
                reconnect_manager.inner.reconnect_notify.notified().await;

                log::debug!("Starting reconnection process ...");
                if no_duplicate {
                    tokio::time::sleep(wait).await;
                }

                // start a new connection
                match WebSocketConnection::<H>::start_connection(Arc::clone(&connection)).await {
                    Ok(new_sink) => {
                        // replace the sink with the new one
                        let mut old_sink = mem::replace(&mut *sink.lock().await, new_sink);
                        log::debug!("New connection established");

                        if no_duplicate {
                            tokio::time::sleep(wait).await;
                        }

                        if let Err(error) = old_sink.sink.close().await {
                            log::debug!(
                                "An error occurred while closing old connection: {}",
                                error
                            );
                        }
                        connection.handler.lock().handle_close(true);
                        log::debug!("Old connection closed");
                    }
                    Err(error) => {
                        // try reconnecting again
                        log::error!(
                            "Failed to reconnect because of an error: {}, trying again ...",
                            error
                        );
                        reconnect_manager.inner.reconnect_notify.notify_one();
                    }
                }

                if no_duplicate {
                    tokio::time::sleep(wait).await;
                }

                reconnect_manager
                    .inner
                    .reconnecting
                    .store(false, Ordering::SeqCst);
                log::debug!("Reconnection process complete");
            }
        }

        let sink_inner = Self::start_connection(Arc::clone(&connection)).await?;
        let sink = Arc::new(AsyncMutex::new(sink_inner));

        tokio::spawn(feed_handler(
            Arc::clone(&connection),
            message_rx,
            reconnect_manager.clone(),
            config.clone(),
            Arc::clone(&sink),
        ));

        let task_reconnect = tokio::spawn(reconnect(
            config.refresh_after,
            config.connect_cooldown,
            Arc::clone(&connection),
            Arc::clone(&sink),
            reconnect_manager.clone(),
            config.ignore_duplicate_during_reconnection,
            config.reconnection_wait,
        ));

        Ok(Self {
            task_reconnect,
            sink,
            inner: connection,
            reconnect_state: reconnect_manager,
        })
    }

    async fn start_connection(
        connection: Arc<ConnectionInner<impl WebSocketHandler>>,
    ) -> Result<ActiveSink, TungsteniteError> {
        let config = connection.handler.lock().websocket_config();
        let handshake_headers = config.handshake_headers;
        let url = config.url_prefix + connection.base_url.as_str();
        let mut request = url.clone().into_client_request()?;
        for (name, value) in handshake_headers {
            let name = match tungstenite::http::header::HeaderName::from_bytes(name.as_bytes()) {
                Ok(name) => name,
                Err(_) => {
                    log::warn!("Skipping invalid WebSocket handshake header name: {name}");
                    continue;
                }
            };
            let value = match tungstenite::http::HeaderValue::from_str(&value) {
                Ok(value) => value,
                Err(_) => {
                    log::warn!(
                        "Skipping invalid WebSocket handshake header value for {:?}: {value}",
                        name
                    );
                    continue;
                }
            };
            request.headers_mut().insert(name, value);
        }

        let (websocket_stream, response) = tokio_tungstenite::connect_async(request).await?;
        if log::log_enabled!(log::Level::Debug) {
            log::debug!(
                "WebSocket handshake response: status={} headers={:?}",
                response.status(),
                response.headers()
            );
        }
        // 接続が張れた時点の TCP 情報を保存しておく（受信エラー時の特定用）。
        let (local_addr, peer_addr) = socket_addrs_from_stream(websocket_stream.get_ref());
        let (mut sink, mut stream) = websocket_stream.split();

        // 接続確立直後に送る初期メッセージ（例: subscribe/auth）を handler から受け取る。
        let start_messages = connection.handler.lock().handle_start();
        for message in &start_messages {
            sink.send(message.clone().into_message()).await?;
        }
        sink.flush().await?;

        // fetch_not is unstable so we use fetch_xor
        // 接続ごとに bool をトグルして conn_id として使う（true/false の2値で世代を区別）。
        let id = connection
            .next_connection_id
            .fetch_xor(true, Ordering::SeqCst);
        let mut attempt_info = ConnectionAttemptInfo {
            url: url.clone(),
            local_addr,
            peer_addr,
            sent_messages: VecDeque::new(),
        };
        // 「この接続で送った」初期メッセージも履歴に積む。
        for message in &start_messages {
            attempt_info.record_sent(message);
        }
        connection
            .attempt_info
            .lock()
            .insert(id, attempt_info.clone());
        if log::log_enabled!(log::Level::Debug) {
            let attempt = connection.attempt_info.lock().get(&id).cloned();
            if let Some(attempt) = attempt {
                log::debug!(
                    "WebSocket connection established; url={} local_addr={:?} peer_addr={:?} conn_id={} sent_messages={:?}",
                    attempt.url,
                    attempt.local_addr,
                    attempt.peer_addr,
                    id,
                    attempt.sent_messages_snapshot(),
                );
            }
        }

        // pass messages to task_feed_handler
        tokio::spawn(async move {
            while let Some(message) = stream.next().await {
                if log::log_enabled!(log::Level::Info) {
                    if let Ok(tungstenite::Message::Close(frame)) = &message {
                        match frame {
                            Some(frame) => {
                                log::info!(
                                    "WebSocket received close frame: conn_id={} code={:?} reason={}",
                                    id,
                                    frame.code,
                                    frame.reason
                                );
                            }
                            None => {
                                log::info!(
                                    "WebSocket received close frame: conn_id={} code=none reason=none",
                                    id
                                );
                            }
                        }
                    }
                }
                if log::log_enabled!(log::Level::Trace) {
                    match &message {
                        Ok(message) => {
                            let (kind, len) = match message {
                                tungstenite::Message::Text(text) => ("text", text.len()),
                                tungstenite::Message::Binary(data) => ("binary", data.len()),
                                tungstenite::Message::Ping(data) => ("ping", data.len()),
                                tungstenite::Message::Pong(data) => ("pong", data.len()),
                                tungstenite::Message::Close(_) => ("close", 0),
                                tungstenite::Message::Frame(_) => ("frame", 0),
                            };
                            log::trace!(
                                "WebSocket received: conn_id={} kind={} len={}",
                                id,
                                kind,
                                len
                            );
                        }
                        Err(err) => {
                            log::trace!("WebSocket receive error: conn_id={} err={:?}", id, err);
                        }
                    }
                }
                // send the received message to the task running feed_handler
                if connection
                    .message_tx
                    .send((id, FeederMessage::Message(message)))
                    .is_err()
                {
                    // the channel is closed. we can't disconnect because we don't have the sink
                    log::debug!("WebSocket message receiver is closed; abandon connection");
                    return;
                }
            }
            // the underlying WebSocket connection was closed

            drop(
                connection
                    .message_tx
                    .send((id, FeederMessage::ConnectionClosed)),
            ); // this may be Err
            log::debug!("WebSocket stream closed");
        });
        Ok(ActiveSink { id, sink })
    }

    /// Sends a message to the connection.
    pub async fn send_message(&self, message: WebSocketMessage) -> Result<(), TungsteniteError> {
        // 外部(API利用側)から send_message() で送るケースもあるので、ここでも送信履歴を更新する。
        // 送信先の sink と conn_id を同じロックで確定させて、再接続中の取り違えを防ぐ。
        let mut sink_lock = self.sink.lock().await;
        let current_id = sink_lock.id;
        if let Some(attempt) = self.inner.attempt_info.lock().get_mut(&current_id) {
            attempt.record_sent(&message);
        }
        sink_lock.sink.send(message.into_message()).await?;
        sink_lock.sink.flush().await
    }

    /// Returns a [ReconnectState] for this connection.
    ///
    /// See [ReconnectState] for more information.
    pub fn reconnect_state(&self) -> ReconnectState {
        self.reconnect_state.clone()
    }
}

impl<H: WebSocketHandler> Drop for WebSocketConnection<H> {
    fn drop(&mut self) {
        self.task_reconnect.abort();
        // sending None tells the feeder to close
        let current_id = !self.inner.next_connection_id.load(Ordering::SeqCst);
        self.inner
            .message_tx
            .send((current_id, FeederMessage::DropConnectionRequest))
            .ok();
    }
}

/// A `struct` to request the [WebSocketConnection] to perform a reconnect.
///
/// This `struct` uses an [Arc] internally, so you can obtain multiple
/// `ReconnectState`s for a single [WebSocketConnection] by [cloning][Clone].
#[derive(Debug, Clone)]
pub struct ReconnectState {
    inner: Arc<ReconnectMangerInner>,
}

#[derive(Debug)]
struct ReconnectMangerInner {
    reconnect_notify: Notify,
    reconnecting: AtomicBool,
}

impl ReconnectState {
    fn new() -> Self {
        Self {
            inner: Arc::new(ReconnectMangerInner {
                reconnect_notify: Notify::new(),
                reconnecting: AtomicBool::new(false),
            }),
        }
    }

    /// Returns `true` iff the [WebSocketConnection] is undergoing a reconnection process.
    pub fn is_reconnecting(&self) -> bool {
        self.inner.reconnecting.load(Ordering::SeqCst)
    }

    /// Request the [WebSocketConnection] to perform a reconnect.
    ///
    /// Will return `false` if it is already in a reconnection process.
    pub fn request_reconnect(&self) -> bool {
        if self.is_reconnecting() {
            false
        } else {
            self.inner.reconnect_notify.notify_one();
            true
        }
    }
}

/// An enum that represents a websocket message.
///
/// See also [tungstenite::Message].
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum WebSocketMessage {
    /// A text message
    Text(String),
    /// A binary message
    Binary(Vec<u8>),
    /// A ping message
    Ping(Vec<u8>),
    /// A pong message
    Pong(Vec<u8>),
}

impl WebSocketMessage {
    fn from_message(message: tungstenite::Message) -> Option<Self> {
        match message {
            tungstenite::Message::Text(text) => Some(Self::Text(text)),
            tungstenite::Message::Binary(data) => Some(Self::Binary(data)),
            tungstenite::Message::Ping(data) => Some(Self::Ping(data)),
            tungstenite::Message::Pong(data) => Some(Self::Pong(data)),
            tungstenite::Message::Close(_) | tungstenite::Message::Frame(_) => None,
        }
    }

    fn into_message(self) -> tungstenite::Message {
        match self {
            WebSocketMessage::Text(text) => tungstenite::Message::Text(text),
            WebSocketMessage::Binary(data) => tungstenite::Message::Binary(data),
            WebSocketMessage::Ping(data) => tungstenite::Message::Ping(data),
            WebSocketMessage::Pong(data) => tungstenite::Message::Pong(data),
        }
    }
}

/// A `trait` which is used to handle events on the [WebSocketConnection].
///
/// The `struct` implementing this `trait` is required to be [Send] and `'static` because
/// it will be sent between threads.
pub trait WebSocketHandler: Send + 'static {
    /// Returns a [WebSocketConfig] that will be applied for all WebSocket connections handled by this handler.
    fn websocket_config(&self) -> WebSocketConfig {
        WebSocketConfig::default()
    }

    /// Called when a new connection has been started, and returns messages that should be sent to the server.
    ///
    /// This could be called multiple times because the connection can be reconnected.
    fn handle_start(&mut self) -> Vec<WebSocketMessage> {
        log::debug!("WebSocket connection started");
        vec![]
    }

    /// Called when the [WebSocketConnection] received a message, returns messages to be sent to the server.
    fn handle_message(&mut self, message: WebSocketMessage) -> Vec<WebSocketMessage>;

    /// Called when a websocket connection is closed.
    ///
    /// If the parameter `reconnect` is:
    /// - `true`, it means that the connection is being reconnected for some reason.
    /// - `false`, it means that the connection will not be reconnected, because the [WebSocketConnection] was dropped.
    #[allow(unused_variables)]
    fn handle_close(&mut self, reconnect: bool) {
        log::debug!("WebSocket connection closed; reconnect: {}", reconnect);
    }
}

/// Configuration for [WebSocketHandler].
///
/// Should be returned by [WebSocketHandler::websocket_config()].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WebSocketConfig {
    /// Duration that should elapse between each attempt to start a new connection.
    ///
    /// This matters because the [WebSocketConnection] reconnects on error. If the error
    /// continues to happen, it could spam the server if `connect_cooldown` is too short. [Default]s to 3000ms.
    pub connect_cooldown: Duration,
    /// The [WebSocketConnection] will automatically reconnect when `refresh_after` has elapsed since
    /// the last connection started. If you don't want this feature, set it to [Duration::ZERO]. [Default]s to [Duration::ZERO].
    pub refresh_after: Duration,
    /// Prefix which will be used for connections that started using this `WebSocketConfig`. [Default]s to `""`.
    ///
    /// Example usage: `"wss://example.com"`
    pub url_prefix: String,
    /// During reconnection, [WebSocketHandler] might receive two identical messages
    /// even though the server sent only one message. By setting this to `true`, [WebSocketConnection]
    /// will not send duplicate messages to the [WebSocketHandler]. You should set this option to `true`
    /// when messages contain some sort of ID and are distinguishable.
    ///
    /// Note, that [WebSocketConnection] will **not** check duplicate messages when it is not under reconnection
    /// even this option is set to `true`.
    pub ignore_duplicate_during_reconnection: bool,
    /// When `ignore_duplicate_during_reconnection` is set to `true`, [WebSocketConnection] will wait for a
    /// certain amount of time to make sure no message is lost. [Default]s to 300ms
    pub reconnection_wait: Duration,
    /// A reconnection will be triggered if no messages are received within this amount of time.
    /// [Default]s to [Duration::ZERO], which means no timeout will be applied.
    pub message_timeout: Duration,
    /// Additional HTTP headers to include in the WebSocket handshake request.
    ///
    /// This is useful for servers that require authentication at handshake time.
    /// [Default]s to empty.
    pub handshake_headers: Vec<(String, String)>,
}

impl WebSocketConfig {
    /// Constructs a new `WebSocketConfig` with its fields set to [default][WebSocketConfig::default()].
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            connect_cooldown: Duration::from_millis(3000),
            refresh_after: Duration::ZERO,
            url_prefix: String::new(),
            ignore_duplicate_during_reconnection: false,
            reconnection_wait: Duration::from_millis(300),
            message_timeout: Duration::ZERO,
            handshake_headers: Vec::new(),
        }
    }
}
