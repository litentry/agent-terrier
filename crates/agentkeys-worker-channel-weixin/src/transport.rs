//! The transport seam (household channels, plan §3a). The contact gate's
//! core — L3 from the channel documents, the feed hop with its addressee and
//! contact stamp, the outbound subscription over every reader, the ask queue
//! — knows no transport. A transport is one of two kinds, and the kinds differ
//! in exactly two hooks:
//!
//! - **Aggregating** (WeChat iLink, the 公众号 webhook, Telegram): one thread
//!   per member, every channel folded into it. `resolve` is the router (an
//!   inbound carries no channel), and every delivery is labelled with the
//!   channel it came from — [`label`].
//! - **Channel-native** (a dedicated app, later): the member picks the
//!   channel, so an inbound already carries it and a delivery lands in that
//!   channel's own thread — no label.
//!
//! Today every configured transport is aggregating; the seam is what a
//! channel-native one plugs into ([`TransportKind::ChannelNative`] makes
//! `label` the identity, and the relay skips `resolve` when the inbound
//! names a channel).

/// How a transport shows a member their channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Aggregating,
    ChannelNative,
}

/// What a member receives for an event on `channel_name`: on an aggregating
/// transport `[<channel>] <text>` — the one thread must say where each
/// message belongs — and the bare text on a channel-native one.
pub fn label(kind: TransportKind, channel_name: &str, text: &str) -> String {
    match kind {
        TransportKind::Aggregating => format!("[{}] {text}", channel_name.trim()),
        TransportKind::ChannelNative => text.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_aggregating_transport_labels_and_a_channel_native_one_does_not() {
        assert_eq!(
            label(TransportKind::Aggregating, " 家庭群 ", "今晚做鱼"),
            "[家庭群] 今晚做鱼"
        );
        assert_eq!(
            label(TransportKind::ChannelNative, "家庭群", "今晚做鱼"),
            "今晚做鱼"
        );
    }
}
