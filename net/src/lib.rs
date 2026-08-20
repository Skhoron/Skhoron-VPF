//! Сетевой слой поверх rust-libp2p.
//!
//! Здесь НЕ реализована сама логика подключения/handshake —
//! только структуры конфигурации и заготовка swarm-behaviour.
//! Kademlia DHT берётся готовым из libp2p (не переписывается с нуля).

use libp2p::kad;
use libp2p::PeerId;

/// Адрес bootstrap-ноды. Список заполняется конфигом, не хардкодится
/// в коде — при старте минимум 2-3 ноды в разных юрисдикциях (см. план).
#[derive(Clone, Debug)]
pub struct BootstrapNode {
    pub multiaddr: String,
    pub peer_id: Option<PeerId>,
}

/// Конфигурация сетевого слоя. Заполняется вызывающей стороной
/// (Android/desktop FFI), сам net-крейт значений по умолчанию
/// для продакшена не диктует.
pub struct NetworkConfig {
    pub bootstrap_nodes: Vec<BootstrapNode>,
    pub listen_addr: String,
}

/// Заготовка network behaviour для swarm. Реальная сборка (NetworkBehaviour
/// derive, event loop, транспорт TCP/QUIC) — следующий шаг, сознательно
/// не реализован здесь, чтобы зафиксировать сначала конфиг-контракт.
pub struct SkhoronNetworkBehaviour {
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

impl SkhoronNetworkBehaviour {
    /// TODO(форкер/следующий шаг): собрать swarm с транспортом
    /// (tcp + quic), подключить noise для transport-security,
    /// запустить event loop. Пока — только конструктор behaviour.
    pub fn new(local_peer_id: PeerId) -> Self {
        let store = kad::store::MemoryStore::new(local_peer_id);
        let kademlia = kad::Behaviour::new(local_peer_id, store);
        Self { kademlia }
    }
}