//! Сетевой слой поверх rust-libp2p.
//!
//! Здесь НЕ реализована сама логика подключения/handshake —
//! только структуры конфигурации и заготовка swarm-behaviour.
//! Kademlia DHT берётся готовым из libp2p (не переписывается с нуля).

use libp2p::kad;
use libp2p::{Multiaddr, PeerId};

/// Доверенная bootstrap-нода. `peer_id` обязателен: bootstrap-нода — это
/// точка входа в сеть, и если не проверять её identity, подключение к
/// адресу без ожидаемого PeerId открывает подмену bootstrap-узла
/// (кто угодно, поднявший сервис на этом IP, сойдёт за легитимную ноду).
/// Если нужен режим без проверки — см. `UntrustedDiscoveryNode` ниже,
/// он размечен явно как небезопасный, а не спрятан за Option.
#[derive(Clone, Debug)]
pub struct BootstrapNode {
    pub multiaddr: Multiaddr,
    pub peer_id: PeerId,
}

/// Узел для discovery без проверки identity. Использовать только там,
/// где риск подмены осознанно принят (например ранний dev-тест сети) —
/// название типа сознательно кричащее, чтобы это не подключили молча
/// вместо BootstrapNode.
#[derive(Clone, Debug)]
pub struct UntrustedDiscoveryNode {
    pub multiaddr: Multiaddr,
}

/// Конфигурация сетевого слоя. Заполняется вызывающей стороной
/// (Android/desktop FFI), сам net-крейт значений по умолчанию
/// для продакшена не диктует.
pub struct NetworkConfig {
    pub bootstrap_nodes: Vec<BootstrapNode>,
    pub listen_addr: Multiaddr,
}

/// Заготовка network behaviour для swarm. Реальная сборка (NetworkBehaviour
/// derive, event loop, транспорт TCP/QUIC) — следующий шаг, сознательно
/// не реализован здесь, чтобы зафиксировать сначала конфиг-контракт.
///
/// TODO(следующий шаг, не забыть при переходе от заготовки к продакшену):
/// `kad::store::MemoryStore` теряет данные DHT при перезапуске процесса —
/// нормально для текущей заглушки, но перед реальным использованием нужен
/// персистентный store (например поверх sled/rocksdb).
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