//! Живой пример работы Base: два процесса по TCP делают handshake
//! (X25519 + Ed25519) и обмениваются зашифрованными кадрами (XChaCha20-Poly1305).
//!
//! Запуск (два терминала):
//!   cargo run --example peer -- server 127.0.0.1:9000
//!   cargo run --example peer -- client 127.0.0.1:9000
//!
//! Это не продакшен-транспорт (TCP, без обфускации, без DHT-discovery —
//! peer передаётся вручную) — просто доказательство, что база реально
//! соединяется и шифрует. Discovery/обфускация/UDP — уровень форка.

use std::env;

use skhoron_vbf_core::framing::{Frame, FrameType};
use skhoron_vbf_core::handshake::{self, HandshakeMessage, PeerAuthenticity, HANDSHAKE_MSG_LEN};
use skhoron_vbf_core::identity::Identity;
use skhoron_vbf_core::session::{OrderingGuarantee, Session};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: peer <server|client> <addr:port>");
        std::process::exit(1);
    }

    let identity = Identity::generate();
    println!("Локальный Master-ID: {}", identity.master_id().to_hex());

    let stream = match args[1].as_str() {
        "server" => {
            let listener = TcpListener::bind(&args[2]).await?;
            println!("Слушаю {}, жду подключения...", args[2]);
            let (stream, addr) = listener.accept().await?;
            println!("Подключился {}", addr);
            stream
        }
        "client" => {
            println!("Подключаюсь к {}...", args[2]);
            TcpStream::connect(&args[2]).await?
        }
        other => {
            eprintln!("неизвестный режим: {other}, ожидался server|client");
            std::process::exit(1);
        }
    };

    let (mut reader, mut writer) = stream.into_split();

    // --- Handshake ---
    let (state, my_msg) = handshake::start(&identity);
    let my_msg_bytes = my_msg.encode();
    let handshake_frame = Frame::new(FrameType::Handshake, my_msg_bytes.to_vec());
    write_frame(&mut writer, &handshake_frame).await?;

    let peer_frame = read_frame(&mut reader).await?;
    if peer_frame.frame_type != FrameType::Handshake {
        return Err("ожидался Handshake кадр первым".into());
    }
    let peer_msg = HandshakeMessage::decode(&peer_frame.payload)?;

    // ВНИМАНИЕ: здесь мы доверяем pubkey, пришедшему в самом сообщении
    // (TOFU — trust on first use), потому что peer не был известен заранее.
    // В реальном форке ожидаемый pubkey должен приходить из DHT/конфига,
    // а не из этого же соединения — иначе это не защита от MITM, только
    // от пассивного прослушивания. Это осознанное упрощение примера.
    let peer_identity_pubkey =
        ed25519_dalek::VerifyingKey::from_bytes(&peer_msg.identity_pubkey)?;

    let keys = handshake::finish(
        state,
        &peer_msg,
        &peer_identity_pubkey,
        // Явно TOFU: peer заранее не был известен, pubkey пришёл из этого
        // же соединения. См. README — защищает от пассивного прослушивания,
        // не от MITM на этапе первого знакомства.
        PeerAuthenticity::TrustOnFirstUse,
    )?;
    let mut session = Session::new(keys.tx, keys.rx, OrderingGuarantee::StrictInOrderTransport);

    println!("Handshake завершён. Канал зашифрован (XChaCha20-Poly1305).");
    println!("Peer Master-ID: {}", hex_encode(&peer_msg.identity_pubkey));

    // --- Обмен зашифрованными сообщениями ---
    let outgoing = b"privet ot skhoron-vbf base";
    let frame = session.encrypt_frame(outgoing)?;
    write_frame(&mut writer, &frame).await?;
    println!("Отправлено (plaintext было): {:?}", String::from_utf8_lossy(outgoing));

    let incoming_frame = read_frame(&mut reader).await?;
    let plaintext = session.decrypt_frame(&incoming_frame)?;
    println!("Получено и расшифровано: {:?}", String::from_utf8_lossy(&plaintext));

    Ok(())
}

async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    frame: &Frame,
) -> Result<(), Box<dyn std::error::Error>> {
    let encoded = frame.encode()?;
    writer.write_all(&encoded).await?;
    Ok(())
}

async fn read_frame(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<Frame, Box<dyn std::error::Error>> {
    let mut header = [0u8; 6]; // version(1) + type(1) + length(4)
    reader.read_exact(&mut header).await?;

    let length = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    // Проверяем лимит ДО выделения буфера — иначе именно на этом шаге
    // (не в Frame::decode, а в транспортном чтении) удалённая сторона
    // могла бы указать длину под 4 GiB и заставить нас выделить память
    // ещё до того, как Frame::decode успеет её отклонить.
    if length > skhoron_vbf_core::framing::MAX_FRAME_SIZE {
        return Err("declared frame length exceeds MAX_FRAME_SIZE".into());
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;

    let mut full = Vec::with_capacity(6 + length);
    full.extend_from_slice(&header);
    full.extend_from_slice(&payload);

    let mut buf = bytes::BytesMut::from(&full[..]);
    Ok(Frame::decode(&mut buf)?)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

// Гарантия на этапе компиляции, что размер handshake-сообщения не разъедется
// с константой в core — если кто-то поменяет формат, пример не соберётся молча неверно.
const _: () = assert!(HANDSHAKE_MSG_LEN == 128);