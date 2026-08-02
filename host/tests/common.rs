use std::cell::RefCell;
use std::path::PathBuf;

use bt_hci::controller::ExternalController;
use bt_hci::data::AclPacket;
use bt_hci::event::{EventKind, EventPacket};
use bt_hci::transport::SerialTransport;
use bt_hci::{ControllerToHostPacket, HostToControllerPacket};
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embedded_io_adapters::tokio_1::FromTokio;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::time::Duration;
use tokio_serial::{DataBits, Parity, SerialStream, StopBits};

pub type Serial = SerialTransport<NoopRawMutex, FromTokio<ReadHalf<SerialStream>>, FromTokio<WriteHalf<SerialStream>>>;

#[allow(dead_code)]
pub type Controller = ExternalController<Serial, 10>;

#[allow(dead_code)]
pub type FaultInjectingController = ExternalController<FaultInjector<Serial>, 10>;

pub fn find_controllers() -> Vec<PathBuf> {
    let folder = "/dev/serial/by-id";
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(folder).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();

        let file_name = path.file_name().unwrap().to_string_lossy();
        if file_name.starts_with("usb-ZEPHYR_Zephyr_HCI_UART_sample") {
            paths.push(path.to_path_buf());
        }
    }
    paths
}

#[allow(unused)]
pub(crate) async fn create_controller(port: &PathBuf) -> Controller {
    ExternalController::new(open_transport(port).await)
}

/// Same controller, with a [`FaultInjector`] between it and the host.
#[allow(unused)]
pub(crate) async fn create_fault_injecting_controller(port: &PathBuf, fault: Fault) -> FaultInjectingController {
    ExternalController::new(FaultInjector::new(open_transport(port).await, fault))
}

async fn open_transport(port: &PathBuf) -> Serial {
    let port = port.to_string_lossy();
    let baudrate = 1000000;
    let mut port = SerialStream::open(
        &tokio_serial::new(port, baudrate)
            .baud_rate(baudrate)
            .data_bits(DataBits::Eight)
            .parity(Parity::None)
            .stop_bits(StopBits::One),
    )
    .unwrap();

    // Drain input
    tokio::time::sleep(Duration::from_secs(1)).await;
    loop {
        let mut buf = [0; 1];
        match port.try_read(&mut buf[..]) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            _ => {}
        }
    }

    let (reader, writer) = tokio::io::split(port);

    let reader = embedded_io_adapters::tokio_1::FromTokio::new(reader);
    let writer = embedded_io_adapters::tokio_1::FromTokio::new(writer);

    SerialTransport::new(reader, writer)
}

/// A fault to inject into the HCI event stream.
///
/// The controller decides the order in which it reports events, and the interesting orderings are
/// the ones a working link never produces. Rather than wait for a controller to misbehave, put the
/// pattern on the wire deliberately.
#[allow(dead_code)]
#[derive(Clone, Copy, PartialEq)]
pub enum Fault {
    /// After every Disconnection Complete, deliver an Encryption Change for the handle that just
    /// went away.
    ///
    /// This is what the controller produces on a MIC failure, where Disconnection Complete comes
    /// first and the encryption event trails it — but it is not limited to failures, so the
    /// injected event carries a *success* status to make that explicit.
    EncryptionChangeAfterDisconnect,
}

/// Wraps a [`Transport`] and injects [`Fault`]s into the packets on their way to the host.
///
/// Only the pattern under test is altered; every other packet is passed through as read.
///
/// Note what this does and does not show: it proves how the host reacts to an event sequence, not
/// that any particular controller emits it. The sequence above is one the specification permits.
pub struct FaultInjector<T> {
    inner: T,
    fault: Fault,
    /// Event parameters to hand over on the next read, if any.
    pending: RefCell<Option<(EventKind, usize, [u8; 8])>>,
}

impl<T> FaultInjector<T> {
    pub fn new(inner: T, fault: Fault) -> Self {
        Self {
            inner,
            fault,
            pending: RefCell::new(None),
        }
    }

    /// Build an Encryption Change (v1) for `handle`: status success, encryption enabled.
    fn arm_encryption_change(&self, disconnect_params: &[u8]) {
        // Disconnection Complete parameters: status, connection handle (2), reason.
        if disconnect_params.len() < 3 {
            return;
        }
        let mut params = [0u8; 8];
        params[0] = 0x00; // status: success
        params[1] = disconnect_params[1];
        params[2] = disconnect_params[2];
        params[3] = 0x01; // encryption enabled
        *self.pending.borrow_mut() = Some((EventKind::EncryptionChangeV1, 4, params));
    }
}

impl<T: embedded_io::ErrorType> embedded_io::ErrorType for FaultInjector<T> {
    type Error = T::Error;
}

impl<T: bt_hci::transport::Transport> bt_hci::transport::Transport for FaultInjector<T> {
    async fn write<P: HostToControllerPacket>(&self, val: &P) -> Result<(), Self::Error> {
        self.inner.write(val).await
    }

    async fn read<'a>(&self, rx: &'a mut [u8]) -> Result<ControllerToHostPacket<'a>, Self::Error> {
        // An injected event was armed by the previous read. Hand it over now, once the host has
        // finished processing the disconnection that armed it.
        if let Some((kind, len, params)) = self.pending.borrow_mut().take() {
            println!("[fault] injecting {:?} for a handle the host has already dropped", kind);
            rx[..len].copy_from_slice(&params[..len]);
            return Ok(ControllerToHostPacket::Event(EventPacket { kind, data: &rx[..len] }));
        }

        // Read into scratch so the caller's buffer is free to be rewritten, then rebuild the packet
        // out of `rx` so the borrow the host gets is the one it expects.
        let mut scratch = [0u8; 259];
        let (kind, len, acl) = {
            match self.inner.read(&mut scratch).await? {
                ControllerToHostPacket::Event(event) => {
                    let len = event.data.len().min(rx.len());
                    rx[..len].copy_from_slice(&event.data[..len]);
                    (Some(event.kind), len, None)
                }
                ControllerToHostPacket::Acl(acl) => {
                    let data = acl.data();
                    let len = data.len().min(rx.len());
                    rx[..len].copy_from_slice(&data[..len]);
                    (
                        None,
                        len,
                        Some((acl.handle(), acl.boundary_flag(), acl.broadcast_flag())),
                    )
                }
                other => panic!("[fault] unsupported packet kind: {:?}", other.kind()),
            }
        };

        if let Some((handle, pbf, bf)) = acl {
            return Ok(ControllerToHostPacket::Acl(AclPacket::new(handle, pbf, bf, &rx[..len])));
        }

        let kind = kind.unwrap();
        match self.fault {
            Fault::EncryptionChangeAfterDisconnect if kind == EventKind::DisconnectionComplete => {
                self.arm_encryption_change(&rx[..len]);
            }
            _ => {}
        }

        Ok(ControllerToHostPacket::Event(EventPacket { kind, data: &rx[..len] }))
    }
}
