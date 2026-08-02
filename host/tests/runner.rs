//! Tests that the host runner survives events it cannot act on.
//!
//! Requires the `security` feature: without it `handle_security_hci_event` is a no-op and there is
//! nothing to observe.
#![cfg(feature = "security")]

use std::time::Duration;

use tokio::select;
use trouble_host::prelude::*;

mod common;

const CONNECTIONS_MAX: usize = 1;
const L2CAP_CHANNELS_MAX: usize = 3;

/// The injector's own test: no radio involved, so it can be run anywhere with
/// `cargo test --features log,security --test runner injector`.
///
/// Pins the bytes the fabricated event is built from — a wrong offset here would produce an
/// encryption event for the wrong handle, which the host would ignore for reasons that have nothing
/// to do with what the hardware test is trying to show.
mod injector {
    use bt_hci::event::{EventKind, EventPacket};
    use bt_hci::transport::Transport;
    use bt_hci::{ControllerToHostPacket, HostToControllerPacket};

    use crate::common::{Fault, FaultInjector};

    /// Yields one canned Disconnection Complete for handle 0x0002, then stalls.
    struct OneDisconnect {
        sent: core::cell::Cell<bool>,
    }

    impl embedded_io::ErrorType for OneDisconnect {
        type Error = embedded_io::ErrorKind;
    }

    impl Transport for OneDisconnect {
        async fn write<P: HostToControllerPacket>(&self, _val: &P) -> Result<(), Self::Error> {
            Ok(())
        }

        async fn read<'a>(&self, rx: &'a mut [u8]) -> Result<ControllerToHostPacket<'a>, Self::Error> {
            assert!(!self.sent.replace(true), "the injector read past the canned packet");
            // Disconnection Complete parameters: status success, handle 0x0002, reason 0x13.
            rx[..4].copy_from_slice(&[0x00, 0x02, 0x00, 0x13]);
            Ok(ControllerToHostPacket::Event(EventPacket {
                kind: EventKind::DisconnectionComplete,
                data: &rx[..4],
            }))
        }
    }

    #[tokio::test]
    async fn fabricates_an_encryption_change_for_the_dropped_handle() {
        let injector = FaultInjector::new(
            OneDisconnect {
                sent: core::cell::Cell::new(false),
            },
            Fault::EncryptionChangeAfterDisconnect,
        );

        let mut buf = [0u8; 259];
        match injector.read(&mut buf).await.unwrap() {
            ControllerToHostPacket::Event(e) => assert_eq!(e.kind, EventKind::DisconnectionComplete),
            _ => panic!("expected the disconnection to pass through untouched"),
        }

        let mut buf = [0u8; 259];
        match injector.read(&mut buf).await.unwrap() {
            ControllerToHostPacket::Event(e) => {
                assert_eq!(e.kind, EventKind::EncryptionChangeV1);
                // status success, handle 0x0002 (little endian), encryption enabled.
                assert_eq!(e.data, &[0x00, 0x02, 0x00, 0x01]);
            }
            _ => panic!("expected a fabricated encryption change"),
        }
    }
}

/// An encryption event that arrives after its connection is gone must not end the host.
///
/// `SecurityManager::handle_hci_event` resolves the handle with `with_connected_handle` on both of
/// its branches, so an encryption event for a handle the host has already dropped returns
/// `Error::Disconnected`. That used to be propagated out of the rx event loop with `?`, which ends
/// `Runner::run` and with it every connection — over a condition the controller is free to produce
/// (a MIC failure reports Disconnection Complete first, and the encryption event trails it).
///
/// The peripheral runs behind a [`common::FaultInjector`] that delivers exactly that: after the
/// first link drops, an Encryption Change for the handle that just went away, with a *success*
/// status, to show that no failure of any kind is needed.
///
/// The assertion is the second connection. If the runner died on the injected event, the peripheral
/// never advertises again and the central never connects a second time.
#[tokio::test]
async fn encryption_event_after_disconnect_does_not_stop_the_runner() {
    let _ = env_logger::try_init();
    let adapters = common::find_controllers();
    let peripheral = adapters[0].clone();
    let central = adapters[1].clone();

    let peripheral_address: Address = Address::random([0xff, 0x9f, 0x1b, 0x05, 0xe4, 0xff]);

    let local = tokio::task::LocalSet::new();

    let peripheral = local.spawn_local(async move {
        let controller =
            common::create_fault_injecting_controller(&peripheral, common::Fault::EncryptionChangeAfterDisconnect)
                .await;

        let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
        let stack = trouble_host::new(controller, &mut resources)
            .set_random_address(peripheral_address)
            .build();
        let mut runner = stack.runner();
        let mut peripheral = stack.peripheral();

        select! {
            r = runner.run() => {
                // Reaching this at all is the failure the test is about.
                println!("[peripheral] runner exited: {:?}", r);
                r
            }
            r = async {
                let mut adv_data = [0; 31];
                let adv_data_len = AdStructure::encode_slice(
                    &[AdStructure::Flags(LE_GENERAL_DISCOVERABLE | BR_EDR_NOT_SUPPORTED)],
                    &mut adv_data[..],
                ).unwrap();

                let mut scan_data = [0; 31];
                let scan_data_len = AdStructure::encode_slice(
                    &[AdStructure::CompleteLocalName(b"trouble-runner-int")],
                    &mut scan_data[..],
                ).unwrap();

                for round in 1..=2 {
                    println!("[peripheral] round {round}: advertising");
                    let acceptor = peripheral.advertise(&Default::default(), Advertisement::ConnectableScannableUndirected {
                        adv_data: &adv_data[..adv_data_len],
                        scan_data: &scan_data[..scan_data_len],
                    }).await?;
                    let conn = acceptor.accept().await?;
                    println!("[peripheral] round {round}: connected");

                    loop {
                        match conn.next().await {
                            ConnectionEvent::Disconnected { reason } => {
                                println!("[peripheral] round {round}: disconnected: {:?}", reason);
                                break;
                            }
                            ConnectionEvent::RequestConnectionParams(req) => {
                                let _ = req.accept(None, &stack).await;
                            }
                            _ => {}
                        }
                    }
                    // The injected event lands here, between the disconnection and the next
                    // advertisement. Give the runner a moment to fall over if it is going to.
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }

                println!("[peripheral] survived the injected event and served a second connection");
                Ok(())
            } => {
                r
            }
        }
    });

    let central = local.spawn_local(async move {
        let controller = common::create_controller(&central).await;
        let mut resources: HostResources<DefaultPacketPool, CONNECTIONS_MAX, L2CAP_CHANNELS_MAX> = HostResources::new();
        let stack = trouble_host::new(controller, &mut resources).build();
        let mut runner = stack.runner();
        let mut central = stack.central();

        select! {
            r = runner.run() => {
                r
            }
            r = async {
                let config = ConnectConfig {
                    connect_params: Default::default(),
                    scan_config: ScanConfig {
                        active: true,
                        filter_accept_list: &[peripheral_address],
                        ..Default::default()
                    },
                };

                for round in 1..=2 {
                    println!("[central] round {round}: connecting");
                    let conn = central.connect(&config).await?;
                    println!("[central] round {round}: connected");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    conn.disconnect();
                    // Let the peripheral see the disconnection, and the injected event after it,
                    // before asking for the link back.
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }

                println!("[central] second connection completed, the peripheral's runner is alive");
                Ok(())
            } => {
                r
            }
        }
    });

    match tokio::time::timeout(Duration::from_secs(40), local).await {
        Ok(_) => match tokio::join!(central, peripheral) {
            (Err(e1), Err(e2)) => {
                println!("Central error: {:?}", e1);
                println!("Peripheral error: {:?}", e2);
                panic!();
            }
            (Err(e), _) => {
                println!("Central error: {:?}", e);
                panic!();
            }
            (_, Err(e)) => {
                println!("Peripheral error: {:?}", e);
                panic!();
            }
            _ => {
                println!("Test completed successfully");
            }
        },
        Err(e) => {
            println!("Test timed out: {:?}", e);
            panic!();
        }
    }
}
