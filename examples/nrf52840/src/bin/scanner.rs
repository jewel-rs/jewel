#![no_std]
#![no_main]

use defmt::{info, unwrap};
use embassy_executor::Spawner;
use embassy_nrf::{bind_interrupts, peripherals, radio};
use embassy_time::Timer;
use jewel::radio::{BleRadio, MAX_PDU_LENGTH};
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
});

// Same payload as the embassy/nrf-softdevice ble_advertising example,
// but just in channel 39.
#[embassy_executor::main]
async fn main(_spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;
    let p = embassy_nrf::init(config);

    info!("Starting radio");

    let mut radio = radio::ble::Radio::new(p.RADIO, Irqs);

    let mut buffer = [0u8; MAX_PDU_LENGTH];
    unwrap!(radio.set_buffer_mut(buffer.as_mut()));

    loop {
        info!("Receiving packet");
        radio.receive().await;
        info!("Received packet: {:?}", &buffer);
        Timer::after_millis(500).await;
    }
}