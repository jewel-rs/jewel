#![no_std]

use core::mem;

use embassy_nrf::radio::{
    ble::{Error, Mode, Radio as NrfRadio, TxPower},
    Instance,
};
use jewel::{
    phy::{ChannelTrait, Radio, CRC_POLY},
    Address,
};

pub struct RadioImpl<'d, T: Instance> {
    radio: NrfRadio<'d, T>,
}

// From 5.4.1 of the nRF52840 Product Specification:
// > The HFXO must be running to use the RADIO or  the calibration mechanism associated with the 32.768 kHz RC oscillator.
// Currently the jewel crate don't implement the calibration mechanism, so we need to ensure that the HFXO is running
impl<'d, T: Instance> From<NrfRadio<'d, T>> for RadioImpl<'d, T> {
    fn from(radio: NrfRadio<'d, T>) -> Self {
        RadioImpl { radio }
    }
}

impl<'d, T: Instance> Radio for RadioImpl<'d, T> {
    type Error = Error;

    fn set_mode(&mut self, mode: jewel::phy::Mode) {
        let embassy_mode = match mode {
            jewel::phy::Mode::Ble1mbit => Mode::BLE_1MBIT,
        };

        self.radio.set_mode(embassy_mode);
    }

    fn set_tx_power(&mut self, power_db: i8) {
        let tx_power: TxPower = match power_db {
            #[cfg(not(feature = "nrf5340"))]
            8 => TxPower::POS8D_BM,
            #[cfg(not(feature = "nrf5340"))]
            7 => TxPower::POS7D_BM,
            #[cfg(not(feature = "nrf5340"))]
            6 => TxPower::POS6D_BM,
            #[cfg(not(feature = "nrf5340"))]
            5 => TxPower::POS5D_BM,
            #[cfg(not(feature = "nrf5340"))]
            4 => TxPower::POS4D_BM,
            #[cfg(not(feature = "nrf5340"))]
            3 => TxPower::POS3D_BM,
            #[cfg(not(feature = "nrf5340"))]
            2 => TxPower::POS2D_BM,
            0 => TxPower::_0D_BM,
            -4 => TxPower::NEG4D_BM,
            -8 => TxPower::NEG8D_BM,
            -12 => TxPower::NEG12D_BM,
            -16 => TxPower::NEG16D_BM,
            -20 => TxPower::NEG20D_BM,
            -30 => TxPower::NEG30D_BM,
            -40 => TxPower::NEG40D_BM,
            _ => panic!("Invalid power level"),
        };

        self.radio.set_tx_power(tx_power)
    }

    fn set_header_size(&mut self, header_size: jewel::phy::HeaderSize) {
        let use_s1 = match header_size {
            jewel::phy::HeaderSize::TwoBytes => false,
            jewel::phy::HeaderSize::ThreeBytes => true,
        };
        self.radio.set_header_expansion(use_s1)
    }

    fn set_access_address(&mut self, access_address: u32) {
        self.radio.set_access_address(access_address)
    }

    fn set_channel(&mut self, channel: jewel::phy::Channel) {
        self.radio.set_frequency(channel.central_frequency().into());
        self.radio.set_whitening_init(channel.whitening_init());
    }

    fn set_crc_init(&mut self, crc_init: u32) {
        self.radio.set_crc_poly(CRC_POLY);
        self.radio.set_crc_init(crc_init)
    }

    fn set_crc_poly(&mut self, crc_poly: u32) {
        self.radio.set_crc_poly(crc_poly)
    }

    async fn transmit(&mut self, buffer: &[u8]) -> Result<(), Self::Error> {
        self.radio.transmit(buffer).await
    }

    async fn receive(&mut self, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.radio.receive(buffer).await
    }

    fn device_address(&self) -> Address {
        let ficr: embassy_nrf::pac::FICR = unsafe { mem::transmute(()) };
        let device_address_public = ficr.deviceaddrtype.read().deviceaddrtype().is_public();
        let device_address = u64::from(ficr.deviceaddr[0].read().bits())
            | u64::from(ficr.deviceaddr[1].read().bits());

        if device_address_public {
            Address::new_public(device_address)
        } else {
            Address::new_random(device_address)
        }
    }
}
