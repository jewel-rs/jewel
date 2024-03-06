mod address;
mod adv;

pub use address::*;
pub use adv::*;
use embassy_time::{with_deadline, Duration, Instant, Timer};

use rand::{rngs::SmallRng, Rng, SeedableRng};

use crate::phy::Mode::Ble1mbit;
use crate::phy::{
    AdvertisingChannel, HeaderSize, Radio, ADV_ADDRESS, ADV_CRC_INIT, CRC_POLY, MAX_PDU_LENGTH,
};

///  Inter Frame Space
///  The time interval between two consecutive packets on the same channel index
///  It is defined as the time from the end of the last bit of the previous packet to the start of the first bit of the subsequent packet.
///
///  Ref: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-adf2f32c-5470-6d89-daf1-0a42b657da75
const T_IFS: Duration = Duration::from_micros(150);

/// Minimum AUX Frame Space
/// The minimum time interval between a packet containing an AuxPtr and the auxiliary packet it indicates.
/// It is defined as the minimum time from the end of the last bit of the packet containing the AuxPtr to the start of the auxiliary packet.
///
/// Ref: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-76fbe828-b8f7-12e4-8de2-223c867e4a2a
const T_MAFS: Duration = Duration::from_micros(300);

/// Minimum Subevent Space
/// The minimum time interval between the end of the last bit of the last packet in one subevent
/// and the start of the first bit of the first packet in the next subevent.
///
/// Ref: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-ea6717b6-1fb3-c5ec-9153-04e4b5ee20fb
const T_MSS: Duration = Duration::from_micros(150);

// TODO: Implement clock accuracy based on the receiver's clock accuracy and jitter.
// Ref: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-1cdb9b08-1996-f9bd-9dd5-9587794799b1

/// Active clock accuracy
/// The average timing of packet transmission during a connection, BIG, or CIG event, during active scanning, during a periodic advertising with responses subevent, and when requesting a connection
///
/// Ref: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-1cdb9b08-1996-f9bd-9dd5-9587794799b1
const T_ACA: Duration = Duration::from_micros(2); // less than or equal to ±50 ppm

/// Sleep clock accuracy
/// The max worst-case drift and instantaneos deviataion timing for all other activities
/// Ref: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-4a9f77e1-d1e1-dfe1-1181-032ae1feb03e
const T_SCA: Duration = Duration::from_micros(20); // less than or equal to ±500 ppm

// Guessing a reasonable propagation distance
const PROPAGATION_DISTANCE: u64 = 10; // meters

/// Range delay
/// Where two devices are more than a few meters apart the time taken for a signal to propagate between them will be significant compared with the Active Clock Accuracy
/// Ref: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-e16c5296-3b60-01b4-3251-a8f289f1cdb2
const RANGE_DELAY: Duration = Duration::from_nanos(2 * PROPAGATION_DISTANCE * 4);

// TODO: Implement Window widening
// Ref: https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/low-energy-controller/link-layer-specification.html#UUID-fed93539-5fa3-b4de-4789-1b8a1b48fa13

// pattern from https://hoverbear.org/blog/rust-state-machine-pattern/
pub struct LinkLayer<'r, R: Radio> {
    radio: &'r mut R,
}

impl<'r, R: Radio> LinkLayer<'r, R> {
    pub fn new(radio: &'r mut R) -> Self {
        LinkLayer::<R> { radio }
    }

    fn setup_legacy_adv(&mut self) {
        self.radio.set_mode(Ble1mbit);
        self.radio.set_tx_power(0);
        self.radio.set_header_size(HeaderSize::TwoBytes);
        self.radio.set_access_address(ADV_ADDRESS);
        self.radio.set_crc_init(ADV_CRC_INIT);
        self.radio.set_crc_poly(CRC_POLY);
    }

    pub async fn adv_nonconnectable_nonscannable_undirected<'a>(
        mut self,
        interval: Duration,

        adv_data: &'a [u8],
    ) -> Result<(), R::Error> {
        let rng = SmallRng::seed_from_u64(42);

        self.setup_legacy_adv();
        let mut timer = AdvertisingTimer::new(rng, interval);

        let addr = self.radio.device_address();
        let data_pdu = AdvNonconnInd::new(addr, adv_data);

        let mut data_pdu_buffer = [0u8; MAX_PDU_LENGTH];
        data_pdu.bytes(&mut data_pdu_buffer);

        loop {
            Timer::at(timer.next_event()).await;

            for channel in AdvertisingChannel::channels() {
                self.radio.set_channel(channel.into());
                self.radio.transmit(&data_pdu_buffer).await?;
            }
        }
    }

    pub async fn adv_nonconnectable_scannable_undirected<'a>(
        mut self,
        interval: Duration,

        adv_data: &'a [u8],
        scan_data: &'a [u8],
    ) -> Result<(), R::Error> {
        let rng = SmallRng::seed_from_u64(42);

        self.setup_legacy_adv();
        let mut timer = AdvertisingTimer::new(rng, interval);

        let addr = self.radio.device_address();
        let data_pdu = AdvNonconnInd::new(addr, adv_data);

        let mut data_pdu_buffer = [0u8; MAX_PDU_LENGTH];
        data_pdu.bytes(&mut data_pdu_buffer);

        Timer::at(timer.next_event()).await;
        loop {
            for channel in AdvertisingChannel::channels() {
                self.radio.set_channel(channel.into());
                self.radio.transmit(&data_pdu_buffer).await?;
            }

            // while waiting for the next advertising event
            // we can receive scan requests
            let _ = with_deadline(timer.next_event(), self.receive_scan()).await;
        }
    }

    async fn receive_scan(&mut self) {
        let mut rcv_buffer = [0u8; MAX_PDU_LENGTH];
        let _ = self.radio.receive(&mut rcv_buffer).await;
    }
}

pub struct AdvertisingTimer<RNG: Rng> {
    /// Pseudo-random value used to generate the advDelay between each advertising event
    rng: RNG,

    /// The advertising interval.
    /// It should be an integer multiple of 0.625 ms in the range 20 ms to 10,485.759375 s.
    /// used with advDelay to determine the start of the next advertising event.
    interval: Duration,

    event: Instant,
}

impl<RNG: Rng> AdvertisingTimer<RNG> {
    pub fn new(rng: RNG, interval: Duration) -> Self {
        assert!(interval >= Duration::from_micros(20_000));
        assert!(interval <= Duration::from_micros(10_485_759_375));

        Self {
            rng,
            interval,
            event: Instant::now(),
        }
    }

    /// The advDelay is a (pseudo-)random value with a range 0 ms to 10 ms generated by the Link Layer for each advertising event.
    fn rng_delay(&mut self) -> Duration {
        let delay = self.rng.gen_range(0..10_000);
        Duration::from_micros(delay)
    }

    /// Returns the next advertising event instant and updates the internal state
    fn next_event(&mut self) -> Instant {
        let event = self.event;

        self.event = event + self.interval + self.rng_delay();
        event
    }
}
