//! Advertising and Scan Response data format
//!
//! Ref: [Core 3.C.11](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-54/out/en/host/generic-access-profile.html#UUID-c2a0b759-8ef4-7055-c13b-17c083691361)
//!
//! The AD type identifier values are defined in [Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/).
//! The AD type data formats and meanings are defined in Section 1 of the Part A of the [Core Specification Supplementi](https://www.bluetooth.com/specifications/specs/core-specification-supplement-10/)

pub use flags::*;
use local_name::*;
use uuid::*;

use defmt::Format;

use crate::phy::MAX_PDU_LENGTH;

#[derive(Debug, Clone, PartialEq, Eq, Format, Default)]
#[non_exhaustive]
pub struct AdvData<'a> {
    flags: Option<Flags>,

    // The spec are if the UUIds should be diferent AdStructures
    // Guessing from the wireshark output, it seems that are different AD structures
    uuids16: Option<List<'a, Uuid16>>,
    uuids32: Option<List<'a, Uuid32>>,
    uuids128: Option<List<'a, Uuid128>>,

    local_name: Option<LocalName<'a>>,
}

// Builder
impl<'a> AdvData<'a> {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn set_flags(mut self, flags: Flags) -> Self {
        self.flags = Some(flags);
        self
    }

    pub fn set_complete_local_name(mut self, local_name: &'a str) -> Self {
        self.local_name = Some(LocalName {
            name: local_name.as_bytes(),
            r#type: LocalNameType::Complete,
        });
        self
    }

    pub fn set_uuids16(mut self, uuids: &'a [Uuid16]) -> Self {
        self.uuids16 = Some(List(uuids));
        self
    }

    pub fn set_uuids32(mut self, uuids: &'a [Uuid32]) -> Self {
        self.uuids32 = Some(List(uuids));
        self
    }

    pub fn set_uuids128(mut self, uuids: &'a [Uuid128]) -> Self {
        self.uuids128 = Some(List(uuids));
        self
    }
}

impl<'a> AdvData<'a> {
    pub fn bytes(&self, dest: &mut [u8]) -> usize {
        let mut start = 0;
        if let Some(flags) = &self.flags {
            start += 1;
            let len = flags.bytes(&mut dest[start..]);
            dest[start - 1] = len as u8;
            start += len;
        }
        if let Some(uuids16) = &self.uuids16 {
            start += 1;
            let len = uuids16.bytes(&mut dest[start..]);
            dest[start - 1] = len as u8;
            start += len;
        }
        if let Some(local_name) = &self.local_name {
            start += 1;
            let len = local_name.bytes(&mut dest[start..]);
            dest[start - 1] = len as u8;
            start += len;
        }
        start
    }
}

/// Cap 1.1 in Section 1.3 of the Core Specification Supplement
mod uuid {
    use core::mem::size_of;

    use defmt::Format;

    pub type Uuid16 = u16;
    pub type Uuid32 = u32;
    pub type Uuid128 = u128;

    pub trait Uuid
    where
        Self: Sized + Copy + Default + Format + PartialEq + Eq,
    {
        const INCOMPLETE_AD_TYPE: u8;
        const COMPLETE_AD_TYPE: u8;

        fn bytes(&self, dest: &mut [u8]) -> usize;
        fn parse(bytes: &[u8]) -> Self;
    }

    #[derive(Debug, Clone, Format, PartialEq, Eq)]
    pub struct List<'a, T: Uuid>(pub(crate) &'a [T]);

    impl<'a, T> List<'a, T>
    where
        T: Uuid,
    {
        // 1 byte for the AD type and N bytes for the UUIDs
        const BLOCK_SIZE: usize = 1 + size_of::<T>();

        /// Write the list of UUIDs to the given buffer.
        /// The buffer must be large enough to hold all UUIDs.
        pub fn bytes(&self, dest: &mut [u8]) -> usize {
            let len = self.0.len() * Self::BLOCK_SIZE;
            if len == 0 {
                return 0;
            }

            assert!(dest.len() >= len);

            let mut start = 0;
            for (i, uuid) in self.0.iter().enumerate() {
                start = i * Self::BLOCK_SIZE;
                let end = start + Self::BLOCK_SIZE;

                dest[start] = T::INCOMPLETE_AD_TYPE;
                uuid.bytes(&mut dest[start + 1..end]);
            }
            // Set the last AD type to indicate the end of the list
            dest[start] = T::COMPLETE_AD_TYPE;

            len
        }

        /// Parse the list of UUIDs from the given buffer.
        /// The buffer must be large enough to hold all UUIDs.
        pub fn parse(bytes: &[u8], dest: &'a mut [T]) -> Self {
            if bytes.is_empty() {
                return Self(&[]);
            }

            let mut bytes = bytes;
            let mut i = 0;
            loop {
                let (head, tail) = bytes.split_at(Self::BLOCK_SIZE);
                bytes = tail;

                let ad_type = head[0];
                let data = &head[1..];
                dest[i] = T::parse(data);

                i += 1;
                if ad_type == T::COMPLETE_AD_TYPE {
                    break;
                }
            }

            Self(&dest[..i])
        }
    }

    impl Uuid for Uuid16 {
        const INCOMPLETE_AD_TYPE: u8 = 0x02;
        const COMPLETE_AD_TYPE: u8 = 0x03;

        fn bytes(&self, dest: &mut [u8]) -> usize {
            dest.copy_from_slice(&self.to_be_bytes());
            size_of::<Self>()
        }

        fn parse(bytes: &[u8]) -> Self {
            u16::from_be_bytes([bytes[0], bytes[1]])
        }
    }

    impl Uuid for Uuid32 {
        const INCOMPLETE_AD_TYPE: u8 = 0x04;
        const COMPLETE_AD_TYPE: u8 = 0x05;

        fn bytes(&self, dest: &mut [u8]) -> usize {
            dest.copy_from_slice(&self.to_be_bytes());
            size_of::<Self>()
        }

        fn parse(bytes: &[u8]) -> Self {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
    }

    impl Uuid for Uuid128 {
        const INCOMPLETE_AD_TYPE: u8 = 0x06;
        const COMPLETE_AD_TYPE: u8 = 0x07;

        fn bytes(&self, dest: &mut [u8]) -> usize {
            dest.copy_from_slice(&self.to_be_bytes());
            size_of::<Self>()
        }

        fn parse(bytes: &[u8]) -> Self {
            let mut data = [0; 16];
            data.copy_from_slice(bytes);
            Self::from_be_bytes(data)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        mod uuid16 {
            use super::*;
            #[test]
            fn serialize() {
                let uuid: Uuid16 = 0x1234;

                let mut buf = [0; 2];
                let len = uuid.bytes(&mut buf);

                assert_eq!(buf, [0x12, 0x34]);
                assert_eq!(len, 2);
            }

            #[test]
            fn deserialize() {
                let uuid = Uuid16::parse(&[0x12, 0x34]);
                assert_eq!(uuid, 0x1234);
            }

            #[test]
            fn empty_list_serialize() {
                let uuids = [0u16; 0];
                let list = List(&uuids);

                let mut buf = [0; 10];
                let len = list.bytes(&mut buf);

                assert_eq!(buf, [0; 10]);
                assert_eq!(len, 0);
            }

            #[test]
            fn one_item_list_serialize() {
                let uuids = [0x1234u16];
                let list = List(&uuids);

                let mut buf = [0; 3];
                let len = list.bytes(&mut buf);

                assert_eq!(buf, [0x03, 0x12, 0x34]);
                assert_eq!(len, 3);
            }

            #[test]
            fn list_serialize() {
                let uuids = [0x1234u16, 0x5678, 0x9ABC];
                let list = List(&uuids);

                let mut buf = [0; 9];
                let len = list.bytes(&mut buf);

                assert_eq!(buf, [0x02, 0x12, 0x34, 0x02, 0x56, 0x78, 0x03, 0x9A, 0xBC]);
                assert_eq!(len, 9);
            }
        }

        mod uuid32 {
            use super::*;
            #[test]
            fn serialize_32_uuids() {
                let uuid: Uuid32 = 0x1234_5678;

                let mut buf = [0; 4];
                let len = uuid.bytes(&mut buf);

                assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
                assert_eq!(len, 4);
            }

            #[test]
            fn deserialize_32_bit_uuids() {
                let uuid = Uuid32::parse(&[0x12, 0x34, 0x56, 0x78]);
                assert_eq!(uuid, 0x1234_5678);
            }
        }

        mod uuid128 {
            use super::*;
            #[test]
            fn serialize_128_uuids() {
                let uuid = Uuid128::from_u128(0x1234_5678_9ABC_DEF0_1234_5678_9ABC_DEF0);

                let mut buf = [0; 16];
                let len = uuid.bytes(&mut buf);

                assert_eq!(
                    buf,
                    [
                        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78,
                        0x9A, 0xBC, 0xDE, 0xF0
                    ]
                );
                assert_eq!(len, 16);
            }

            #[test]
            fn deserialize_128_bit_uuids() {
                let uuid = Uuid128::parse(&[
                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A,
                    0xBC, 0xDE, 0xF0,
                ]);

                assert_eq!(
                    uuid,
                    Uuid128::from_u128(0x1234_5678_9ABC_DEF0_1234_5678_9ABC_DEF0)
                );
            }
        }
    }
}

/// Cap 1.2 in Section 1.3 of the Core Specification Supplement
mod local_name {
    use defmt::Format;

    #[derive(Debug, Clone, Format, PartialEq, Eq)]
    pub enum LocalNameType {
        Shortened,
        Complete,
    }

    #[derive(Debug, Clone, Format, PartialEq, Eq)]
    pub struct LocalName<'a> {
        pub name: &'a [u8],
        pub r#type: LocalNameType,
    }

    impl<'a> LocalName<'a> {
        pub const SHORTENETD_AD_TYPE: u8 = 0x08;
        pub const COMPLETE_AD_TYPE: u8 = 0x09;

        pub fn bytes(&self, dest: &mut [u8]) -> usize {
            let len = 1 + self.name.len();
            dest[0] = match self.r#type {
                LocalNameType::Shortened => Self::SHORTENETD_AD_TYPE,
                LocalNameType::Complete => Self::COMPLETE_AD_TYPE,
            };
            dest[1..len].copy_from_slice(self.name);

            len
        }

        pub fn parse(bytes: &'a [u8]) -> Self {
            let r#type = match bytes[0] {
                Self::SHORTENETD_AD_TYPE => LocalNameType::Shortened,
                Self::COMPLETE_AD_TYPE => LocalNameType::Complete,
                _ => panic!("Invalid AD type for local name"),
            };

            Self {
                name: &bytes[1..],
                r#type,
            }
        }

        pub fn to_str(&self) -> &str {
            core::str::from_utf8(self.name).unwrap()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn serialize_shortened_local_name() {
            let name = LocalName {
                name: b"test",
                r#type: LocalNameType::Shortened,
            };

            let mut buf = [0; 5];
            let len = name.bytes(&mut buf);
            assert_eq!(buf, [0x08, b't', b'e', b's', b't']);
            assert_eq!(len, 5);
        }

        #[test]
        fn deserialize_shortened_local_name() {
            let name = LocalName::parse(&[0x08, b't', b'e', b's', b't']);
            assert_eq!(name.name, b"test");
            assert_eq!(name.r#type, LocalNameType::Shortened);
        }

        #[test]
        fn serialize_complete_local_name() {
            let name = LocalName {
                name: b"test",
                r#type: LocalNameType::Complete,
            };

            let mut buf = [0; 5];
            let len = name.bytes(&mut buf);
            assert_eq!(buf, [0x09, b't', b'e', b's', b't']);
            assert_eq!(len, 5);
        }

        #[test]
        fn deserialize_complete_local_name() {
            let name = LocalName::parse(&[0x09, b't', b'e', b's', b't']);
            assert_eq!(name.name, b"test");
            assert_eq!(name.r#type, LocalNameType::Complete);
        }
    }
}

/// Cap 1.3 in Section 1.3 of the Core Specification Supplement
mod flags {
    use defmt::Format;

    #[derive(Debug, Clone, Format, PartialEq, Eq)]
    pub struct Flags {
        /// Device operating in LE Limited Discoverable mode.
        ///
        /// Either this or `le_general_disc` must be set for the device to be discoverable.
        /// Note that "Broadcast Mode" still works with undiscoverable devices, since it doesn't need
        /// discovery or connections.
        pub le_limited_disc: bool,

        /// Device operating in LE General Discoverable mode.
        ///
        /// Either this or `le_limited_disc` must be set for the device to be discoverable.
        /// Note that "Broadcast Mode" still works with undiscoverable devices, since it doesn't need
        /// discovery or connections.
        pub le_general_disc: bool,

        /// Indicate if the device that sent this `Flags` value supports BR/EDR (aka "Classic Bluetooth").
        pub br_edr_not_supported: bool,

        pub simultaneous_le_bredr_capable_controller: bool, // not used in BLE
    }

    // Based in rubble implementation https://github.com/jonas-schievink/rubble/blob/f475c20e213fcd0a957521951bea3c3892699640/rubble/src/link/ad_structure.rs#L264-L309
    impl Flags {
        pub const AD_TYPE: u8 = 0x01;

        pub fn non_discoverable() -> Self {
            Self {
                le_limited_disc: false,
                le_general_disc: false,
                br_edr_not_supported: true,
                simultaneous_le_bredr_capable_controller: false,
            }
        }

        /// Returns flags suitable for discoverable devices that want to establish a connection.
        ///
        /// The created `Flags` value specifies that this device is not BR/EDR (classic Bluetooth)
        /// capable and is in General Discoverable mode.
        pub fn discoverable() -> Self {
            Self {
                le_limited_disc: false,
                le_general_disc: true,
                br_edr_not_supported: true,
                simultaneous_le_bredr_capable_controller: false,
            }
        }

        /// Returns flags suitable for non-connectable devices that just broadcast advertising packets.
        ///
        /// Creates a `Flags` value that specifies that BR/EDR (classic Bluetooth) is not supported and
        /// that this device is not discoverable.
        pub fn broadcast() -> Self {
            Self {
                le_limited_disc: false,
                le_general_disc: false,
                br_edr_not_supported: true,
                simultaneous_le_bredr_capable_controller: false,
            }
        }

        fn byte(&self) -> u8 {
            (self.le_limited_disc as u8)
                | (self.le_general_disc as u8) << 1
                | (self.br_edr_not_supported as u8) << 2
                | (self.simultaneous_le_bredr_capable_controller as u8) << 3
        }

        pub(crate) fn bytes(&self, dest: &mut [u8]) -> usize {
            dest[0] = Self::AD_TYPE;
            dest[1] = self.byte();
            2
        }

        fn parse_byte(byte: u8) -> Self {
            Self {
                le_limited_disc: byte & 0b0000_0001 != 0,
                le_general_disc: byte & 0b0000_0010 != 0,
                br_edr_not_supported: byte & 0b0000_0100 != 0,
                simultaneous_le_bredr_capable_controller: byte & 0b0000_1000 != 0,
            }
        }

        pub(crate) fn parse(bytes: &[u8]) -> Self {
            assert_eq!(bytes[0], Self::AD_TYPE);
            Self::parse_byte(bytes[1])
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn serialize_flags() {
            let flags = Flags {
                le_limited_disc: true,
                le_general_disc: false,
                br_edr_not_supported: true,
                simultaneous_le_bredr_capable_controller: false,
            };

            assert_eq!(flags.byte(), 0b0000_0101);

            let mut buf = [0; 2];
            let len = flags.bytes(&mut buf);
            assert_eq!(buf, [0x01, 0b0000_0101]);
            assert_eq!(len, 2);
        }

        #[test]
        fn deserialize_flags() {
            assert_eq!(
                Flags::parse(&[0x01, 0b0000_0101]),
                Flags {
                    le_limited_disc: true,
                    le_general_disc: false,
                    br_edr_not_supported: true,
                    simultaneous_le_bredr_capable_controller: false,
                }
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty_adv_data() {
        let adv_data = AdvData::empty();
        let mut buf = [0; 31];
        let len = adv_data.bytes(&mut buf);

        assert_eq!(buf, [0; 31]);
        assert_eq!(len, 0);
    }

    #[test]
    fn full() {
        let adv_data = AdvData::empty()
            .set_flags(Flags::discoverable())
            .set_uuids16(&[0x0918])
            .set_complete_local_name("HelloRust");

        let expected = [
            0x02, 0x01, 0x06, // Flags
            0x03, 0x03, 0x09, 0x18, // Complete list of 16-bit UUIDs available
            0x0A, 0x09, // Length, Type: Device name
            b'H', b'e', b'l', b'l', b'o', b'R', b'u', b's', b't',
        ];

        let mut buf = [0; 31];
        let len = adv_data.bytes(&mut buf);

        assert_eq!(&buf[..len], &expected[..]);
    }
}
