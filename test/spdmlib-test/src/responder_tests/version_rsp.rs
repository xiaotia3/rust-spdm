// Copyright (c) 2020 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use crate::common::crypto_callback::{FAKE_ASYM_VERIFY, FAKE_HMAC};
use crate::common::device_io::{FakeSpdmDeviceIoReceve, SharedBuffer};
use crate::common::secret_callback::SECRET_ASYM_IMPL_INSTANCE;
use crate::common::transport::PciDoeTransportEncap;
use crate::common::util::{create_info, TestSpdmMessage};
use codec::{Codec, Reader, Writer};
use spdmlib::common::session::SpdmSessionState;
use spdmlib::common::*;
use spdmlib::config::{MAX_SPDM_MSG_SIZE, MAX_SPDM_SESSION_COUNT};
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::{responder, secret};
use spin::Mutex;
extern crate alloc;
use crate::watchdog_impl_sample::init_watchdog;
use alloc::sync::Arc;

#[test]
fn test_case0_handle_spdm_version() {
    let future = async {
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));

        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());

        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));

        let mut context = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        let bytes = &mut [0u8; 1024];
        let mut writer = Writer::init(bytes);
        let value = SpdmMessageHeader {
            version: SpdmVersion::SpdmVersion10,
            request_response_code: SpdmRequestResponseCode::SpdmRequestChallenge,
        };
        assert!(value.encode(&mut writer).is_ok());

        let mut response_buffer = [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer = Writer::init(&mut response_buffer);
        context.handle_spdm_version(bytes, &mut writer);

        let data = context.common.runtime_info.message_a.as_ref();
        let u8_slice = &mut [0u8; 1024];
        for (i, data) in data.iter().enumerate() {
            u8_slice[i] = *data;
        }

        let mut reader = Reader::init(u8_slice);
        let spdm_message_header = SpdmMessageHeader::read(&mut reader).unwrap();
        assert_eq!(spdm_message_header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message_header.request_response_code,
            SpdmRequestResponseCode::SpdmRequestChallenge
        );

        let u8_slice = &u8_slice[4..];
        let mut reader = Reader::init(u8_slice);
        let spdm_message: SpdmMessage =
            SpdmMessage::spdm_read(&mut context.common, &mut reader).unwrap();

        assert_eq!(spdm_message.header.version, SpdmVersion::SpdmVersion10);
        assert_eq!(
            spdm_message.header.request_response_code,
            SpdmRequestResponseCode::SpdmResponseVersion
        );
        if let SpdmMessagePayload::SpdmVersionResponse(payload) = &spdm_message.payload {
            assert_eq!(payload.version_number_entry_count, 0x03);
            assert_eq!(payload.versions[0].update, 0);
            assert_eq!(payload.versions[0].version, SpdmVersion::SpdmVersion10);
            assert_eq!(payload.versions[1].update, 0);
            assert_eq!(payload.versions[1].version, SpdmVersion::SpdmVersion11);
            assert_eq!(payload.versions[2].update, 0);
            assert_eq!(payload.versions[2].version, SpdmVersion::SpdmVersion12);
        }
    };
    executor::block_on(future);
}

#[test]
#[cfg(feature = "mut-auth")]
fn test_case1_reset_state_after_receiving_get_version() {
    let future = async {
        spdmlib::crypto::asym_verify::register(FAKE_ASYM_VERIFY.clone());
        secret::asym_sign::register(SECRET_ASYM_IMPL_INSTANCE.clone());
        spdmlib::crypto::hmac::register(FAKE_HMAC.clone());
        init_watchdog();
        let (config_info, provision_info) = create_info();
        let pcidoe_transport_encap = Arc::new(Mutex::new(PciDoeTransportEncap {}));
        let shared_buffer = SharedBuffer::new();
        let socket_io_transport = Arc::new(Mutex::new(FakeSpdmDeviceIoReceve::new(Arc::new(
            shared_buffer,
        ))));
        let mut responder = responder::ResponderContext::new(
            socket_io_transport,
            pcidoe_transport_encap,
            config_info,
            provision_info,
        );

        // responder context provision - handle get_version
        let request_buffer = &mut [0x10, 0x84, 0, 0];
        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        assert!(responder
            .handle_spdm_version(request_buffer, &mut writer_rsp)
            .0
            .is_ok());
        assert!(responder
            .send_message(None, response_buffer, false)
            .await
            .is_ok());
        assert_eq!(
            responder.common.runtime_info.get_connection_state(),
            SpdmConnectionState::SpdmConnectionAfterVersion
        );

        // responder context provision - handle get_capabilities
        let request_buffer = &mut [
            0x12, 0xE1, 0, 0, 0, 0, 0, 0, 0xC6, 0x76, 0, 0, 0, 0x10, 0, 0, 0, 0x10, 0, 0,
        ];
        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        assert!(responder
            .handle_spdm_capability(request_buffer, &mut writer_rsp)
            .0
            .is_ok());
        assert!(responder
            .send_message(None, response_buffer, false)
            .await
            .is_ok());
        assert_eq!(
            responder.common.negotiate_info.spdm_version_sel,
            SpdmVersion::SpdmVersion12
        );
        assert_eq!(
            responder.common.runtime_info.get_connection_state(),
            SpdmConnectionState::SpdmConnectionAfterCapabilities
        );

        // responder context provision - handle negotiate_algorithms
        let request_buffer = &mut [
            0x12, 0xE3, 0x04, 0, 0x30, 0, 0x01, 0x02, 0x80, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x20, 0x10, 0, 0x03, 0x20, 0x02, 0, 0x04, 0x20,
            0x80, 0, 0x05, 0x20, 0x01, 0,
        ];
        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        assert!(responder
            .handle_spdm_algorithm(request_buffer, &mut writer_rsp)
            .0
            .is_ok());
        assert!(responder
            .send_message(None, response_buffer, false)
            .await
            .is_ok());
        assert_eq!(
            responder.common.runtime_info.get_connection_state(),
            SpdmConnectionState::SpdmConnectionNegotiated
        );

        // responder context provision - handle get_digests
        let request_buffer = &mut [0x12, 0x81, 0, 0];
        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        assert!(responder
            .handle_spdm_digest(request_buffer, None, &mut writer_rsp)
            .0
            .is_ok());

        let digest_message_used = writer_rsp.used();
        let mut digest_message = [0u8; MAX_SPDM_MSG_SIZE]; // save this message for reuse later
        digest_message[0..digest_message_used].copy_from_slice(writer_rsp.used_slice());
        assert!(responder
            .send_message(None, response_buffer, false)
            .await
            .is_ok());
        assert_eq!(
            responder.common.runtime_info.get_connection_state(),
            SpdmConnectionState::SpdmConnectionAfterDigest
        );

        // responder context provision - handle get_certificate
        let mut cert_messages: Vec<([u8; MAX_SPDM_MSG_SIZE], usize)> = Vec::new();
        const MAX_SPDM_CERT_PORTION_LEN: u16 = 512;
        let my_cert_chain = responder.common.provision_info.my_cert_chain[0]
            .as_ref()
            .unwrap();
        let cert_total_len = my_cert_chain.data_size;
        let mut offset: u16 = 0;
        while offset < cert_total_len {
            let request_buffer = &mut [0u8; 8];
            let writer_req = &mut Writer::init(request_buffer);
            assert!(0x12u8.encode(writer_req).is_ok());
            assert!(0x81u8.encode(writer_req).is_ok());
            assert!(0u16.encode(writer_req).is_ok());
            let send_len: u16 = (cert_total_len - offset).min(MAX_SPDM_CERT_PORTION_LEN);
            assert!(offset.encode(writer_req).is_ok());
            assert!(send_len.encode(writer_req).is_ok());
            offset += send_len;

            let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
            let mut writer_rsp = Writer::init(response_buffer);
            assert!(responder
                .handle_spdm_certificate(request_buffer, None, &mut writer_rsp)
                .0
                .is_ok());

            let mut cert_buffer = [0u8; MAX_SPDM_MSG_SIZE];
            cert_buffer[0..writer_rsp.used()].copy_from_slice(writer_rsp.used_slice());
            let cert_message: ([u8; MAX_SPDM_MSG_SIZE], usize) = (cert_buffer, writer_rsp.used());
            cert_messages.push(cert_message); // save this message for reuse later

            assert!(responder
                .send_message(None, response_buffer, false)
                .await
                .is_ok());
        }
        assert_eq!(
            responder.common.runtime_info.get_connection_state(),
            SpdmConnectionState::SpdmConnectionAfterCertificate
        );

        // responder context provision - handle key_exchange
        let request_buffer = &mut [0u8; 154];
        let random_data = &mut [
            0xBD, 0x62, 0x09, 0x83, 0x71, 0x56, 0x66, 0x90, 0x6C, 0xB1, 0xDB, 0x18, 0x70, 0x82,
            0x1E, 0xE4, 0xDF, 0xEB, 0xDF, 0xE6, 0xC5, 0xC7, 0x26, 0x3E, 0x06, 0xF8, 0xE9, 0x15,
            0x60, 0xAC, 0x0E, 0x69,
        ];
        let exchange_data = &mut [
            0xB1, 0xCE, 0xA4, 0xC4, 0x88, 0x67, 0x0F, 0x75, 0x70, 0x88, 0x20, 0x32, 0x29, 0xEE,
            0x9E, 0xAE, 0x42, 0x0F, 0x09, 0xC2, 0xC6, 0xE4, 0xA5, 0x2C, 0xE6, 0xD4, 0xF6, 0xC4,
            0xDB, 0x77, 0xEF, 0x95, 0x05, 0xD9, 0xCA, 0xAD, 0x3B, 0xE5, 0x3A, 0x39, 0x9B, 0xB4,
            0x3B, 0xA8, 0xC7, 0x23, 0x15, 0xEE, 0x8A, 0x0A, 0xCE, 0x7B, 0x2D, 0x8B, 0x8B, 0xE3,
            0xDC, 0x17, 0xB2, 0x67, 0x72, 0xBC, 0x6A, 0xF7, 0x95, 0x1D, 0x1C, 0x03, 0xE6, 0x0A,
            0x77, 0x31, 0x13, 0xF1, 0xE1, 0x0A, 0x46, 0x12, 0x82, 0xC7, 0x8D, 0x11, 0x3C, 0x6F,
            0xCF, 0x91, 0x93, 0xC7, 0x65, 0x9A, 0x62, 0x6B, 0x61, 0x12, 0x1C, 0x4A,
        ];
        let opaque = &mut [
            0x10, 0, 0x01, 0, 0, 0, 0, 0, 0x07, 0, 0x01, 0x01, 0x02, 0, 0x10, 0, 0x11, 0,
        ];
        request_buffer[0..8].copy_from_slice(&[0x12, 0xE4, 0, 0, 0xFD, 0xFF, 0, 0]);
        request_buffer[8..40].copy_from_slice(random_data);
        request_buffer[40..40 + 96].copy_from_slice(exchange_data);
        request_buffer[136..136 + 18].copy_from_slice(opaque);

        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        assert!(responder
            .handle_spdm_key_exchange(request_buffer, &mut writer_rsp)
            .0
            .is_ok());
        assert!(responder
            .send_message(None, response_buffer, false)
            .await
            .is_ok());
        assert_eq!(
            responder.common.runtime_info.get_connection_state(),
            SpdmConnectionState::SpdmConnectionAfterCertificate
        );
        assert_eq!(
            responder.common.session[0].get_session_state(),
            SpdmSessionState::SpdmSessionHandshaking
        );

        // responder context provision - handle get_encapsulated_request
        let request_buffer = &mut [0x12, 0xEA, 0, 0];
        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        assert!(responder
            .handle_get_encapsulated_request(request_buffer, &mut writer_rsp)
            .0
            .is_ok());
        assert!(responder
            .send_message(None, response_buffer, false)
            .await
            .is_ok());
        assert_eq!(
            responder.common.runtime_info.get_connection_state(),
            SpdmConnectionState::SpdmConnectionAfterCertificate
        );

        // responder context provision - handle deliver_encapsulated_response(digest)
        let request_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        request_buffer[0..4].copy_from_slice(&[0x12, 0xEB, 0, 0]);
        request_buffer[4..4 + digest_message_used]
            .copy_from_slice(&digest_message[0..digest_message_used]);
        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        assert!(responder
            .handle_deliver_encapsulated_reponse(request_buffer, &mut writer_rsp)
            .0
            .is_ok());
        assert!(responder
            .send_message(None, response_buffer, false)
            .await
            .is_ok());

        // responder context provision - handle deliver_encapsulated_response(certificate)
        for (buffer, size) in cert_messages {
            let request_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
            request_buffer[0..4].copy_from_slice(&[0x12, 0xEB, 0, 0]);
            request_buffer[4..4 + size].copy_from_slice(&buffer[0..size]);
            let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
            let mut writer_rsp = Writer::init(response_buffer);
            assert!(responder
                .handle_deliver_encapsulated_reponse(request_buffer, &mut writer_rsp)
                .0
                .is_ok());
            assert!(responder
                .send_message(None, response_buffer, false)
                .await
                .is_ok());
        }
        assert_eq!(
            responder.common.encap_context.encap_cert_size,
            cert_total_len
        );

        // responder context provision - handle finish
        let request_buffer = &mut [0u8; 148];
        let signature = &mut [
            0x42, 0xB8, 0xD3, 0x3A, 0xB3, 0x44, 0x41, 0xD7, 0x31, 0xB0, 0x52, 0xE7, 0x86, 0x5D,
            0x68, 0xD8, 0xA0, 0xFC, 0x9A, 0x81, 0xD9, 0x25, 0xF7, 0x4A, 0xB0, 0x49, 0x61, 0x64,
            0x88, 0xB2, 0x28, 0xC3, 0xF1, 0x50, 0x1E, 0xB0, 0xBA, 0xCB, 0x30, 0xE2, 0x9E, 0x70,
            0x95, 0x01, 0x56, 0xFA, 0xD9, 0x1D, 0x75, 0x07, 0x66, 0xDD, 0x5E, 0xD5, 0x31, 0x71,
            0xF4, 0xAB, 0xA7, 0xFB, 0x04, 0x5C, 0xEB, 0x97, 0x91, 0xF0, 0xCD, 0x14, 0x56, 0x29,
            0x9E, 0xEA, 0x8D, 0x8F, 0xC2, 0xC2, 0xA1, 0x35, 0x8F, 0x57, 0x08, 0x8F, 0x68, 0x17,
            0x4E, 0xF6, 0x09, 0x49, 0x11, 0xE1, 0xE8, 0x10, 0x68, 0x9D, 0x9B, 0xE7,
        ];
        let verify_data = &mut [
            0xCE, 0xFF, 0xA4, 0xB5, 0xB6, 0x97, 0x4D, 0xFE, 0x4C, 0x5C, 0xEC, 0x9F, 0x37, 0x55,
            0xEF, 0x28, 0x6C, 0xCC, 0xD3, 0x42, 0xC4, 0x4D, 0xB8, 0xD6, 0x5F, 0x8E, 0xFC, 0x6C,
            0x57, 0xA9, 0x68, 0xA9, 0xAF, 0xA7, 0x67, 0x31, 0xFA, 0xD5, 0x1E, 0x17, 0x63, 0xE8,
            0x3A, 0x0F, 0xDD, 0xE5, 0xBC, 0x73,
        ];
        request_buffer[0..4].copy_from_slice(&[0x12, 0xE5, 0x01, 0]);
        request_buffer[4..4 + 96].copy_from_slice(signature);
        request_buffer[100..100 + 48].copy_from_slice(verify_data);

        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        let session_id = responder.common.session[0].get_session_id();
        assert!(responder
            .handle_spdm_finish(session_id, request_buffer, &mut writer_rsp)
            .0
            .is_ok());
        assert!(responder
            .send_message(Some(session_id), response_buffer, false)
            .await
            .is_ok());
        assert_eq!(
            responder.common.runtime_info.get_connection_state(),
            SpdmConnectionState::SpdmConnectionAfterCertificate
        );
        assert_eq!(
            responder.common.session[0].get_session_state(),
            SpdmSessionState::SpdmSessionEstablished
        );

        // handle get version
        let request_buffer = &mut [0x10, 0x84, 0, 0];
        let response_buffer = &mut [0u8; MAX_SPDM_MSG_SIZE];
        let mut writer_rsp = Writer::init(response_buffer);
        assert!(responder
            .handle_spdm_version(request_buffer, &mut writer_rsp)
            .0
            .is_ok());
        let message_a_used = request_buffer.len() + writer_rsp.used();
        assert!(responder
            .send_message(None, response_buffer, false)
            .await
            .is_ok());

        // check sessions
        for i in 0..MAX_SPDM_SESSION_COUNT {
            assert_eq!(
                responder.common.session[i].get_session_id(),
                INVALID_SESSION_ID
            );
            assert_eq!(
                responder.common.session[i].get_session_state(),
                SpdmSessionState::SpdmSessionNotStarted
            );
        }

        // check negotiated info
        let state = &responder.common.negotiate_info;
        assert_eq!(state.spdm_version_sel, SpdmVersion::SpdmVersion10);
        assert_eq!(
            state.req_capabilities_sel.bits(),
            SpdmRequestCapabilityFlags::default().bits()
        );
        assert_eq!(
            state.rsp_capabilities_sel.bits(),
            SpdmResponseCapabilityFlags::default().bits()
        );
        assert_eq!(state.req_ct_exponent_sel, 0);
        assert_eq!(state.rsp_ct_exponent_sel, 0);
        assert_eq!(
            state.measurement_specification_sel,
            SpdmMeasurementSpecification::default()
        );
        assert_eq!(
            state.measurement_hash_sel,
            SpdmMeasurementHashAlgo::default()
        );
        assert_eq!(state.base_hash_sel, SpdmBaseHashAlgo::default());
        assert_eq!(state.base_asym_sel, SpdmBaseAsymAlgo::default());
        assert_eq!(state.dhe_sel, SpdmDheAlgo::default());
        assert_eq!(state.aead_sel, SpdmAeadAlgo::default());
        assert_eq!(state.req_asym_sel, SpdmReqAsymAlgo::default());
        assert_eq!(state.key_schedule_sel, SpdmKeyScheduleAlgo::default());
        assert_eq!(state.opaque_data_support, SpdmOpaqueSupport::default());
        assert_eq!(state.termination_policy_set, false);
        assert_eq!(state.req_data_transfer_size_sel, 0);
        assert_eq!(state.req_max_spdm_msg_size_sel, 0);
        assert_eq!(state.rsp_data_transfer_size_sel, 0);
        assert_eq!(state.rsp_max_spdm_msg_size_sel, 0);

        // check runtime info
        let state = &responder.common.runtime_info;
        assert_eq!(
            state.get_connection_state(),
            SpdmConnectionState::SpdmConnectionAfterVersion
        );
        if let Some(last_session_id) = state.get_last_session_id() {
            assert_eq!(last_session_id, INVALID_SESSION_ID);
        }
        assert_eq!(state.get_local_used_cert_chain_slot_id(), 0);
        assert_eq!(state.get_peer_used_cert_chain_slot_id(), 0);
        assert_eq!(state.need_measurement_summary_hash, false);
        assert_eq!(state.need_measurement_signature, false);
        assert_eq!(state.message_a.as_ref().len(), message_a_used);
        assert_eq!(state.digest_context_m1m2, None);
        assert_eq!(state.digest_context_l1l2, None);
        assert_eq!(
            state.content_changed,
            SpdmMeasurementContentChanged::default()
        );

        // check peer info
        let state = &responder.common.peer_info;
        for i in 0..SPDM_MAX_SLOT_NUMBER {
            assert!(state.peer_cert_chain[i].is_none());
        }
        assert!(state.peer_cert_chain_temp.is_none());

        // check encap context
        let state = &responder.common.encap_context;
        assert_eq!(state.req_slot_id, 0);
        assert_eq!(state.request_id, 0);
        assert_eq!(state.encap_cert_size, 0);
    };
    executor::block_on(future);
}

pub fn construct_version_positive() -> (TestSpdmMessage, TestSpdmMessage) {
    use crate::protocol;
    let get_version_msg = TestSpdmMessage {
        message: protocol::Message::GET_VERSION(protocol::version::GET_VERSION {
            SPDMVersion: 0x10,
            RequestResponseCode: 0x84,
            Param1: 0,
            Param2: 0,
        }),
        secure: 0,
    };
    let (config_info, provision_info) = create_info();
    let version_msg = TestSpdmMessage {
        message: protocol::Message::VERSION(protocol::version::VERSION {
            SPDMVersion: 0x10,
            RequestResponseCode: 0x04,
            Param1: 0,
            Param2: 0,
            Reserved: 0,
            VersionNumberEntryCount: config_info.spdm_version.len() as u8,
            VersionNumberEntry: {
                let mut versions = Vec::new();
                for v in config_info.spdm_version {
                    let version = (u8::from(v) as u16) << 8;
                    versions.push(version)
                }
                versions
            },
        }),
        secure: 0,
    };
    (get_version_msg, version_msg)
}
