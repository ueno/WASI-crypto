mod array_output;
mod ecdsa;
mod eddsa;
mod error;
mod handles;
mod rsa;
mod signature;
mod signature_keypair;
mod signature_op;
mod signature_publickey;
mod mac;

use array_output::*;
use handles::*;
use signature::*;
use signature_keypair::*;
use signature_op::*;
use signature_publickey::*;
use mac::*;

pub use error::CryptoError;
pub use handles::Handle;
pub use signature::SignatureEncoding;
pub use signature_keypair::{KeyPairEncoding, Version};
pub use signature_publickey::PublicKeyEncoding;

#[allow(unused)]
static REBUILD_IF_WITX_FILE_IS_UPDATED: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../witx/proposal_signatures.witx"
));

wiggle::from_witx!({
    witx: ["../witx/proposal_signatures.witx",
	   "../witx/proposal_macs.witx"],
    ctx: WasiCryptoCtx
});

pub struct HandleManagers {
    pub signature_op: HandlesManager<SignatureOp>,
    pub signature_keypair_builder: HandlesManager<SignatureKeyPairBuilder>,
    pub signature_keypair: HandlesManager<SignatureKeyPair>,
    pub signature_state: HandlesManager<ExclusiveSignatureState>,
    pub signature: HandlesManager<Signature>,
    pub signature_publickey: HandlesManager<SignaturePublicKey>,
    pub signature_verification_state: HandlesManager<ExclusiveSignatureVerificationState>,
    pub array_output: HandlesManager<ArrayOutput>,
    pub mac_state: HandlesManager<MacState>,
}

pub struct CryptoCtx {
    pub(crate) handles: HandleManagers,
}

pub struct WasiCryptoCtx {
    ctx: CryptoCtx,
}

impl CryptoCtx {
    pub fn new() -> Self {
        CryptoCtx {
            handles: HandleManagers {
                array_output: HandlesManager::new(0x00),
                signature_op: HandlesManager::new(0x01),
                signature_keypair_builder: HandlesManager::new(0x02),
                signature_keypair: HandlesManager::new(0x03),
                signature_state: HandlesManager::new(0x04),
                signature: HandlesManager::new(0x05),
                signature_publickey: HandlesManager::new(0x06),
                signature_verification_state: HandlesManager::new(0x07),
		mac_state: HandlesManager::new(0x06),
            },
        }
    }
}

impl WasiCryptoCtx {
    pub fn new() -> Self {
        WasiCryptoCtx {
            ctx: CryptoCtx::new(),
        }
    }
}

#[test]
fn test_signatures() {
    let ctx = CryptoCtx::new();
    let op_handle = ctx.signature_op_open("ECDSA_P256_SHA256").unwrap();
    let kp_builder_handle = ctx.signature_keypair_builder_open(op_handle).unwrap();
    let kp_handle = ctx.signature_keypair_generate(kp_builder_handle).unwrap();
    let state_handle = ctx.signature_state_open(kp_handle).unwrap();
    ctx.signature_state_update(state_handle, b"test").unwrap();
    let signature_handle = ctx.signature_state_sign(state_handle).unwrap();

    let pk_handle = ctx.signature_keypair_publickey(kp_handle).unwrap();

    let verification_state_handle = ctx.signature_verification_state_open(pk_handle).unwrap();
    ctx.signature_verification_state_update(verification_state_handle, b"test")
        .unwrap();
    ctx.signature_verification_state_verify(verification_state_handle, signature_handle)
        .unwrap();

    ctx.signature_op_close(op_handle).unwrap();
    ctx.signature_keypair_builder_close(kp_builder_handle)
        .unwrap();
    ctx.signature_keypair_close(kp_handle).unwrap();
    ctx.signature_state_close(state_handle).unwrap();
    ctx.signature_verification_state_close(verification_state_handle)
        .unwrap();
    ctx.signature_close(signature_handle).unwrap();
}

#[test]
fn test_macs() {
    let ctx = CryptoCtx::new();
    let mac_handle = ctx.mac_open("HMAC-SHA256", b"test", &[]).unwrap();
    ctx.mac_update(mac_handle, b"test").unwrap();
    let mut digest = vec![0; 32];
    let digest_len = ctx.mac_digest(mac_handle, &mut digest).unwrap();
    assert_eq!(digest_len, 32);
    let expected: &[u8] = &[0xad, 0x71, 0x14, 0x8c, 0x79, 0xf2, 0x1a, 0xb9,
			    0xee, 0xc5, 0x1e, 0xa5, 0xc7, 0xdd, 0x2b, 0x66,
			    0x87, 0x92, 0xf7, 0xc0, 0xd3, 0x53, 0x4a, 0xe6,
			    0x6b, 0x22, 0xf7, 0x1c, 0x61, 0x52, 0x3f, 0xb3];
    assert_eq!(digest, expected);
    ctx.mac_verify(mac_handle, expected).unwrap();
    ctx.mac_close(mac_handle).unwrap();
}
