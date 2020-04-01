use ring::hmac;
use ring::constant_time::verify_slices_are_equal;
use super::error::*;
use super::handles::*;
use super::types as guest_types;
use super::{CryptoCtx, WasiCryptoCtx};

#[derive(Clone)]
pub enum MacState {
    HMAC(hmac::Context),
}

impl CryptoCtx {
    pub fn mac_open(
        &self,
	algorithm: &str,
        key: &[u8],
	_options: Handle,
    ) -> Result<Handle, CryptoError> {
	let mac_state = match algorithm {
	    "HMAC-SHA256" => {
		MacState::HMAC(
		    hmac::Context::with_key(
			&hmac::Key::new(hmac::HMAC_SHA256, key.as_ref())))
	    },
            _ => bail!(CryptoError::UnsupportedAlgorithm),
	};
        let handle = self.handles.mac_state.register(mac_state)?;
        Ok(handle)
    }

    pub fn mac_close(
	&self,
	handle: Handle
    ) -> Result<(), CryptoError> {
        self.handles.mac_state.close(handle)
    }

    pub fn mac_update(
	&self,
	handle: Handle,
	data: &[u8],
    ) -> Result<(), CryptoError> {
	let handle = self.handles.mac_state.get(handle)?;
	match handle {
	    MacState::HMAC(mut context) => context.update(data),
	};
	Ok(())
    }

    pub fn mac_digest(
	&self,
	handle: Handle,
	digest: &mut [u8],
    ) -> Result<u32, CryptoError> {
	let handle = self.handles.mac_state.get(handle)?;
	let tag = match handle {
	    MacState::HMAC(context) => context.sign(),
	};
	let bytes = tag.as_ref();
	let limit = std::cmp::min(bytes.len(), digest.len());
	digest[..limit].copy_from_slice(&bytes[..limit]);
	Ok(limit as u32)
    }

    pub fn mac_verify(
	&self,
	handle: Handle,
	digest: &[u8],
    ) -> Result<(), CryptoError> {
	let handle = self.handles.mac_state.get(handle)?;
	match handle {
	    MacState::HMAC(context) => {
		let tag = context.sign();
		verify_slices_are_equal(tag.as_ref(), digest)
		    .map_err(|_| CryptoError::AlgorithmFailure)
	    },
	}
    }
}

impl WasiCryptoCtx {
    pub fn mac_open(
        &self,
	algorithm: &wiggle::GuestPtr<'_, str>,
        key_ptr: &wiggle::GuestPtr<'_, u8>,
	key_len: guest_types::Size,
	options: guest_types::Options,
    ) -> Result<guest_types::MacState, CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
        let algorithm: &str = unsafe {
	    &*algorithm.as_raw(&mut guest_borrow)?
	};
	let key: &[u8] = unsafe {
	    &*key_ptr
		.as_array(key_len as _)
		.as_raw(&mut guest_borrow)?
	};
        Ok(self
           .ctx
           .mac_open(algorithm, key, options.into())?
           .into())
    }

    pub fn mac_close(
        &self,
        handle: guest_types::MacState,
    ) -> Result<(), CryptoError> {
        self.ctx.mac_close(handle.into())
    }

    pub fn mac_update(
	&self,
        handle: guest_types::MacState,
	data_ptr: &wiggle::GuestPtr<'_, u8>,
	data_len: guest_types::Size,
    ) -> Result<(), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
	let data: &[u8] = unsafe {
	    &*data_ptr
		.as_array(data_len as _)
		.as_raw(&mut guest_borrow)?
	};
	self.ctx.mac_update(handle.into(), data)
    }

    pub fn mac_digest(
	&self,
	handle: guest_types::MacState,
	digest_ptr: &wiggle::GuestPtr<'_, u8>,
	max_digest_len: guest_types::Size,
    ) -> Result<u32, CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
	let digest: &mut [u8] = unsafe {
	    &mut *digest_ptr
		.as_array(max_digest_len as _)
		.as_raw(&mut guest_borrow)?
	};
	self.ctx.mac_digest(handle.into(), digest)
    }

    pub fn mac_verify(
	&self,
	handle: guest_types::MacState,
	digest_ptr: &wiggle::GuestPtr<'_, u8>,
	digest_len: guest_types::Size,
    ) -> Result<(), CryptoError> {
        let mut guest_borrow = wiggle::GuestBorrows::new();
	let digest: &[u8] = unsafe {
	    &*digest_ptr
		.as_array(digest_len as _)
		.as_raw(&mut guest_borrow)?
	};
	self.ctx.mac_verify(handle.into(), digest)
    }
}
