//! Parameters generated by a random oracle.

use core::iter::once;

use alloc::vec::Vec;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::*;
use serde_with::serde_as;
use utils::{
    affine_group_element_from_byte_slices, concat_slices, misc::n_affine_group_elements,
    serde_utils::ArkObjectBytes,
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use utils::join;

/// Parameters generated by a random oracle.
#[serde_as]
#[derive(
    Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize,
)]
pub struct SignatureParams<E: Pairing> {
    #[serde_as(as = "ArkObjectBytes")]
    pub g: E::G1Affine,
    #[serde_as(as = "ArkObjectBytes")]
    pub g_tilde: E::G2Affine,
    #[serde_as(as = "Vec<ArkObjectBytes>")]
    pub h: Vec<E::G1Affine>,
}

impl<E: Pairing> SignatureParams<E> {
    /// Generates `g`, `g_tilde` and `h`. These params are shared between signer and all users.
    pub fn new<D: digest::Digest>(label: &[u8], message_count: u32) -> Self {
        let (g, g_tilde, h) = join!(
            affine_group_element_from_byte_slices!(label, b" : g"),
            affine_group_element_from_byte_slices!(label, b" : g_tilde"),
            n_affine_group_elements::<_, D>(0..message_count, &concat_slices!(label, b" : h_"))
                .collect()
        );

        Self { g, g_tilde, h }
    }

    /// Returns max amount of messages supported by this params.
    pub fn supported_message_count(&self) -> usize {
        self.h.len()
    }

    /// Returns `true` if underlying params are valid i.e don't have zero elements.
    pub fn valid(&self) -> bool {
        !once(&self.g).chain(&self.h).any(AffineRepr::is_zero) && !self.g_tilde.is_zero()
    }
}

pub type PreparedSignatureParams<E> = SignatureParams<E>;
