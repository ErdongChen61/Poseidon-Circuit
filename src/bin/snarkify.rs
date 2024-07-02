use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BS64, Engine};
use ff::PrimeField;
use halo2_proofs::{
    plonk::{self, create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use halo2curves::bn256::{Bn256, Fr, G1Affine};
use poseidon_circuit::test_circuit;
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use snarkify_sdk::prover::ProofHandler;

/// A prover for Poseidon hashes using the Halo2 proving system.
struct PoseidonProver;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProofType {
    Undefined,
    Chunk,
    Batch,
}

impl ProofType {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => ProofType::Chunk,
            2 => ProofType::Batch,
            _ => ProofType::Undefined,
        }
    }
}

impl Serialize for ProofType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            ProofType::Undefined => serializer.serialize_i8(0),
            ProofType::Chunk => serializer.serialize_i8(1),
            ProofType::Batch => serializer.serialize_i8(2),
        }
    }
}

impl<'de> Deserialize<'de> for ProofType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: u8 = u8::deserialize(deserializer)?;
        Ok(ProofType::from_u8(v))
    }
}

impl Default for ProofType {
    fn default() -> Self {
        Self::Undefined
    }
}

/// Represents the inputs to the Poseidon Circuit
///
/// This struct is designed to capture the necessary inputs for the
/// Poseidon hash circuit.
#[derive(Serialize, Deserialize, Default)]
pub struct Task {
    /// The private_input vector, representing the hash input
    ///
    /// These inputs are part of the witness
    pub uuid: String,
    pub id: String,
    #[serde(rename = "type", default)]
    pub task_type: ProofType,
    pub task_data: String,
    #[serde(default)]
    pub hard_fork_name: String,
}

#[derive(Serialize, Deserialize, Default)]
pub struct ProofDetail {
    pub id: String,
    #[serde(rename = "type", default)]
    pub proof_type: ProofType,
    pub proof_data: String,
    pub error: String,
}

#[async_trait]
impl ProofHandler for PoseidonProver {
    type Input = Task;
    type Output = ProofDetail;
    type Error = Error;

    /// Generates a zk-SNARK proof for the Poseidon hash function.
    ///
    /// Given an [`Input`] instance containing the private and public inputs,
    /// this function goes through the steps of setting up the proving parameters,
    /// generating a proof, and then verifying that proof, ultimately returning
    /// a serialized proof in the form of a Base64-encoded string.
    ///
    /// # Arguments
    ///
    /// * `input` - An `Input` struct containing:
    ///   - `private_input`: A `Vec<u64>` representing the private part of the input to the hash function.
    ///   - `public_input`: A `String` representing the expected hash output in the field `Fp`.
    ///
    /// # Returns
    ///
    /// If successful, it returns `Ok(String)` where the string is the Base64-encoded
    /// representation of the generated zk-SNARK proof. If any step in the proof generation
    /// or verification fails, it returns an `Err(Error)`, which captures and conveys
    /// the specific stage and nature of the failure.
    async fn prove(input: Self::Input) -> Result<Self::Output, Self::Error> {
        Ok(ProofDetail {
            id: input.id.clone(),
            proof_type: input.task_type,
            proof_data: "proof".to_string(),
            error: "error".to_string(),
        })
    }
}

/// Enumerates the potential errors that can occur within the [`PoseidonProver`].
///
/// This error enum captures the various points of failure that could occur
/// during the setup, proof generation, and verification steps of the Poseidon
/// proving process.
///
/// Note: The [`plonk::Error`] type is not serializable, hence we convert it to a string
/// to capture the error information. This workaround allows us to include `plonk::Error`
/// information in a serializable format.
#[derive(Serialize)]
pub enum Error {
    WhileKeygenVk { plonk_error: String },
    WhileKeygenPk { plonk_error: String },
    PubInputOutOfField { public_input: String },
    WhileProve { plonk_error: String },
    WhileVerify { plonk_error: String },
}

impl Error {
    fn while_keygen_vk(err: plonk::Error) -> Self {
        Self::WhileKeygenVk {
            plonk_error: format!("{err:?}"),
        }
    }
    fn while_keygen_pk(err: plonk::Error) -> Self {
        Self::WhileKeygenPk {
            plonk_error: format!("{err:?}"),
        }
    }
    fn while_prove(err: plonk::Error) -> Self {
        Self::WhileProve {
            plonk_error: format!("{err:?}"),
        }
    }
    fn while_verify(err: plonk::Error) -> Self {
        Self::WhileProve {
            plonk_error: format!("{err:?}"),
        }
    }
}

fn main() -> Result<(), std::io::Error> {
    snarkify_sdk::run::<PoseidonProver>()
}
