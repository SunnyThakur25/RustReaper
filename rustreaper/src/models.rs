use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base_address: u64,
    pub size: u64,
    pub protection: String,
    pub data: Vec<u8>,
    pub is_executable: bool,
    pub is_writable: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum ArtifactType {
    Hook,
    IndirectHook,
    EncryptedPayload,
    Shellcode,
    InjectedPE,
    SuspiciousString,
    ApiHook,
    IatHook,
    UnusualSection,
    YaraMatch(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Artifact {
    pub address: u64,
    pub artifact_type: ArtifactType,
    pub description: String,
    pub confidence: f32,
    pub entropy: Option<f64>,
    pub context: Option<Vec<u8>>,
}