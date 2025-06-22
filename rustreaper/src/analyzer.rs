use capstone::prelude::*;
use crossbeam_channel::Sender;
use log::{debug, error, info, warn};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use statrs::statistics::{Data, Distribution};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::Path;
use yara::Compiler;

use crate::models::{Artifact, ArtifactType, MemoryRegion};

#[derive(Debug)]
pub enum AnalysisError {
    DisassemblyError(String),
    PatternMatchError(String),
    EntropyCalculationError(String),
    YaraError(yara::Error),
}

impl fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AnalysisError::DisassemblyError(e) => write!(f, "Disassembly error: {}", e),
            AnalysisError::PatternMatchError(e) => write!(f, "Pattern match error: {}", e),
            AnalysisError::EntropyCalculationError(e) => write!(f, "Entropy calculation error: {}", e),
            AnalysisError::YaraError(e) => write!(f, "YARA error: {}", e),
        }
    }
}

impl std::error::Error for AnalysisError {}

impl From<yara::Error> for AnalysisError {
    fn from(err: yara::Error) -> Self {
        AnalysisError::YaraError(err)
    }
}

pub struct MemoryAnalyzer {
    cs: Capstone,
    yara_rules: Option<yara::Rules>,
    known_hashes: HashSet<Vec<u8>>,
    api_hashes: HashMap<u32, String>,
    iat_threshold: f32,
}

impl MemoryAnalyzer {
    pub fn new_with_rules(rules_path: &Path) -> Result<Self, AnalysisError> {
        let cs = Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Intel)
            .detail(true)
            .build()
            .map_err(|e| AnalysisError::DisassemblyError(e.to_string()))?;

        let yara_rules = Self::load_yara_rules(rules_path)?;
        let known_hashes = Self::load_known_hashes();
        let api_hashes = Self::load_api_hashes();

        Ok(Self {
            cs,
            yara_rules,
            known_hashes,
            api_hashes,
            iat_threshold: 0.7,
        })
    }

    fn load_yara_rules(path: &Path) -> Result<Option<yara::Rules>, AnalysisError> {
        let rules = fs::read_to_string(path)
            .map_err(|e| AnalysisError::YaraError(yara::Error::from(e)))?;
        let mut compiler = Compiler::new()?;
        compiler.add_rules_str(&rules)?;
        Ok(Some(compiler.compile_rules()?))
    }

    fn load_known_hashes() -> HashSet<Vec<u8>> {
        HashSet::new()
    }

    fn load_api_hashes() -> HashMap<u32, String> {
        let mut apis = HashMap::new();
        apis.insert(0x6D4F325A, "CreateProcessA");
        apis.insert(0x7C0017A5, "VirtualAlloc");
        apis.insert(0x91AFCA54, "WriteProcessMemory");
        apis
    }

    pub fn analyze<F>(&self, regions: &[MemoryRegion], progress_callback: F) -> Result<Vec<Artifact>, AnalysisError>
    where
        F: Fn(f32) + Sync,
    {
        info!("Starting deep analysis of {} memory regions", regions.len());
        self.analyze_internal(regions, progress_callback, true, true)
    }

    pub fn analyze_quick<F>(&self, regions: &[MemoryRegion], progress_callback: F) -> Result<Vec<Artifact>, AnalysisError>
    where
        F: Fn(f32) + Sync,
    {
        info!("Starting quick analysis of {} memory regions", regions.len());
        self.analyze_internal(regions, progress_callback, false, false)
    }

    pub fn analyze_stealth<F>(&self, regions: &[MemoryRegion], progress_callback: F) -> Result<Vec<Artifact>, AnalysisError>
    where
        F: Fn(f32) + Sync,
    {
        info!("Starting stealth analysis of {} memory regions", regions.len());
        self.analyze_internal(regions, progress_callback, true, false)
    }

    fn analyze_internal<F>(
        &self,
        regions: &[MemoryRegion],
        progress_callback: F,
        use_yara: bool,
        use_entropy: bool,
    ) -> Result<Vec<Artifact>, AnalysisError>
    where
        F: Fn(f32) + Sync,
    {
        let total_regions = regions.len();
        let processed = std::sync::atomic::AtomicUsize::new(0);

        let artifacts: Vec<Artifact> = regions
            .par_iter()
            .flat_map(|region| {
                let mut artifacts = Vec::new();

                if region.is_executable {
                    if let Ok(mut exec_artifacts) = self.analyze_executable_region(region) {
                        artifacts.append(&mut exec_artifacts);
                    }
                }

                if region.is_writable {
                    if let Ok(mut writable_artifacts) = self.analyze_writable_region(region, use_entropy) {
                        artifacts.append(&mut writable_artifacts);
                    }
                }

                if use_yara {
                    if let Ok(mut general_artifacts) = self.analyze_general_region(region) {
                        artifacts.append(&mut general_artifacts);
                    }
                }

                let count = processed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let progress = (count + 1) as f32 / total_regions as f32 * 100.0;
                progress_callback(progress);

                artifacts
            })
            .collect();

        info!("Analysis completed, found {} artifacts", artifacts.len());
        Ok(artifacts)
    }

    fn analyze_executable_region(&self, region: &MemoryRegion) -> Result<Vec<Artifact>, AnalysisError> {
        let mut artifacts = Vec::new();
        let instructions = self.cs.disasm_all(&region.data, region.base_address)
            .map_err(|e| AnalysisError::DisassemblyError(e.to_string()))?;

        artifacts.extend(self.detect_hooks(&instructions, region)?);
        artifacts.extend(self.detect_shellcode(&instructions, region)?);
        artifacts.extend(self.detect_api_hashing(&instructions, region)?);

        Ok(artifacts)
    }

    fn analyze_writable_region(&self, region: &MemoryRegion, use_entropy: bool) -> Result<Vec<Artifact>, AnalysisError> {
        let mut artifacts = Vec::new();

        if self.detect_pe_header(&region.data) {
            artifacts.push(Artifact {
                address: region.base_address,
                artifact_type: ArtifactType::InjectedPE,
                description: "PE header found in writable memory".to_string(),
                confidence: 0.85,
                entropy: None,
                context: Some(region.data[..64.min(region.data.len())].to_vec()),
            });
        }

        if use_entropy {
            let entropy = calculate_entropy(&region.data)?;
            if entropy > 7.2 {
                artifacts.push(Artifact {
                    address: region.base_address,
                    artifact_type: ArtifactType::EncryptedPayload,
                    description: format!("High entropy region ({:.2} bits)", entropy),
                    confidence: 0.9 - (0.1 * (8.0 - entropy as f32)),
                    entropy: Some(entropy),
                    context: None,
                });
            }
        }

        Ok(artifacts)
    }

    fn analyze_general_region(&self, region: &MemoryRegion) -> Result<Vec<Artifact>, AnalysisError> {
        let mut artifacts = Vec::new();

        if let Some(rules) = &self.yara_rules {
            let matches = rules.scan_mem(&region.data, 10)
                .map_err(|e| AnalysisError::YaraError(e))?;

            for m in matches {
                artifacts.push(Artifact {
                    address: region.base_address + m.offset as u64,
                    artifact_type: ArtifactType::YaraMatch(m.rule.identifier.to_string()),
                    description: format!("YARA rule match: {}", m.rule.identifier),
                    confidence: 0.8,
                    entropy: None,
                    context: Some(region.data[m.offset..(m.offset + 64).min(region.data.len())].to_vec()),
                });
            }
        }

        artifacts.extend(self.detect_suspicious_strings(region)?);
        Ok(artifacts)
    }

    fn detect_hooks(&self, instructions: &Instructions, region: &MemoryRegion) -> Result<Vec<Artifact>, AnalysisError> {
        let mut artifacts = Vec::new();
        let mut prev_instruction: Option<(u64, &str)> = None;

        for insn in instructions.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            let op_str = insn.op_str().unwrap_or("");

            if mnemonic == "jmp" || mnemonic == "call" {
                if let Some(target) = Self::parse_jump_target(op_str) {
                    if !region.contains_address(target) {
                        artifacts.push(Artifact {
                            address: insn.address(),
                            artifact_type: ArtifactType::Hook,
                            description: format!("{} to 0x{:x} outside current region", mnemonic, target),
                            confidence: 0.9,
                            entropy: None,
                            context: Some(insn.bytes().to_vec()),
                        });
                    }
                }
            }

            if (mnemonic == "jmp" || mnemonic == "call") && op_str.starts_with('[') {
                artifacts.push(Artifact {
                    address: insn.address(),
                    artifact_type: ArtifactType::IndirectHook,
                    description: format!("Indirect {} {}", mnemonic, op_str),
                    confidence: 0.85,
                    entropy: None,
                    context: Some(insn.bytes().to_vec()),
                });
            }

            if let Some((prev_addr, prev_mnemonic)) = prev_instruction {
                if prev_mnemonic == "push" && mnemonic == "ret" {
                    artifacts.push(Artifact {
                        address: prev_addr,
                        artifact_type: ArtifactType::Hook,
                        description: "Push/ret trampoline detected".to_string(),
                        confidence: 0.95,
                        entropy: None,
                        context: Some(
                            [instructions.iter().find(|i| i.address() == prev_addr)
                                .map(|i| i.bytes())
                                .unwrap_or(&[]), insn.bytes()]
                            .concat(),
                        ),
                    });
                }
            }

            prev_instruction = Some((insn.address(), mnemonic));
        }

        Ok(artifacts)
    }

    fn detect_shellcode(&self, instructions: &Instructions, region: &MemoryRegion) -> Result<Vec<Artifact>, AnalysisError> {
        let mut artifacts = Vec::new();
        let mut syscall_count = 0;
        let mut xor_count = 0;
        let mut getpc_count = 0;

        for insn in instructions.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            let bytes = insn.bytes();

            if mnemonic == "syscall" || mnemonic == "int" {
                syscall_count += 1;
            } else if mnemonic == "xor" {
                xor_count += 1;
            } else if bytes.len() >= 5 && bytes[0] == 0xE8 && bytes[1..5] == [0x00, 0x00, 0x00, 0x00] {
                getpc_count += 1;
            }
        }

        if syscall_count > 3 {
            artifacts.push(Artifact {
                address: region.base_address,
                artifact_type: ArtifactType::Shellcode,
                description: format!("Multiple syscall/int instructions ({})", syscall_count),
                confidence: 0.8,
                entropy: None,
                context: None,
            });
        }

        if xor_count > 5 {
            artifacts.push(Artifact {
                address: region.base_address,
                artifact_type: ArtifactType::Shellcode,
                description: format!("Multiple XOR instructions ({})", xor_count),
                confidence: 0.75,
                entropy: None,
                context: None,
            });
        }

        if getpc_count > 0 {
            artifacts.push(Artifact {
                address: region.base_address,
                artifact_type: ArtifactType::Shellcode,
                description: "GetPC code detected".to_string(),
                confidence: 0.9,
                entropy: None,
                context: None,
            });
        }

        Ok(artifacts)
    }

    fn detect_api_hashing(&self, instructions: &Instructions, region: &MemoryRegion) -> Result<Vec<Artifact>, AnalysisError> {
        let mut artifacts = Vec::new();
        let mut hash_candidates = Vec::new();

        for insn in instructions.iter() {
            let mnemonic = insn.mnemonic().unwrap_or("");
            let op_str = insn.op_str().unwrap_or("");

            if mnemonic == "xor" && op_str.contains("0x") {
                if let Some(imm) = Self::parse_immediate(op_str) {
                    hash_candidates.push(imm);
                }
            }

            if (mnemonic == "ror" || mnemonic == "rol") && op_str.contains("0x") {
                if let Some(imm) = Self::parse_immediate(op_str) {
                    hash_candidates.push(imm);
                }
            }
        }

        for &hash in &hash_candidates {
            if let Some(api_name) = self.api_hashes.get(&hash) {
                artifacts.push(Artifact {
                    address: region.base_address,
                    artifact_type: ArtifactType::Shellcode,
                    description: format!("API hash detected for {}", api_name),
                    confidence: 0.85,
                    entropy: None,
                    context: None,
                });
            }
        }

        Ok(artifacts)
    }

    fn detect_pe_header(&self, data: &[u8]) -> bool {
        if data.len() >= 0x40 && &data[0..2] == b"MZ" {
            let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
            if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset+4] == b"PE\0\0" {
                return true;
            }
        }
        false
    }

    fn detect_suspicious_strings(&self, region: &MemoryRegion) -> Result<Vec<Artifact>, AnalysisError> {
        let mut artifacts = Vec::new();
        let suspicious_patterns = [
            (b"http://", "HTTP URL"),
            (b"https://", "HTTPS URL"),
            (b"cmd.exe", "Command prompt"),
            (b"powershell", "PowerShell"),
            (b"CreateRemoteThread", "Process injection API"),
            (b"VirtualAlloc", "Memory allocation API"),
        ];

        for (pattern, desc) in &suspicious_patterns {
            if let Some(pos) = memchr::memmem::find(&region.data, pattern) {
                artifacts.push(Artifact {
                    address: region.base_address + pos as u64,
                    artifact_type: ArtifactType::SuspiciousString,
                    description: format!("Suspicious string: {}", desc),
                    confidence: 0.7,
                    entropy: None,
                    context: Some(
                        region.data[pos..(pos + 64).min(region.data.len())].to_vec()
                    ),
                });
            }
        }

        Ok(artifacts)
    }

    fn parse_jump_target(op_str: &str) -> Option<u64> {
        if op_str.starts_with("0x") {
            u64::from_str_radix(&op_str[2..], 16).ok()
        } else {
            None
        }
    }

    fn parse_immediate(op_str: &str) -> Option<u32> {
        if let Some(imm_str) = op_str.split(',').last() {
            if imm_str.trim().starts_with("0x") {
                return u32::from_str_radix(&imm_str.trim()[2..], 16).ok();
            }
        }
        None
    }
}

fn calculate_entropy(data: &[u8]) -> Result<f64, AnalysisError> {
    if data.is_empty() {
        return Err(AnalysisError::EntropyCalculationError("Empty data".to_string()));
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let probabilities: Vec<f64> = counts
        .iter()
        .map(|&c| c as f64 / data.len() as f64)
        .filter(|&p| p > 0.0)
        .collect();

    if probabilities.is_empty() {
        return Ok(0.0);
    }

    Ok(-Data::new(probabilities).entropy().unwrap_or(0.0))
}

impl MemoryRegion {
    pub fn contains_address(&self, address: u64) -> bool {
        address >= self.base_address && address < self.base_address + self.size
    }
}