#[cfg(test)]
mod tests {
    use crate::analyzer::{MemoryAnalyzer, AnalysisError};
    use crate::models::{MemoryRegion, Artifact, ArtifactType};
    use crossbeam_channel::{unbounded, Receiver};
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

    // Helper to create a mock MemoryRegion
    fn create_mock_region(data: Vec<u8>, base_address: u64, executable: bool, writable: bool) -> MemoryRegion {
        MemoryRegion {
            base_address,
            size: data.len() as u64,
            protection: if executable && writable { "rwx".to_string() } else if executable { "r-x".to_string() } else { "rw-".to_string() },
            data,
            is_executable: executable,
            is_writable: writable,
        }
    }

    // Helper to create a temporary YARA rules file
    fn create_yara_rules_file(dir: &TempDir, content: &str) -> std::io::Result<std::path::PathBuf> {
        let path = dir.path().join("test_rules.yara");
        let mut file = File::create(&path)?;
        file.write_all(content.as_bytes())?;
        Ok(path)
    }

    #[test]
    fn test_new_with_rules_valid() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, r#"
            rule test_rule {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#).unwrap();

        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path);
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_new_with_rules_invalid() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, r#"
            rule invalid_rule {
                strings:
                    $a = "test
                condition:
                    $a
            }
        "#).unwrap();

        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path);
        assert!(analyzer.is_err());
    }

    #[test]
    fn test_analyze_hook_detection() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, "").unwrap();
        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path).unwrap();

        // Mock JMP instruction to external address
        let data = vec![
            0xE9, 0x00, 0x00, 0x00, 0x00, // jmp 0x0
        ];
        let region = create_mock_region(data, 0x1000, true, false);
        let (tx, rx) = unbounded::<f32>();
        let artifacts = analyzer.analyze(&[region], |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_type, ArtifactType::Hook);
        assert_eq!(artifacts[0].address, 0x1000);
        assert!(rx.recv().unwrap() > 0.0); // Progress callback invoked
    }

    #[test]
    fn test_analyze_shellcode_detection() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, "").unwrap();
        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path).unwrap();

        // Mock shellcode with multiple syscalls
        let data = vec![
            0x0F, 0x05, // syscall
            0x0F, 0x05, // syscall
            0x0F, 0x05, // syscall
            0x0F, 0x05, // syscall
        ];
        let region = create_mock_region(data, 0x2000, true, false);
        let (tx, rx) = unbounded::<f32>();
        let artifacts = analyzer.analyze(&[region], |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_type, ArtifactType::Shellcode);
        assert!(artifacts[0].description.contains("syscall"));
        assert!(rx.recv().unwrap() > 0.0);
    }

    #[test]
    fn test_analyze_yara_match() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, r#"
            rule test_rule {
                strings:
                    $a = "malware"
                condition:
                    $a
            }
        "#).unwrap();
        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path).unwrap();

        let data = b"malware payload".to_vec();
        let region = create_mock_region(data, 0x3000, false, true);
        let (tx, rx) = unbounded::<f32>();
        let artifacts = analyzer.analyze(&[region], |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(artifacts.len(), 1);
        if let ArtifactType::YaraMatch(ref rule) = artifacts[0].artifact_type {
            assert_eq!(rule, "test_rule");
        } else {
            panic!("Expected YaraMatch");
        }
        assert!(rx.recv().unwrap() > 0.0);
    }

    #[test]
    fn test_analyze_high_entropy() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, "").unwrap();
        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path).unwrap();

        // Random data for high entropy
        let data = (0..256).collect::<Vec<u8>>();
        let region = create_mock_region(data, 0x4000, false, true);
        let (tx, rx) = unbounded::<f32>();
        let artifacts = analyzer.analyze(&[region], |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_type, ArtifactType::EncryptedPayload);
        assert!(artifacts[0].entropy.unwrap() > 7.0);
        assert!(rx.recv().unwrap() > 0.0);
    }

    #[test]
    fn test_analyze_quick_mode() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, "").unwrap();
        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path).unwrap();

        let data = b"MZ\x90\x00".to_vec(); // Mock PE header
        let region = create_mock_region(data, 0x5000, false, true);
        let (tx, rx) = unbounded::<f32>();
        let artifacts = analyzer.analyze_quick(&[region], |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(artifacts.len(), 1); // Only PE header detected, no YARA or entropy
        assert_eq!(artifacts[0].artifact_type, ArtifactType::InjectedPE);
        assert!(rx.recv().unwrap() > 0.0);
    }

    #[test]
    fn test_analyze_stealth_mode() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, r#"
            rule test_rule {
                strings:
                    $a = "test"
                condition:
                    $a
            }
        "#).unwrap();
        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path).unwrap();

        let data = b"test".to_vec();
        let region = create_mock_region(data, 0x6000, false, true);
        let (tx, rx) = unbounded::<f32>();
        let artifacts = analyzer.analyze_stealth(&[region], |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(artifacts.len(), 1); // YARA match, no entropy
        assert!(matches!(artifacts[0].artifact_type, ArtifactType::YaraMatch(_)));
        assert!(rx.recv().unwrap() > 0.0);
    }

    #[test]
    fn test_analyze_empty_region() {
        let dir = TempDir::new().unwrap();
        let rules_path = create_yara_rules_file(&dir, "").unwrap();
        let analyzer = MemoryAnalyzer::new_with_rules(&rules_path).unwrap();

        let region = create_mock_region(vec![], 0x7000, true, true);
        let (tx, rx) = unbounded::<f32>();
        let artifacts = analyzer.analyze(&[region], |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(artifacts.len(), 0);
        assert!(rx.recv().unwrap() > 0.0);
    }
}