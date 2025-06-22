#[cfg(test)]
mod tests {
    use crate::models::MemoryRegion;
    use crate::parser::{parse_memory, parse_live_process};
    use crossbeam_channel::{unbounded, Receiver};
    use mockall::mock;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

    // Mock system calls for Linux
    #[cfg(target_os = "linux")]
    mock! {
        pub FileSystem {
            fn read_to_string(path: &str) -> std::io::Result<String>;
            fn open(path: &str) -> std::io::Result<File>;
        }
    }

    // Mock system calls for Windows
    #[cfg(target_os = "windows")]
    mock! {
        pub WinApi {
            fn open_process(pid: u32) -> std::io::Result<isize>;
            fn virtual_query_ex(handle: isize, address: *const (), mbi: *mut windows::Win32::System::Memory::MEMORY_BASIC_INFORMATION, size: usize) -> usize;
            fn read_process_memory(handle: isize, address: *const (), buffer: *mut u8, size: usize, bytes_read: *mut usize) -> bool;
        }
    }

    // Mock Mach APIs for macOS
    #[cfg(target_os = "macos")]
    mock! {
        pub MachApi {
            fn task_for_pid(port: mach::port::mach_port_t, pid: mach::vm_types::pid_t, task: *mut mach::port::mach_port_t) -> mach::kern_return::kern_return_t;
            fn mach_vm_region(
                task: mach::port::mach_port_t,
                address: *mut mach::vm_types::mach_vm_address_t,
                size: *mut mach::vm_types::mach_vm_size_t,
                flavor: mach::vm::vm_region_flavor_t,
                info: *mut mach::vm::vm_region_info_t,
                info_cnt: *mut u32,
                object_name: *mut mach::port::mach_port_t
            ) -> mach::kern_return::kern_return_t;
            fn mach_vm_read(
                task: mach::port::mach_port_t,
                address: mach::vm_types::mach_vm_address_t,
                size: mach::vm_types::mach_vm_size_t,
                data: *mut *mut u8,
                data_cnt: *mut usize
            ) -> mach::kern_return::kern_return_t;
        }
    }

    // Helper to create a temporary dump file
    fn create_dump_file(dir: &TempDir, content: &[u8]) -> std::io::Result<std::path::PathBuf> {
        let path = dir.path().join("dump.bin");
        let mut file = File::create(&path)?;
        file.write_all(content)?;
        Ok(path)
    }

    #[test]
    fn test_parse_memory_basic() {
        let dir = TempDir::new().unwrap();
        let data = vec![0x90; 0x2000]; // 8KB of NOPs
        let dump_path = create_dump_file(&dir, &data).unwrap();
        let dump = std::fs::read(&dump_path).unwrap();

        let (tx, rx) = unbounded::<f32>();
        let regions = parse_memory(&dump, false, |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(regions.len(), 2); // 2 pages (0x1000 each)
        assert_eq!(regions[0].base_address, 0x0);
        assert_eq!(regions[0].size, 0x1000);
        assert_eq!(regions[1].base_address, 0x1000);
        assert_eq!(regions[1].size, 0x1000);
        assert_eq!(regions[0].protection, "rwx");
        assert!(regions[0].is_executable);
        assert!(regions[0].is_writable);
        assert_eq!(rx.recv().unwrap(), 50.0); // First page
        assert_eq!(rx.recv().unwrap(), 100.0); // Second page
    }

    #[test]
    fn test_parse_memory_skip_known() {
        let dir = TempDir::new().unwrap();
        let data = vec![0x90; 0x10000]; // 64KB
        let dump_path = create_dump_file(&dir, &data).unwrap();
        let dump = std::fs::read(&dump_path).unwrap();

        let (tx, rx) = unbounded::<f32>();
        let regions = parse_memory(&dump, true, |progress| tx.send(progress).unwrap()).unwrap();

        // Every 10th page skipped
        assert_eq!(regions.len(), 6); // 64KB / 4KB = 16 pages, 2 skipped
        assert_eq!(regions[0].base_address, 0x1000); // First page skipped
        let mut progress_values = vec![];
        while let Ok(progress) = rx.try_recv() {
            progress_values.push(progress);
        }
        assert!(progress_values.contains(&100.0));
    }

    #[test]
    fn test_parse_memory_empty() {
        let (tx, rx) = unbounded::<f32>();
        let regions = parse_memory(&[], false, |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(regions.len(), 0);
        assert!(rx.try_recv().is_err()); // No progress for empty data
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_parse_live_process_linux() {
        let dir = TempDir::new().unwrap();
        let maps_content = r#"
            00400000-00401000 r-xp 00000000 08:01 12345 /bin/test
            00600000-00601000 rw-p 00000000 08:01 12345 /bin/test
            7fff0000-7fff1000 rw-p 00000000 00:00 0 [heap]
        "#;
        let mem_content = vec![0xCC; 0x1000]; // 4KB of INT3
        let maps_path = dir.path().join("maps");
        let mem_path = dir.path().join("mem");
        File::create(&maps_path).unwrap().write_all(maps_content.as_bytes()).unwrap();
        File::create(&mem_path).unwrap().write_all(&mem_content).unwrap();

        let mut mock_fs = MockFileSystem::new();
        mock_fs
            .expect_read_to_string()
            .withf(|path| path == "/proc/1234/maps")
            .return_once(move |_| Ok(maps_content.to_string()));
        mock_fs
            .expect_open()
            .withf(|path| path == "/proc/1234/mem")
            .return_once(move |_| File::open(&mem_path));

        let (tx, rx) = unbounded::<f32>();
        let regions = parse_live_process(1234, |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(regions.len(), 3);
        assert_eq!(regions[0].base_address, 0x00400000);
        assert_eq!(regions[0].size, 0x1000);
        assert_eq!(regions[0].protection, "r-x");
        assert!(regions[0].is_executable);
        assert!(!regions[0].is_writable);
        assert_eq!(regions[2].base_address, 0x7fff0000);
        assert_eq!(regions[2].protection, "rw-");
        assert!(!regions[2].is_executable);
        assert!(regions[2].is_writable);
        let mut progress_values = vec![];
        while let Ok(progress) = rx.try_recv() {
            progress_values.push(progress);
        }
        assert!(progress_values.contains(&100.0));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_parse_live_process_windows() {
        use windows::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE, MEM_COMMIT};

        let mut mock_winapi = MockWinApi::new();
        mock_winapi
            .expect_open_process()
            .return_once(|_| Ok(1));
        mock_winapi
            .expect_virtual_query_ex()
            .times(3) // First pass + second pass + end
            .returning(|_, _, mbi, _| {
                unsafe {
                    *mbi = MEMORY_BASIC_INFORMATION {
                        BaseAddress: 0x1000 as _,
                        RegionSize: 0x2000,
                        Protect: PAGE_EXECUTE_READWRITE,
                        State: MEM_COMMIT,
                        ..Default::default()
                    };
                }
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>()
            })
            .returning(|_, _, _, _| 0); // End of regions
        mock_winapi
            .expect_read_process_memory()
            .return_once(|_, _, buffer, size, bytes_read| {
                unsafe {
                    std::ptr::write_bytes(buffer, 0x90, size);
                    *bytes_read = size;
                }
                true
            });

        let (tx, rx) = unbounded::<f32>();
        let regions = parse_live_process(1234, |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].base_address, 0x1000);
        assert_eq!(regions[0].size, 0x2000);
        assert_eq!(regions[0].protection, "rwx");
        assert!(regions[0].is_executable);
        assert!(regions[0].is_writable);
        assert_eq!(rx.recv().unwrap(), 100.0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_live_process_macos_basic() {
        use mach::kern_return::KERN_SUCCESS;
        use mach::vm::vm_region_basic_info_64;

        let mut mock_mach = MockMachApi::new();
        mock_mach
            .expect_task_for_pid()
            .withf(|_, pid, _| pid == 1234)
            .return_once(|_, _, task| {
                unsafe { *task = 1 }; // Valid task port
                KERN_SUCCESS
            });
        mock_mach
            .expect_mach_vm_region()
            .times(3) // First pass + second pass + end
            .returning(|_, address, size, _, info, info_cnt, _| {
                unsafe {
                    *address = 0x1000;
                    *size = 0x2000;
                    let info_ptr = info as *mut vm_region_basic_info_64;
                    (*info_ptr).protection = mach::vm::vm_prot_t::VM_PROT_READ | mach::vm::vm_prot_t::VM_PROT_EXECUTE;
                    *info_cnt = std::mem::size_of::<vm_region_basic_info_64>() as u32;
                }
                KERN_SUCCESS
            })
            .returning(|_, _, _, _, _, _, _| mach::kern_return::KERN_FAILURE); // End of regions
        mock_mach
            .expect_mach_vm_read()
            .return_once(|_, _, size, data, data_cnt| {
                unsafe {
                    *data = Box::into_raw(Box::new(vec![0x90; size as usize])) as *mut u8;
                    *data_cnt = size as usize;
                }
                KERN_SUCCESS
            });

        let (tx, rx) = unbounded::<f32>();
        let regions = parse_live_process(1234, |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].base_address, 0x1000);
        assert_eq!(regions[0].size, 0x2000);
        assert_eq!(regions[0].protection, "r-x");
        assert!(regions[0].is_executable);
        assert!(!regions[0].is_writable);
        assert_eq!(regions[0].data, vec![0x90; 0x2000]);
        assert_eq!(rx.recv().unwrap(), 100.0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_live_process_macos_invalid_task() {
        let mut mock_mach = MockMachApi::new();
        mock_mach
            .expect_task_for_pid()
            .return_once(|_, _, _| mach::kern_return::KERN_FAILURE);

        let (tx, rx) = unbounded::<f32>();
        let result = parse_live_process(1234, |progress| tx.send(progress).unwrap());

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Failed to get task port"
        );
        assert!(rx.try_recv().is_err()); // No progress
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_live_process_macos_read_failure() {
        use mach::kern_return::KERN_SUCCESS;

        let mut mock_mach = MockMachApi::new();
        mock_mach
            .expect_task_for_pid()
            .return_once(|_, _, task| {
                unsafe { *task = 1 };
                KERN_SUCCESS
            });
        mock_mach
            .expect_mach_vm_region()
            .times(3)
            .returning(|_, address, size, _, info, info_cnt, _| {
                unsafe {
                    *address = 0x1000;
                    *size = 0x2000;
                    let info_ptr = info as *mut mach::vm::vm_region_basic_info_64;
                    (*info_ptr).protection = mach::vm::vm_prot_t::VM_PROT_READ | mach::vm::vm_prot_t::VM_PROT_WRITE;
                    *info_cnt = std::mem::size_of::<vm_region_basic_info_64>() as u32;
                }
                KERN_SUCCESS
            })
            .returning(|_, _, _, _, _, _, _| mach::kern_return::KERN_FAILURE);
        mock_mach
            .expect_mach_vm_read()
            .return_once(|_, _, _, _, _| mach::kern_return::KERN_FAILURE);

        let (tx, rx) = unbounded::<f32>();
        let regions = parse_live_process(1234, |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(regions.len(), 0); // No regions due to read failure
        assert_eq!(rx.recv().unwrap(), 100.0); // Progress still completes
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_live_process_macos_multiple_regions() {
        use mach::kern_return::KERN_SUCCESS;

        let mut mock_mach = MockMachApi::new();
        mock_mach
            .expect_task_for_pid()
            .return_once(|_, _, task| {
                unsafe { *task = 1 };
                KERN_SUCCESS
            });
        mock_mach
            .expect_mach_vm_region()
            .times(5) // 2 regions + end in first pass, 2 in second pass
            .returning(|_, address, size, _, info, info_cnt, _| {
                let addr = unsafe { *address };
                if addr == 0 {
                    unsafe {
                        *address = 0x1000;
                        *size = 0x2000;
                        let info_ptr = info as *mut mach::vm::vm_region_basic_info_64;
                        (*info_ptr).protection = mach::vm::vm_prot_t::VM_PROT_READ | mach::vm::vm_prot_t::VM_PROT_EXECUTE;
                        *info_cnt = std::mem::size_of::<vm_region_basic_info_64>() as u32;
                    }
                    KERN_SUCCESS
                } else if addr == 0x1000 {
                    unsafe {
                        *address = 0x3000;
                        *size = 0x1000;
                        let info_ptr = info as *mut mach::vm::vm_region_basic_info_64;
                        (*info_ptr).protection = mach::vm::vm_prot_t::VM_PROT_READ | mach::vm::vm_prot_t::VM_PROT_WRITE;
                        *info_cnt = std::mem::size_of::<vm_region_basic_info_64>() as u32;
                    }
                    KERN_SUCCESS
                } else {
                    mach::kern_return::KERN_FAILURE
                }
            });
        mock_mach
            .expect_mach_vm_read()
            .times(2)
            .returning(|_, address, size, data, data_cnt| {
                let mock_data = if address == 0x1000 {
                    vec![0xE8, 0x00, 0x00, 0x00, 0x00] // call 0 (GetPC)
                } else {
                    vec![0xCC; size as usize] // INT3
                };
                unsafe {
                    *data = Box::into_raw(Box::new(mock_data)) as *mut u8;
                    *data_cnt = size as usize;
                }
                KERN_SUCCESS
            });

        let (tx, rx) = unbounded::<f32>();
        let regions = parse_live_process(1234, |progress| tx.send(progress).unwrap()).unwrap();

        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].base_address, 0x1000);
        assert_eq!(regions[0].size, 0x2000);
        assert_eq!(regions[0].protection, "r-x");
        assert!(regions[0].is_executable);
        assert!(!regions[0].is_writable);
        assert_eq!(regions[0].data[0..5], [0xE8, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(regions[1].base_address, 0x3000);
        assert_eq!(regions[1].size, 0x1000);
        assert_eq!(regions[1].protection, "rw-");
        assert!(!regions[1].is_executable);
        assert!(regions[1].is_writable);
        let mut progress_values = vec![];
        while let Ok(progress) = rx.try_recv() {
            progress_values.push(progress);
        }
        assert_eq!(progress_values, vec![50.0, 100.0]); // 2 regions
    }
}