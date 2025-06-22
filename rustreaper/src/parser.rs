use crate::models::MemoryRegion;
use crossbeam_channel::Sender;
use log::{error, info};
use std::fs::File;
use std::io::{self, Read};
use std::mem::size_of;
use std::ptr;

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "windows")]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
#[cfg(target_os = "windows")]
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
#[cfg(target_os = "windows")]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

#[cfg(target_os = "macos")]
use libc::{c_int, c_void, pid_t};
#[cfg(target_os = "macos")]
use mach::{
    kern_return::kern_return_t,
    port::{mach_port_t, MACH_PORT_NULL},
    vm::{
        mach_vm_deallocate, mach_vm_read, mach_vm_region, vm_region_flavor_t, vm_region_info_t,
        vm_region_basic_info_64, VM_REGION_BASIC_INFO_64,
    },
    vm_types::{mach_vm_address_t, mach_vm_size_t},
};

pub fn parse_memory<F>(data: &[u8], skip_known: bool, progress_callback: F) -> io::Result<Vec<MemoryRegion>>
where
    F: Fn(f32) + Sync,
{
    info!("Parsing memory dump of size: {} bytes", data.len());
    let mut regions = Vec::new();
    let page_size = 0x1000;
    let total_bytes = data.len() as f32;
    let mut processed_bytes = 0.0;

    for i in (0..data.len()).step_by(page_size) {
        let end = std::cmp::min(i + page_size, data.len());
        if skip_known && i % (page_size * 10) == 0 {
            continue;
        }

        regions.push(MemoryRegion {
            base_address: i as u64,
            size: (end - i) as u64,
            protection: "rwx".to_string(),
            data: data[i..end].to_vec(),
            is_executable: true,
            is_writable: true,
        });

        processed_bytes += (end - i) as f32;
        let progress = (processed_bytes / total_bytes) * 100.0;
        progress_callback(progress);
    }

    info!("Parsed {} regions from memory dump", regions.len());
    Ok(regions)
}

pub fn parse_live_process<F>(pid: u32, progress_callback: F) -> io::Result<Vec<MemoryRegion>>
where
    F: Fn(f32) + Sync,
{
    info!("Parsing live process PID: {}", pid);
    let mut regions = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let maps_path = format!("/proc/{}/maps", pid);
        let maps = fs::read_to_string(&maps_path)?;
        let lines: Vec<&str> = maps.lines().collect();
        let total_lines = lines.len() as f32;
        let mut processed_lines = 0.0;

        for line in lines {
            if line.contains("[heap]") || line.contains("r-x") || line.contains("rw-") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(addr_range) = parts.get(0) {
                    let addr_parts: Vec<&str> = addr_range.split('-').collect();
                    if addr_parts.len() == 2 {
                        let start = u64::from_str_radix(addr_parts[0], 16)?;
                        let end = u64::from_str_radix(addr_parts[1], 16)?;
                        let size = end - start;

                        let mut buffer = vec![0u8; size as usize];
                        let mem_path = format!("/proc/{}/mem", pid);
                        let mut file = File::open(&mem_path)?;
                        file.seek(std::io::SeekFrom::Start(start))?;
                        file.read_exact(&mut buffer)?;

                        regions.push(MemoryRegion {
                            base_address: start,
                            size,
                            protection: parts.get(1).unwrap_or(&"rwx").to_string(),
                            data: buffer,
                            is_executable: line.contains("x"),
                            is_writable: line.contains("w"),
                        });
                    }
                }
            }
            processed_lines += 1.0;
            let progress = (processed_lines / total_lines) * 100.0;
            progress_callback(progress);
        }
    }

    #[cfg(target_os = "windows")]
    {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)? };
        let max_address = 0x7FFF_FFFF_FFFF;

        let mut region_count = 0;
        {
            let mut temp_address = 0;
            while temp_address < max_address {
                let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
                let size = unsafe {
                    VirtualQueryEx(
                        handle,
                        temp_address as _,
                        &mut mbi,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                };
                if size == 0 {
                    break;
                }
                if mbi.State == windows::Win32::System::Memory::MEM_COMMIT {
                    region_count += 1;
                }
                temp_address = (mbi.BaseAddress as u64 + mbi.RegionSize as u64) as _;
            }
        }

        let total_regions = region_count as f32;
        let mut processed_regions = 0.0;

        let mut address = 0;
        while address < max_address {
            let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
            let size = unsafe {
                VirtualQueryEx(
                    handle,
                    address as _,
                    &mut mbi,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if size == 0 {
                break;
            }

            if mbi.State == windows::Win32::System::Memory::MEM_COMMIT {
                let region_size = mbi.RegionSize as usize;
                let mut buffer = vec![0u8; region_size];
                let mut bytes_read = 0;
                let read_success = unsafe {
                    ReadProcessMemory(
                        handle,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as _,
                        region_size,
                        &mut bytes_read,
                    )
                }
                .is_ok();

                if read_success && bytes_read > 0 {
                    let protection = match mbi.Protect {
                        windows::Win32::System::Memory::PAGE_EXECUTE => "x--".to_string(),
                        windows::Win32::System::Memory::PAGE_EXECUTE_READ => "r-x".to_string(),
                        windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE => "rwx".to_string(),
                        windows::Win32::System::Memory::PAGE_EXECUTE_WRITECOPY => "rwx".to_string(),
                        windows::Win32::System::Memory::PAGE_READONLY => "r--".to_string(),
                        windows::Win32::System::Memory::PAGE_READWRITE => "rw-".to_string(),
                        windows::Win32::System::Memory::PAGE_WRITECOPY => "rw-".to_string(),
                        _ => "rwx".to_string(),
                    };
                    regions.push(MemoryRegion {
                        base_address: mbi.BaseAddress as u64,
                        size: region_size as u64,
                        protection,
                        data: buffer[..bytes_read].to_vec(),
                        is_executable: mbi.Protect & windows::Win32::System::Memory::PAGE_EXECUTE != 0,
                        is_writable: mbi.Protect & windows::Win32::System::Memory::PAGE_READWRITE != 0
                            || mbi.Protect & windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE != 0
                            || mbi.Protect & windows::Win32::System::Memory::PAGE_WRITECOPY != 0,
                    });
                }
            }
            address = (mbi.BaseAddress as u64 + mbi.RegionSize as u64) as _;

            processed_regions += 1.0;
            let progress = (processed_regions / total_regions) * 100.0;
            progress_callback(progress);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let task = unsafe { task_for_pid(mach_task_self(), pid as pid_t, &mut 0 as *mut mach_port_t) };
        if task == MACH_PORT_NULL {
            error!("Failed to get task port for PID {}", pid);
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get task port"));
        }

        let mut address: mach_vm_address_t = 0;
        let mut region_count = 0;
        {
            let mut temp_address = address;
            while unsafe {
                let mut size: mach_vm_size_t = 0;
                let mut info = vm_region_basic_info_64::default();
                let mut count = size_of::<vm_region_basic_info_64>() as u32;
                mach_vm_region(
                    task,
                    &mut temp_address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    &mut info as *mut _ as vm_region_info_t,
                    &mut count,
                    ptr::null_mut(),
                ) == KERN_SUCCESS
            } {
                region_count += 1;
                temp_address += size;
            }
        }

        let total_regions = region_count as f32;
        let mut processed_regions = 0.0;

        while unsafe {
            let mut size: mach_vm_size_t = 0;
            let mut info = vm_region_basic_info_64::default();
            let mut count = size_of::<vm_region_basic_info_64>() as u32;
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_BASIC_INFO_64,
                &mut info as *mut _ as vm_region_info_t,
                &mut count,
                ptr::null_mut(),
            ) == KERN_SUCCESS
        } {
            let mut buffer = vec![0u8; size as usize];
            let mut read_size = size;
            if unsafe {
                mach_vm_read(
                    task,
                    address,
                    size,
                    buffer.as_mut_ptr() as *mut c_void,
                    &mut read_size,
                ) == KERN_SUCCESS
            } {
                regions.push(MemoryRegion {
                    base_address: address as u64,
                    size: read_size as u64,
                    protection: format!(
                        "{}{}{}",
                        if info.protection & vm_prot_t::VM_PROT_READ != 0 { "r" } else { "-" },
                        if info.protection & vm_prot_t::VM_PROT_WRITE != 0 { "w" } else { "-" },
                        if info.protection & vm_prot_t::VM_PROT_EXECUTE != 0 { "x" } else { "-" }
                    ),
                    data: buffer[..read_size].to_vec(),
                    is_executable: info.protection & vm_prot_t::VM_PROT_EXECUTE != 0,
                    is_writable: info.protection & vm_prot_t::VM_PROT_WRITE != 0,
                });
            }
            address += size;
            processed_regions += 1.0;
            let progress = (processed_regions / total_regions) * 100.0;
            progress_callback(progress);
        }
    }

    info!("Parsed {} regions from live process PID: {}", regions.len(), pid);
    Ok(regions)
}

#[cfg(target_os = "macos")]
extern "C" {
    fn task_for_pid(port: mach_port_t, pid: pid_t, task: *mut mach_port_t) -> kern_return_t;
}