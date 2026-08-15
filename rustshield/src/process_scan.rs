// process_scan.rs
// Enumerate all running process executable paths on Windows.
// This is what Windows Defender uses in its quick scan — checking
// memory-resident threats that leave no trace on disk in watched folders.

/// Returns a deduplicated list of absolute paths to every running
/// process's executable. Skips System (PID 4) and Idle (PID 0).
#[cfg(target_os = "windows")]
pub fn get_running_executables() -> Vec<String> {
    use std::collections::HashSet;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{CloseHandle, BOOL};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut paths: HashSet<String> = HashSet::new();

    unsafe {
        let snap = match CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) {
            Ok(h) if !h.is_invalid() => h,
            _ => {
                log::warn!("CreateToolhelp32Snapshot failed — skipping process scan");
                return vec![];
            }
        };

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let pid = entry.th32ProcessID;
                // Skip System Idle Process (0) and System (4)
                if pid > 4 {
                    if let Ok(proc_h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, BOOL(0), pid)
                    {
                        let mut buf = [0u16; 1024];
                        let mut len = buf.len() as u32;
                        let pwstr = PWSTR(buf.as_mut_ptr());
                        if QueryFullProcessImageNameW(proc_h, PROCESS_NAME_WIN32, pwstr, &mut len)
                            .is_ok()
                        {
                            let path = String::from_utf16_lossy(&buf[..len as usize]);
                            if !path.is_empty() {
                                let p = std::path::Path::new(&path);
                                if p.exists() && p.is_file() {
                                    paths.insert(path);
                                }
                            }
                        }
                        let _ = CloseHandle(proc_h);
                    }
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }

    log::info!(
        "Process scan: {} unique running executables found",
        paths.len()
    );
    paths.into_iter().collect()
}

#[cfg(not(target_os = "windows"))]
pub fn get_running_executables() -> Vec<String> {
    vec![]
}
