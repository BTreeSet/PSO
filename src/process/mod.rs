use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use sysinfo::{ProcessesToUpdate, System};

pub fn find_process_pid(process_name: &str) -> Option<i32> {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system
        .processes()
        .iter()
        .find_map(|(pid, process)| (process.name() == process_name).then_some(pid.as_u32() as i32))
}

pub fn find_process_pid_by_exe(executable: &Path) -> Result<Option<i32>> {
    let target = fs::canonicalize(executable)
        .with_context(|| format!("failed to resolve {}", executable.display()))?;
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);

    Ok(system.processes().iter().find_map(|(pid, process)| {
        process
            .exe()
            .and_then(|path| fs::canonicalize(path).ok())
            .filter(|path| path == &target)
            .map(|_| pid.as_u32() as i32)
    }))
}

pub fn resolve_singbox_pid(singbox_bin: &Path, explicit_pid_hint: &str) -> Result<i32> {
    match find_process_pid_by_exe(singbox_bin) {
        Ok(Some(pid)) => Ok(pid),
        Ok(None) => find_process_pid("sing-box").with_context(|| {
            format!(
                "sing-box process was not found for executable {}; pass {explicit_pid_hint} to target an explicit process",
                singbox_bin.display()
            )
        }),
        Err(error) => find_process_pid("sing-box").with_context(|| {
            format!(
                "failed to match sing-box executable path ({error:#}); pass {explicit_pid_hint} to target an explicit process"
            )
        }),
    }
}

pub fn sighup_process(pid: i32) -> Result<()> {
    let result = unsafe { libc::kill(pid, libc::SIGHUP) };
    if result != 0 {
        return Err(anyhow!(std::io::Error::last_os_error()))
            .map_err(|error| error.context(format!("failed to send SIGHUP to pid {pid}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn resolve_singbox_pid_matches_unique_executable_copy() {
        let sleep_path = Command::new("sh")
            .arg("-c")
            .arg("command -v sleep")
            .output()
            .expect("sleep path")
            .stdout;
        let sleep_path = std::str::from_utf8(&sleep_path)
            .expect("sleep path utf8")
            .trim();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let copied_sleep = temp_dir.path().join("sleep-copy");
        fs::copy(sleep_path, &copied_sleep).expect("copy sleep binary");

        let mut child = Command::new(&copied_sleep)
            .arg("30")
            .spawn()
            .expect("spawn copied sleep");

        let pid = resolve_singbox_pid(Path::new(&copied_sleep), "--singbox-pid")
            .expect("resolve copied sleep pid");

        assert_eq!(pid, child.id() as i32);
        let _ = child.kill();
        let _ = child.wait();
    }
}
