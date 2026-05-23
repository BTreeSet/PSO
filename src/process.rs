use anyhow::{Result, anyhow};
use sysinfo::{ProcessesToUpdate, System};

pub fn find_process_pid(process_name: &str) -> Option<i32> {
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system
        .processes()
        .iter()
        .find_map(|(pid, process)| (process.name() == process_name).then_some(pid.as_u32() as i32))
}

pub fn sighup_process(pid: i32) -> Result<()> {
    let result = unsafe { libc::kill(pid, libc::SIGHUP) };
    if result != 0 {
        return Err(anyhow!(std::io::Error::last_os_error()))
            .map_err(|error| error.context(format!("failed to send SIGHUP to pid {pid}")));
    }
    Ok(())
}
