use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct DeployPlan {
    pub singbox_bin: PathBuf,
    pub rendered_tmp: PathBuf,
    pub active_config: PathBuf,
    pub singbox_pid: i32,
}

pub async fn deploy_with_sighup(plan: &DeployPlan) -> Result<()> {
    validate_singbox_config(&plan.singbox_bin, &plan.rendered_tmp).await?;
    atomic_swap(&plan.rendered_tmp, &plan.active_config)?;
    send_sighup(plan.singbox_pid)?;
    Ok(())
}

pub async fn validate_singbox_config(singbox_bin: &Path, config: &Path) -> Result<()> {
    let output = Command::new(singbox_bin)
        .arg("check")
        .arg("-c")
        .arg(config)
        .output()
        .await
        .with_context(|| format!("failed to execute {}", singbox_bin.display()))?;

    if !output.status.success() {
        return Err(anyhow!(
            "sing-box check failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(())
}

pub fn atomic_swap(rendered_tmp: &Path, active_config: &Path) -> Result<()> {
    if let Some(parent) = active_config.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    fs::rename(rendered_tmp, active_config).with_context(|| {
        format!(
            "failed to atomically move {} to {}",
            rendered_tmp.display(),
            active_config.display()
        )
    })?;
    Ok(())
}

pub fn send_sighup(pid: i32) -> Result<()> {
    let result = unsafe { libc::kill(pid, libc::SIGHUP) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to send SIGHUP to pid {pid}"));
    }
    Ok(())
}
