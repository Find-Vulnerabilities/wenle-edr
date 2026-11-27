//! Whether this Windows install can run Memory Integrity, and what it is doing.
//!
//! The product does not implement VBS. It reads the operating system's own
//! `Win32_DeviceGuard` answer and the `HypervisorEnforcedCodeIntegrity` policy,
//! and the Settings tab offers the Windows switch only when Windows reports
//! that the feature exists. A machine whose firmware or CPU cannot run VBS
//! gets a disabled control with the reason, not a button that fails after a
//! restart.
//!
//! # Why PowerShell rather than a COM binding
//!
//! `Win32_DeviceGuard` is a WMI class. A full WMI client in this process would
//! be a COM apartment, a query, and a variant decoder for two integers; the
//! same two integers are one short script. The window already runs elevated,
//! and this is asked once when the Settings tab is first opened.

use std::process::Command;

/// What Windows says about VBS and HVCI.
#[derive(Debug, Clone)]
pub struct CoreIsolation {
    /// Windows reports that VBS can be enabled here.
    pub supported: bool,
    /// The policy value is 1. A reboot may still be pending.
    pub enabled: bool,
    /// VBS is running and HVCI is one of the running services.
    pub running: bool,
    /// A policy owns the value; the window must not offer to change it.
    pub locked: bool,
    /// A change was written and needs a restart.
    pub restart_required: bool,
    /// One sentence for the Settings tab.
    pub detail: String,
}

impl Default for CoreIsolation {
    fn default() -> Self {
        Self {
            supported: false,
            enabled: false,
            running: false,
            locked: false,
            restart_required: false,
            detail: "The core-isolation state has not been read yet.".to_owned(),
        }
    }
}

impl CoreIsolation {
    /// Ask Windows. This is called once, when Settings is first drawn.
    #[cfg(windows)]
    pub fn probe() -> Self {
        let script = r#"
$ErrorActionPreference = 'Stop'
$d = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard
$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
$p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
$enabled = if ($null -ne $p.Enabled) { [int]$p.Enabled } else { 0 }
$locked = if ($null -ne $p.Locked) { [int]$p.Locked } else { 0 }
$services = (@($d.SecurityServicesRunning) -join ',')
$properties = (@($d.AvailableSecurityProperties) -join ',')
"$($d.VirtualizationBasedSecurityStatus)|$services|$properties|$enabled|$locked"
"#;
        let output = hidden_powershell(script);
        let Ok(output) = output else {
            return Self {
                detail: "Windows did not answer the Device Guard query; core isolation cannot be offered here.".to_owned(),
                ..Self::default()
            };
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let line = text.lines().last().unwrap_or("").trim();
        let fields: Vec<&str> = line.split('|').collect();
        if fields.len() != 5 {
            return Self {
                detail: "Windows did not answer the Device Guard query; core isolation cannot be offered here.".to_owned(),
                ..Self::default()
            };
        }
        let status: u32 = fields[0].parse().unwrap_or(0);
        let services: Vec<u32> = fields[1]
            .split(',')
            .filter_map(|value| value.trim().parse().ok())
            .collect();
        let properties: Vec<u32> = fields[2]
            .split(',')
            .filter_map(|value| value.trim().parse().ok())
            .collect();
        let enabled = fields[3].trim() == "1";
        let locked = fields[4].trim() == "1";
        // 1 is "hypervisor support" in AvailableSecurityProperties. A machine
        // without it cannot run VBS at all, and the control must be disabled.
        let supported = status > 0 || properties.contains(&1);
        let running = services.contains(&2);
        let detail = if !supported {
            "Windows reports that this firmware and processor cannot run VBS. The option is disabled."
                .to_owned()
        } else if locked {
            "Core isolation is controlled by policy on this machine. Change it in Windows Security."
                .to_owned()
        } else if running {
            "Memory Integrity (HVCI) is running.".to_owned()
        } else if enabled {
            "Core isolation is enabled and will start after the next restart.".to_owned()
        } else {
            "Core isolation is available but not enabled.".to_owned()
        };
        Self {
            supported,
            enabled,
            running,
            locked,
            restart_required: false,
            detail,
        }
    }

    #[cfg(not(windows))]
    pub fn probe() -> Self {
        Self {
            detail: "Core isolation is a Windows feature.".to_owned(),
            ..Self::default()
        }
    }

    /// Write the two policy values Windows uses for Memory Integrity.
    ///
    /// `enabled` only says what the user asked for. The return value is empty
    /// on success and a sentence for the Settings tab on failure.
    #[cfg(windows)]
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
        let value = if enabled { 1 } else { 0 };
        let script = format!(
            r#"
$ErrorActionPreference = 'Stop'
$dg = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$hv = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
New-Item -Path $dg -Force | Out-Null
New-Item -Path $hv -Force | Out-Null
Set-ItemProperty -Path $dg -Name EnableVirtualizationBasedSecurity -Type DWord -Value {value}
Set-ItemProperty -Path $hv -Name Enabled -Type DWord -Value {value}
"#
        );
        match hidden_powershell(&script) {
            Ok(output) if output.status.success() => {
                self.enabled = enabled;
                self.running = false;
                self.restart_required = true;
                self.detail = if enabled {
                    "Core isolation was enabled. Restart Windows to apply it.".to_owned()
                } else {
                    "Core isolation was disabled. Restart Windows to apply it.".to_owned()
                };
                Ok(())
            }
            Ok(output) => Err(format!(
                "Windows refused the change: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
            Err(error) => Err(format!("The Windows setting could not be changed: {error}")),
        }
    }

    #[cfg(not(windows))]
    pub fn set_enabled(&mut self, _enabled: bool) -> Result<(), String> {
        Err("Core isolation is a Windows feature.".to_owned())
    }
}

#[cfg(windows)]
fn hidden_powershell(script: &str) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_state_is_not_offered() {
        let state = CoreIsolation::default();
        assert!(!state.supported);
        assert!(!state.enabled);
        assert!(!state.detail.is_empty());
    }
}
