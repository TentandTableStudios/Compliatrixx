use std::thread;
use std::sync::mpsc::{self, Receiver, Sender};
use std::process::Command;
use eframe::egui;

#[cfg(target_os = "windows")]
fn is_running_as_admin() -> bool {
    let out = Command::new("powershell")
        .args([
            "-NoLogo", "-NoProfile", "-Command",
            "[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)"
        ])
        .output();
    match out {
        Ok(ref o) if String::from_utf8_lossy(&o.stdout).trim() == "True" => true,
        _ => false,
    }
}
#[cfg(not(target_os = "windows"))]
fn is_running_as_admin() -> bool { true } // Assume yes for non-Windows

#[derive(Clone)]
pub struct ComplianceSettings {
    pub require_bitlocker: bool,
    pub min_password_length: u8,
    pub require_firewall: bool,
    pub require_mdm: bool,
    pub require_tpm: bool,
    pub require_hello: bool,
    pub min_drive_space_gb: u32,
    pub require_laps: bool,
    pub require_bios_pw: bool,
    pub require_mfa: bool,
    pub require_antivirus: bool,
    pub require_auto_update: bool,
    pub require_device_guard: bool,
    pub require_secure_dns: bool,
    pub require_usb_block: bool,
    pub require_patch_cadence: u8,
    pub require_ssd: bool,
    pub require_antimalware: bool,
    pub require_privileged_account_monitor: bool,
    pub require_password_expiry_days: u16,
    pub require_event_log_size_mb: u32,
}

impl Default for ComplianceSettings {
    fn default() -> Self {
        Self {
            require_bitlocker: true,
            min_password_length: 12,
            require_firewall: true,
            require_mdm: true,
            require_tpm: true,
            require_hello: true,
            min_drive_space_gb: 15,
            require_laps: false,
            require_bios_pw: false,
            require_mfa: false,
            require_antivirus: true,
            require_auto_update: true,
            require_device_guard: true,
            require_secure_dns: true,
            require_usb_block: false,
            require_patch_cadence: 30,
            require_ssd: false,
            require_antimalware: true,
            require_privileged_account_monitor: false,
            require_password_expiry_days: 90,
            require_event_log_size_mb: 32,
        }
    }
}

#[derive(Default)]
pub struct MainApp {
    scan_results: Vec<(String, bool, String)>,
    scanning: bool,
    show_reason: Option<(String, String)>,
    show_settings: bool,
    compliance_settings: ComplianceSettings,
    scan_rx: Option<std::sync::mpsc::Receiver<ScanStatus>>, 
    scan_progress: Option<(usize, usize, String)>, 
}

fn main() {
    if !is_running_as_admin() {
        #[cfg(target_os = "windows")]
        {
            use std::io::Write;
            let _ = std::io::stderr().write_all(b"ERROR: Please run this tool as Administrator.\n");
            let _ = Command::new("powershell")
                .args(&["-Command", "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Please run this tool as Administrator.', 'Compliatrixx', 'OK', 'Error')"])
                .output();
        }
        return;
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 800.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Compliatrixx",
        options,
        Box::new(|_cc| Box::new(MainApp::default())),
    );
}

impl eframe::App for MainApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("⚙️ Policy Settings").clicked() {
                    self.show_settings = true;
                }
            });
        });

        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(19, 28, 36))
                    .inner_margin(16.0),
            )
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading(
                        egui::RichText::new("🛡️Compliatrixx")
                            .size(30.0)
                            .color(egui::Color32::from_rgb(60, 180, 255)),
                    );
                    ui.label(
                        egui::RichText::new("Beyond Surface Compliance.")
                            .size(16.0)
                            .color(egui::Color32::LIGHT_GRAY),
                    );
                });

                ui.add_space(8.0);

                if !self.scanning {
                    if ui
                        .add(
                            egui::Button::new("🔍 Start Deep Compliance Scan")
                                .fill(egui::Color32::from_rgb(44, 97, 167))
                                .min_size(egui::vec2(210.0, 40.0)),
                        )
                        .clicked()
                    {
                        let (tx, rx) = mpsc::channel();
                        self.scan_rx = Some(rx);
                        self.scan_progress = Some((0, 1, "Starting...".to_string()));
                        let settings = self.compliance_settings.clone();
                        thread::spawn(move || {
                            perform_scan_with_progress(&settings, tx);
                        });
                        self.scanning = true;
                        self.scan_results.clear();
                    }
                } else {
                    // -- NEW: Show progress bar if scanning --
                    if let Some(rx) = &self.scan_rx {
                        // Handle progress updates
                        while let Ok(status) = rx.try_recv() {
                            match status {
                                ScanStatus::Progress { current, total, check_name } => {
                                    self.scan_progress = Some((current, total, check_name));
                                }
                                ScanStatus::Done(results) => {
                                    self.scan_results = results;
                                    self.scanning = false;
                                    self.scan_rx = None;
                                    self.scan_progress = None;
                                }
                            }
                        }
                    }

                    if let Some((current, total, check_name)) = &self.scan_progress {
                        let frac = if *total > 0 { *current as f32 / *total as f32 } else { 0.0 };
                        ui.add(egui::ProgressBar::new(frac).show_percentage());
                        ui.label(format!("Scanning: {}", check_name));
                    } else {
                        ui.label("Initializing scan...");
                    }
                }

                ui.add_space(16.0);
                ui.separator();

                egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        for (check, passed, details) in &self.scan_results {
                            let is_fail = !*passed;
                            let button = egui::Button::new({
                                if is_fail {
                                    format!("❌ {} (Click for more info)", check)
                                } else {
                                    format!("✔️ {} (Click for more info)", check)
                                }
                            })
                            .fill(if is_fail {
                                egui::Color32::from_rgb(110, 30, 30)
                            } else {
                                egui::Color32::from_rgb(44, 167, 97)
                            })
                            .min_size(egui::vec2(440.0, 34.0))
                            .rounding(8.0);

                            if ui.add(button).on_hover_text(details).clicked() {
                                self.show_reason = Some((check.clone(), details.clone()));
                            }

                            ui.label(
                                egui::RichText::new(details)
                                    .size(13.0)
                                    .color(if is_fail { egui::Color32::YELLOW } else { egui::Color32::GRAY }),
                            );

                            ui.add_space(7.0);
                        }
                    });
                });

                if !self.scan_results.is_empty() {
                    let compliant = self.scan_results.iter().all(|(_, ok, _)| *ok);
                    ui.add_space(18.0);
                    ui.vertical_centered(|ui| {
                        if compliant {
                            ui.label(
                                egui::RichText::new("✅ DEVICE IS FULLY COMPLIANT")
                                    .size(20.0)
                                    .color(egui::Color32::GREEN)
                                    .strong(),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new("❌ DEVICE IS NOT COMPLIANT")
                                    .size(20.0)
                                    .color(egui::Color32::RED)
                                    .strong(),
                            );
                        }
                    });
                }

                if let Some((check, reason)) = self.show_reason.clone() {
                    let mut clear_reason = false;
                    egui::Window::new(format!("Details for \"{}\"", check))
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.label(
                                egui::RichText::new(&reason)
                                    .size(16.0)
                                    .color(egui::Color32::YELLOW),
                            );
                            if ui.button("Close").clicked() {
                                clear_reason = true;
                            }
                        });
                    if clear_reason {
                        self.show_reason = None;
                    }
                }

                if self.show_settings {
                    egui::Window::new("Compliance Policy Settings")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("Set your company compliance policy:");
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.add(
                                            egui::Button::new("❌")
                                                .fill(egui::Color32::from_rgb(80, 10, 10))
                                                .rounding(5.0)
                                                .min_size(egui::vec2(28.0, 28.0)),
                                        ).on_hover_text("Exit").clicked() {
                                            self.show_settings = false;
                                        }
                                    }
                                );
                            });
                            ui.separator();

                            let mut applied = false;
                            egui::ScrollArea::vertical()
                                .max_height(480.0)
                                .show(ui, |ui| {
                                    ui.add_space(6.0);
                                    ui.checkbox(&mut self.compliance_settings.require_bitlocker, "Require BitLocker for disk encryption");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_firewall, "Firewall must be enabled");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_mdm, "MDM client required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_tpm, "TPM/Hardware Security Module required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_hello, "Windows Hello/Face/Fingerprint required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_laps, "LAPS/Privileged Account Passwords required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_bios_pw, "BIOS/UEFI password required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_mfa, "MFA required for logon");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_antivirus, "Antivirus/EDR required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_auto_update, "Automatic OS Updates required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_device_guard, "Device Guard required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_secure_dns, "Secure DNS (DoH/DoT) required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_usb_block, "Block USB Storage devices");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_ssd, "SSD Required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_antimalware, "Antimalware (Defender/3rd party) required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_privileged_account_monitor, "Privileged account monitoring required");
                                    ui.add_space(2.0);
                                    ui.horizontal(|ui| {
                                        ui.label("Minimum password length:");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.min_password_length).clamp_range(8..=32));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("Minimum free disk space (GB):");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.min_drive_space_gb).clamp_range(5..=256));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("Patch cadence (days):");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.require_patch_cadence).clamp_range(7..=90));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("Password expiry (days):");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.require_password_expiry_days).clamp_range(30..=365));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("Event Log min size (MB):");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.require_event_log_size_mb).clamp_range(4..=256));
                                    });
                                    ui.add_space(14.0);

                                    if applied {
                                        self.scan_results = perform_scan(&self.compliance_settings); // immediately re-scan with new settings
                                        self.show_settings = false;
                                    }

                                    });

                            if applied {
                                self.show_settings = false;
                            }
                        });
                }
            });
    }
}


        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(19, 28, 36))
                    .inner_margin(16.0),
            )
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading(
                        egui::RichText::new("🛡️Compliatrixx")
                            .size(30.0)
                            .color(egui::Color32::from_rgb(60, 180, 255)),
                    );
                    ui.label(
                        egui::RichText::new("Beyond Surface Compliance.")
                            .size(16.0)
                            .color(egui::Color32::LIGHT_GRAY),
                    );
                });

                ui.add_space(8.0);

                if !self.scanning {
                    if ui
                        .add(
                            egui::Button::new("🔍 Start Deep Compliance Scan")
                                .fill(egui::Color32::from_rgb(44, 97, 167))
                                .min_size(egui::vec2(210.0, 40.0)),
                        )
                        .clicked()
                    {
                        let (tx, rx) = mpsc::channel();
                        self.scan_rx = Some(rx);
                        self.scan_progress = Some((0, 1, "Starting...".to_string()));
                        let settings = self.compliance_settings.clone();
                        thread::spawn(move || {
                            perform_scan_with_progress(&settings, tx);
                        });
                        self.scanning = true;
                        self.scan_results.clear();
                    }
                }
  
                    
            } else {
    // Progress polling and progress bar
                if let Some(rx) = &self.scan_rx {
                    while let Ok(status) = rx.try_recv() {
                        match status {
                            ScanStatus::Progress { current, total, check_name } => {
                                self.scan_progress = Some((current, total, check_name));
                            }
                            ScanStatus::Done(results) => {
                                self.scan_results = results;
                                self.scanning = false;
                                self.scan_rx = None;
                                self.scan_progress = None;
                            }
                        }
                    }
                }
                // Show progress bar and scan status
                if let Some((current, total, check_name)) = &self.scan_progress {
                    let frac = if *total > 0 { *current as f32 / *total as f32 } else { 0.0 };
                    ui.add(egui::ProgressBar::new(frac).show_percentage());
                    ui.label(format!("Scanning: {}", check_name));
                } else {
                    ui.label("Initializing scan...");
                }
            }


                ui.add_space(16.0);
                ui.separator();

                egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        for (check, passed, details) in &self.scan_results {
                            let is_fail = !*passed;
                            let button = egui::Button::new({
                                if is_fail {
                                    format!("❌ {} (Click for more info)", check)
                                } else {
                                    format!("✔️ {} (Click for more info)", check)
                                }
                            })
                            .fill(if is_fail {
                                egui::Color32::from_rgb(110, 30, 30)
                            } else {
                                egui::Color32::from_rgb(44, 167, 97)
                            })
                            .min_size(egui::vec2(440.0, 34.0))
                            .rounding(8.0);

                            if ui.add(button).on_hover_text(details).clicked() {
                                self.show_reason = Some((check.clone(), details.clone()));
                            }

                            ui.label(
                                egui::RichText::new(details)
                                    .size(13.0)
                                    .color(if is_fail { egui::Color32::YELLOW } else { egui::Color32::GRAY }),
                            );

                            ui.add_space(7.0);
                        }
                    });
                });

                if !self.scan_results.is_empty() {
                    let compliant = self.scan_results.iter().all(|(_, ok, _)| *ok);
                    ui.add_space(18.0);
                    ui.vertical_centered(|ui| {
                        if compliant {
                            ui.label(
                                egui::RichText::new("✅ DEVICE IS FULLY COMPLIANT")
                                    .size(20.0)
                                    .color(egui::Color32::GREEN)
                                    .strong(),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new("❌ DEVICE IS NOT COMPLIANT")
                                    .size(20.0)
                                    .color(egui::Color32::RED)
                                    .strong(),
                            );
                        }
                    });
                }

                if let Some((check, reason)) = self.show_reason.clone() {
                    let mut clear_reason = false;
                    egui::Window::new(format!("Details for \"{}\"", check))
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.label(
                                egui::RichText::new(&reason)
                                    .size(16.0)
                                    .color(egui::Color32::YELLOW),
                            );
                            if ui.button("Close").clicked() {
                                clear_reason = true;
                            }
                        });
                    if clear_reason {
                        self.show_reason = None;
                    }
                }

                if self.show_settings {
                    egui::Window::new("Compliance Policy Settings")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                        .show(ctx, |ui| {
                            ui.horizontal(|ui| {
                                ui.label("Set your company compliance policy:");
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui.add(
                                            egui::Button::new("❌")
                                                .fill(egui::Color32::from_rgb(80, 10, 10))
                                                .rounding(5.0)
                                                .min_size(egui::vec2(28.0, 28.0)),
                                        ).on_hover_text("Exit").clicked() {
                                            self.show_settings = false;
                                        }
                                    }
                                );
                            });
                            ui.separator();

                            let mut applied = false;
                            egui::ScrollArea::vertical()
                                .max_height(480.0)
                                .show(ui, |ui| {
                                    ui.add_space(6.0);
                                    ui.checkbox(&mut self.compliance_settings.require_bitlocker, "Require BitLocker for disk encryption");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_firewall, "Firewall must be enabled");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_mdm, "MDM client required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_tpm, "TPM/Hardware Security Module required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_hello, "Windows Hello/Face/Fingerprint required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_laps, "LAPS/Privileged Account Passwords required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_bios_pw, "BIOS/UEFI password required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_mfa, "MFA required for logon");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_antivirus, "Antivirus/EDR required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_auto_update, "Automatic OS Updates required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_device_guard, "Device Guard required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_secure_dns, "Secure DNS (DoH/DoT) required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_usb_block, "Block USB Storage devices");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_ssd, "SSD Required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_antimalware, "Antimalware (Defender/3rd party) required");
                                    ui.add_space(2.0);
                                    ui.checkbox(&mut self.compliance_settings.require_privileged_account_monitor, "Privileged account monitoring required");
                                    ui.add_space(2.0);
                                    ui.horizontal(|ui| {
                                        ui.label("Minimum password length:");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.min_password_length).clamp_range(8..=32));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("Minimum free disk space (GB):");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.min_drive_space_gb).clamp_range(5..=256));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("Patch cadence (days):");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.require_patch_cadence).clamp_range(7..=90));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("Password expiry (days):");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.require_password_expiry_days).clamp_range(30..=365));
                                    });
                                    ui.horizontal(|ui| {
                                        ui.label("Event Log min size (MB):");
                                        ui.add(egui::DragValue::new(&mut self.compliance_settings.require_event_log_size_mb).clamp_range(4..=256));
                                    });
                                    ui.add_space(14.0);

                                    if applied {
                                        self.scan_results = perform_scan(&self.compliance_settings); // immediately re-scan with new settings
                                        self.show_settings = false;
                                    }

                                    });

                            if applied {
                                self.show_settings = false;
                            }
                        });
                }
            });
    }
}

// =============================
//  REAL WINDOWS CHECKS SECTION
// =============================



pub enum ScanStatus {
    Progress { current: usize, total: usize, check_name: String },
    Done(Vec<(String, bool, String)>),
}

fn perform_scan_with_progress(s: &ComplianceSettings, tx: Sender<ScanStatus>) {
    let checks: Vec<fn(&ComplianceSettings) -> (String, bool, String)> = vec![
        check_os_update,
        check_antivirus,
        check_disk_encryption,
        check_firewall,
        check_admins,
        check_screen_lock,
        check_password_policy,
        check_usb_devices,
        check_blacklisted_apps,
        check_required_apps,
        check_secure_boot,
        check_guest_account,
        check_auditing,
        check_ntp_time,
        check_system_file_integrity,
        check_running_processes,
        check_open_ports,
        check_unpatched_software,
        check_unauthorized_cloud_apps,
        check_event_logs,
        check_local_accounts,
        check_dns_settings,
        check_rdp_ssh,
        check_tpm,
        check_bios_password,
        check_windows_hello,
        check_laps,
        check_inactive_accounts,
        check_network_shares,
        check_exploit_guard,
        check_restore_status,
        check_defender_channel,
        check_drive_space,
        check_uac_status,
        check_smart_screen,
        check_clipboard_redir,
        check_app_guard,
        check_hypervisor_status,
        check_antimalware,
        check_device_guard,
        check_patch_cadence,
        check_ssd_required,
        check_privileged_monitor,
        check_password_expiry,
        check_host_is_domain_joined,
        check_wifi_security,
        check_boot_config,
        check_guest_sharing,
        check_service_integrity,
        check_kernel_protection,
        check_event_log_size,
        check_gpo_compliance,
        check_screen_capture_block,
        check_rdp_encryption,
        check_bluetooth_block,
        check_autorun_policy,
        check_network_profile_privacy,
        check_browser_policy,
    ];
    let total = checks.len();
    let mut results = Vec::with_capacity(total);

    for (i, check_fn) in checks.iter().enumerate() {
        let (name, pass, details) = check_fn(s);
        tx.send(ScanStatus::Progress {
            current: i + 1,
            total,
            check_name: name.clone(),
        }).ok();
        results.push((name, pass, details));
    }
    tx.send(ScanStatus::Done(results)).ok();
}

// ========== **INDIVIDUAL CHECKS** (all use cmd/PowerShell where possible) ==========

// -- Utility: Run a PowerShell or CMD command, return stdout as String --
fn run_cmd(args: &[&str]) -> String {
    let output = Command::new("cmd")
        .args(["/C"].iter().chain(args.iter()))
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => "error running cmd".to_string(),
    }
}
fn run_powershell(script: &str) -> String {
    let output = Command::new("powershell")
        .args(["-NoLogo", "-NoProfile", "-Command", script])
        .output();
    match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
        Err(_) => "error running powershell".to_string(),
    }
}

// =========== CHECKS START HERE ===========

fn check_os_update(_s: &ComplianceSettings) -> (String, bool, String) {
    // Windows Update status (needs admin)
    let last = run_powershell("Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 1 | Format-Table -HideTableHeaders -Property InstalledOn");
    let recent = last.split_whitespace().last().unwrap_or("");
    let is_recent = recent != "" && recent.len() >= 6; // just a rough date check
    (
        "OS Patch Level".into(),
        is_recent,
        format!("Latest patch installed: {recent}"),
    )
}
fn check_antivirus(_s: &ComplianceSettings) -> (String, bool, String) {
    let result = run_powershell("Get-MpComputerStatus | Select-Object -ExpandProperty AMServiceEnabled");
    let ok = result.trim() == "True";
    (
        "Antivirus/EDR".into(),
        ok,
        if ok { "Defender real-time protection is ON.".into() } else { "No Defender or AV active!".into() }
    )
}
fn check_antimalware(_s: &ComplianceSettings) -> (String, bool, String) {
    let sigdate = run_powershell("Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusSignatureLastUpdated");
    let ok = !sigdate.is_empty();
    (
        "Antimalware".into(),
        ok,
        format!("AV signature date: {}", if ok { &sigdate } else { "Unknown" }),
    )
}
fn check_disk_encryption(_s: &ComplianceSettings) -> (String, bool, String) {
    let output = run_cmd(&["manage-bde", "-status", "C:"]);
    let enabled = output.contains("Percentage Encrypted: 100%");
    (
        "Disk Encryption".into(),
        enabled,
        if enabled { "BitLocker is fully enabled on C: drive.".into() } else { "BitLocker is NOT fully enabled on C:!".into() }
    )
}
fn check_firewall(_s: &ComplianceSettings) -> (String, bool, String) {
    let output = run_cmd(&["netsh", "advfirewall", "show", "allprofiles"]);
    let ok = output.contains("State ON");
    (
        "Firewall".into(),
        ok,
        if ok { "Firewall enabled for all profiles.".into() } else { "Firewall is disabled for one or more profiles.".into() }
    )
}
fn check_admins() -> (String, bool, String) {
    let output = run_powershell("Get-LocalGroupMember -Group Administrators | Select-Object -ExpandProperty Name");
    let admins: Vec<_> = output.lines().collect();
    let ok = admins.iter().all(|a| a.contains("Administrator") || a.contains("Domain Admins"));
    (
        "Admin Users".into(),
        ok,
        if ok { format!("Admins: {:?}", admins) } else { format!("Non-standard admins: {:?}", admins) }
    )
}
fn check_screen_lock() -> (String, bool, String) {
    // Screen lock (lockout after idle)
    let out = run_powershell("Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut | Select-Object -ExpandProperty ScreenSaveTimeOut");
    let timeout_secs = out.trim().parse::<u32>().unwrap_or(0);
    let ok = timeout_secs <= 600 && timeout_secs != 0;
    (
        "Auto Screen Lock".into(),
        ok,
        if ok { format!("Screen lock timeout: {} seconds", timeout_secs) } else { "Screen lock not set or too high!".into() }
    )
}
fn check_password_policy(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_cmd(&["net", "accounts"]);
    let min_len_line = out.lines().find(|l| l.contains("Minimum password length"));
    let min_len = min_len_line.and_then(|l| l.split(':').nth(1)).unwrap_or("").trim().parse::<u8>().unwrap_or(0);
    (
        "Password Policy".into(),
        min_len >= 8,
        format!("Minimum password length: {min_len}"),
    )
}
fn check_usb_devices(_s: &ComplianceSettings) -> (String, bool, String) {
    // Checks USB block by policy
    let out = run_powershell("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start | Select-Object -ExpandProperty Start");
    let blocked = out.trim() == "4";
    (
        "USB Storage Block".into(),
        blocked,
        if blocked { "USB storage devices are blocked via policy.".into() } else { "USB storage devices allowed.".into() }
    )
}
fn check_blacklisted_apps() -> (String, bool, String) {
    // Checks if common "bad" apps are installed
    let bad = ["utorrent", "teamviewer", "anydesk"];
    let out = run_powershell("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object -ExpandProperty DisplayName");
    let mut found = Vec::new();
    for b in &bad {
        if out.to_lowercase().contains(b) {
            found.push(*b);
        }
    }
    (
        "Prohibited Apps".into(),
        found.is_empty(),
        if found.is_empty() { "No blacklisted apps found.".into() } else { format!("Detected: {:?}", found) }
    )
}
fn check_required_apps(_s: &ComplianceSettings) -> (String, bool, String) {
    // Example: MDM check (you may want a real company check here)
    let found = run_powershell("Get-Service | Where-Object {$_.DisplayName -like '*Intune*'} | Select-Object -First 1 | Format-Table -HideTableHeaders -Property Status");
    let ok = !found.is_empty();
    (
        "Required Apps".into(),
        ok,
        if ok { "MDM client (Intune) detected.".into() } else { "MDM client not found.".into() }
    )
}
fn check_secure_boot() -> (String, bool, String) {
    let output = run_powershell("Confirm-SecureBootUEFI");
    let ok = output.trim() == "True";
    (
        "Secure Boot".into(),
        ok,
        if ok { "Secure Boot is enabled in UEFI.".into() } else { "Secure Boot is disabled.".into() }
    )
}
fn check_guest_account() -> (String, bool, String) {
    let out = run_powershell("Get-LocalUser -Name Guest | Select-Object -ExpandProperty Enabled");
    let disabled = out.trim() == "False";
    (
        "Guest Account".into(),
        disabled,
        if disabled { "Guest account is disabled.".into() } else { "Guest account is enabled!".into() }
    )
}
fn check_auditing(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("auditpol /get /category:*");
    let ok = out.contains("Success") || out.contains("Failure");
    (
        "Audit Logging".into(),
        ok,
        if ok { "Audit logging is configured.".into() } else { "Audit logging is NOT configured.".into() }
    )
}
fn check_ntp_time() -> (String, bool, String) {
    let out = run_cmd(&["w32tm", "/query", "/status"]);
    let synced = out.contains("Source");
    (
        "System Time Sync".into(),
        synced,
        if synced { "NTP time sync is working.".into() } else { "Time not syncing via NTP.".into() }
    )
}
fn check_system_file_integrity() -> (String, bool, String) {
    // Checks last SFC result (may require to run SFC before for best result)
    let out = run_cmd(&["findstr", "SR", "C:\\Windows\\Logs\\CBS\\CBS.log"]);
    let ok = !out.contains("repair") && !out.contains("corrupt");
    (
        "System File Integrity".into(),
        ok,
        if ok { "No OS tampering detected (SFC OK).".into() } else { "Possible OS tampering/corruption.".into() }
    )
}
fn check_running_processes() -> (String, bool, String) {
    // Checks for "bad" processes (example)
    let bad = ["mimikatz", "procmon", "wireshark"];
    let out = run_cmd(&["tasklist"]);
    let mut found = Vec::new();
    for b in &bad {
        if out.to_lowercase().contains(b) {
            found.push(*b);
        }
    }
    (
        "Process List Clean".into(),
        found.is_empty(),
        if found.is_empty() { "No dangerous processes running.".into() } else { format!("Detected: {:?}", found) }
    )
}
fn check_open_ports() -> (String, bool, String) {
    // Looks for open ports (basic)
    let out = run_cmd(&["netstat", "-an"]);
    let open = out.lines().filter(|l| l.contains("LISTENING")).count();
    (
        "Network Ports".into(),
        open < 50,
        format!("{} listening ports detected.", open),
    )
}
fn check_unpatched_software(_s: &ComplianceSettings) -> (String, bool, String) {
    // Only a rough check, for full check use WSUS/MDT/SCCM or third party.
    let out = run_powershell("Get-WindowsUpdateLog");
    let ok = !out.contains("failed");
    (
        "Software Patch Health".into(),
        ok,
        if ok { "No failed patch installs found.".into() } else { "Some software patches may have failed.".into() }
    )
}
fn check_unauthorized_cloud_apps() -> (String, bool, String) {
    // Example: checks for Dropbox/Google Drive/OneDrive
    let out = run_powershell("Get-Process | Select-Object -ExpandProperty ProcessName");
    let apps = ["dropbox", "googledrive", "onedrive"];
    let mut found = Vec::new();
    for app in &apps {
        if out.to_lowercase().contains(app) {
            found.push(*app);
        }
    }
    (
        "Cloud Sync Apps".into(),
        found.is_empty(),
        if found.is_empty() { "No cloud sync apps running.".into() } else { format!("Detected: {:?}", found) }
    )
}
fn check_event_logs(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("Get-EventLog -LogName Security -Newest 1");
    let ok = !out.contains("error") && !out.is_empty();
    (
        "Security Event Log".into(),
        ok,
        if ok { "Security event log is healthy.".into() } else { "Security event log missing/errors.".into() }
    )
}
fn check_local_accounts() -> (String, bool, String) {
    let out = run_powershell("Get-LocalUser | Select-Object -ExpandProperty Name");
    let users: Vec<_> = out.lines().collect();
    let ok = !users.iter().any(|u| u.contains("test") || u.contains("temp"));
    (
        "User Accounts".into(),
        ok,
        if ok { format!("Users: {:?}", users) } else { "Test/temp users exist!".into() }
    )
}
fn check_dns_settings(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses");
    let ok = out.contains("8.8.8.8") || out.contains("1.1.1.1");
    (
        "DNS Settings".into(),
        ok,
        format!("DNS: {out}"),
    )
}
fn check_rdp_ssh() -> (String, bool, String) {
    let out = run_cmd(&["sc", "query", "TermService"]);
    let rdp_on = out.contains("RUNNING");
    let ssh_on = run_cmd(&["sc", "query", "sshd"]).contains("RUNNING");
    (
        "Remote Access".into(),
        !ssh_on,
        if !ssh_on && rdp_on { "RDP enabled, SSH disabled.".into() }
        else if ssh_on { "SSH daemon running (possible risk)!".into() }
        else { "Neither RDP nor SSH enabled.".into() }
    )
}
fn check_tpm(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("Get-WmiObject -Namespace 'Root\\CIMv2\\Security\\MicrosoftTpm' -Class Win32_Tpm | Select-Object -ExpandProperty IsEnabled_InitialValue");
    let ok = out.trim() == "True";
    (
        "TPM/Hardware Security".into(),
        ok,
        if ok { "TPM 2.0+ enabled.".into() } else { "TPM not enabled or not present.".into() }
    )
}
fn check_bios_password(_s: &ComplianceSettings) -> (String, bool, String) {
    // No real way to check BIOS password from Windows without vendor tools.
    (
        "BIOS/UEFI Password".into(),
        false,
        "Cannot check BIOS password from Windows, requires vendor tool.".into()
    )
}
fn check_windows_hello(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("Get-WmiObject -Namespace root\\cimv2\\mdm\\dmmap -Class MDM_Policy_Config01_LocalPoliciesSecurity | Select-Object -ExpandProperty PasswordComplexity");
    let ok = out.trim() != "";
    (
        "Windows Hello/MFA".into(),
        ok,
        if ok { "Windows Hello/MFA appears to be set.".into() } else { "Not detected.".into() }
    )
}
fn check_laps(_s: &ComplianceSettings) -> (String, bool, String) {
    // Real LAPS check would need AD tools; we just look for presence of LAPS client
    let out = run_cmd(&["sc", "query", "AdmPwd"]);
    let ok = out.contains("RUNNING");
    (
        "LAPS Protection".into(),
        ok,
        if ok { "LAPS client is running.".into() } else { "LAPS not detected.".into() }
    )
}
fn check_inactive_accounts() -> (String, bool, String) {
    // Can't get last logon easily without AD; just checks for "Disabled" users
    let out = run_powershell("Get-LocalUser | Where-Object { $_.Enabled -eq $False } | Select-Object -ExpandProperty Name");
    let ok = out.is_empty();
    (
        "Inactive Account Scan".into(),
        ok,
        if ok { "No disabled/inactive accounts.".into() } else { format!("Inactive: {out}") }
    )
}
fn check_network_shares() -> (String, bool, String) {
    let out = run_cmd(&["net", "share"]);
    let ok = !out.to_lowercase().contains("everyone");
    (
        "Network Share Audit".into(),
        ok,
        format!("{out}")
    )
}
fn check_exploit_guard() -> (String, bool, String) {
    let out = run_powershell("Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions");
    let ok = !out.is_empty();
    (
        "Exploit Guard".into(),
        ok,
        if ok { "Exploit Guard is configured.".into() } else { "Exploit Guard not configured.".into() }
    )
}
fn check_restore_status() -> (String, bool, String) {
    let out = run_powershell("Get-ComputerRestorePoint | Select-Object -First 1");
    let ok = !out.is_empty();
    (
        "System Restore Status".into(),
        ok,
        if ok { "System Restore point exists.".into() } else { "No system restore points found.".into() }
    )
}
fn check_defender_channel() -> (String, bool, String) {
    let out = run_powershell("Get-MpPreference | Select-Object -ExpandProperty Channel");
    let ok = out.contains("Enterprise") || out.contains("Preview");
    (
        "Defender Channel".into(),
        ok,
        format!("Defender Channel: {out}")
    )
}
fn check_drive_space(s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("Get-PSDrive -Name C | Select-Object -ExpandProperty Free");
    let free_gb = out.trim().parse::<u64>().unwrap_or(0) / 1024 / 1024 / 1024;
    let ok = free_gb >= s.min_drive_space_gb as u64;
    (
        "Drive Free Space".into(),
        ok,
        format!("{free_gb} GB free. Policy requires at least {} GB.", s.min_drive_space_gb)
    )
}
fn check_uac_status() -> (String, bool, String) {
    let out = run_powershell("Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA | Select-Object -ExpandProperty EnableLUA");
    let ok = out.trim() == "1";
    (
        "UAC Status".into(),
        ok,
        if ok { "UAC is enabled.".into() } else { "UAC is disabled!".into() }
    )
}
fn check_smart_screen() -> (String, bool, String) {
    let out = run_powershell("Get-ItemProperty -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer -Name SmartScreenEnabled | Select-Object -ExpandProperty SmartScreenEnabled");
    let ok = out.contains("RequireAdmin") || out.contains("Warn");
    (
        "SmartScreen".into(),
        ok,
        format!("SmartScreen: {out}")
    )
}
fn check_clipboard_redir() -> (String, bool, String) {
    // Can't directly check clipboard redir, so assume allowed.
    (
        "Clipboard Redirection".into(),
        false,
        "Cannot directly check clipboard redirection status.".into()
    )
}
fn check_app_guard() -> (String, bool, String) {
    let out = run_powershell("Get-WindowsOptionalFeature -Online | Where-Object {$_.FeatureName -eq 'Windows-Defender-ApplicationGuard'} | Select-Object -ExpandProperty State");
    let ok = out.contains("Enabled");
    (
        "Application Guard".into(),
        ok,
        if ok { "Application Guard enabled.".into() } else { "Application Guard not enabled.".into() }
    )
}
fn check_hypervisor_status() -> (String, bool, String) {
    let out = run_cmd(&["systeminfo"]);
    let ok = out.contains("Hyper-V Requirements: A hypervisor has been detected");
    (
        "Hypervisor/Virtualization".into(),
        ok,
        if ok { "Hyper-V detected.".into() } else { "No Hyper-V/virtualization detected.".into() }
    )
}
fn check_device_guard(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object -ExpandProperty SecurityServicesConfigured");
    let ok = out.contains("1");
    (
        "Device Guard".into(),
        ok,
        if ok { "Device Guard enabled.".into() } else { "Device Guard not enabled.".into() }
    )
}
fn check_patch_cadence(s: &ComplianceSettings) -> (String, bool, String) {
    // This is a policy, not a real check
    (
        "Patch Cadence".into(),
        s.require_patch_cadence <= 30,
        format!("Patch window: {} days", s.require_patch_cadence)
    )
}
fn check_ssd_required(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("Get-PhysicalDisk | Select-Object -ExpandProperty MediaType");
    let ok = out.to_lowercase().contains("ssd");
    (
        "SSD Required".into(),
        ok,
        if ok { "System drive is an SSD.".into() } else { "System is not using an SSD.".into() }
    )
}
fn check_privileged_monitor(_s: &ComplianceSettings) -> (String, bool, String) {
    // No universal way in Windows; needs enterprise monitoring tools.
    (
        "Privileged Account Monitoring".into(),
        false,
        "Requires SIEM or monitoring tool.".into()
    )
}
fn check_password_expiry(s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_cmd(&["net", "accounts"]);
    let line = out.lines().find(|l| l.contains("Maximum password age"));
    let days = line.and_then(|l| l.split(':').nth(1)).unwrap_or("").trim().replace("days", "").trim().parse::<u16>().unwrap_or(0);
    (
        "Password Expiry Policy".into(),
        days <= s.require_password_expiry_days,
        format!("Password expiry: {} days", days)
    )
}
fn check_host_is_domain_joined() -> (String, bool, String) {
    let out = run_powershell("(Get-WmiObject Win32_ComputerSystem).PartOfDomain");
    let ok = out.trim() == "True";
    (
        "Domain Join Status".into(),
        ok,
        if ok { "System is domain-joined.".into() } else { "Not domain-joined.".into() }
    )
}
fn check_wifi_security() -> (String, bool, String) {
    let out = run_cmd(&["netsh", "wlan", "show", "interfaces"]);
    let ok = out.contains("WPA2") || out.contains("WPA3");
    (
        "WiFi Security".into(),
        ok,
        if ok { "WiFi secured with WPA2/3.".into() } else { "WiFi not secured.".into() }
    )
}
fn check_boot_config() -> (String, bool, String) {
    let out = run_cmd(&["bcdedit"]);
    let ok = out.contains("bootmgr");
    (
        "Boot Configuration".into(),
        ok,
        if ok { "Boot manager config present.".into() } else { "Boot manager config missing!".into() }
    )
}
fn check_guest_sharing() -> (String, bool, String) {
    // Check if guest sharing is enabled
    let out = run_cmd(&["net", "share"]);
    let ok = !out.to_lowercase().contains("guest");
    (
        "Guest Sharing Block".into(),
        ok,
        if ok { "No guest shares enabled.".into() } else { "Guest sharing enabled!".into() }
    )
}
fn check_service_integrity() -> (String, bool, String) {
    // Only basic check: all services running
    let out = run_cmd(&["sc", "query", "type=", "service", "state=", "all"]);
    let stopped = out.lines().filter(|l| l.contains("STOPPED")).count();
    (
        "Service Integrity".into(),
        stopped == 0,
        format!("{} services stopped.", stopped)
    )
}
fn check_kernel_protection() -> (String, bool, String) {
    let out = run_powershell("Get-WmiObject -Class Win32_OSRecoveryConfiguration | Select-Object -ExpandProperty DebugFilePath");
    let ok = out.trim().is_empty();
    (
        "Kernel Protection".into(),
        ok,
        if ok { "Kernel debugging off.".into() } else { "Kernel debugging ON!".into() }
    )
}
fn check_event_log_size(_s: &ComplianceSettings) -> (String, bool, String) {
    let out = run_powershell("Get-EventLog -LogName Security | Select-Object -First 1 | Select-Object -ExpandProperty MaximumKilobytes");
    let mb = out.trim().parse::<u32>().unwrap_or(0) / 1024;
    (
        "Event Log Size".into(),
        mb >= 16,
        format!("Event log size: {} MB", mb)
    )
}
fn check_gpo_compliance() -> (String, bool, String) {
    // Only can check if GPO applied, not compliance without company rules.
    let out = run_cmd(&["gpresult", "/R"]);
    let ok = out.contains("Applied Group Policy Objects");
    (
        "GPO Compliance".into(),
        ok,
        if ok { "GPO applied.".into() } else { "No GPOs applied.".into() }
    )
}
fn check_screen_capture_block() -> (String, bool, String) {
    // Not easily checkable
    (
        "Screen Capture Block".into(),
        false,
        "Cannot check screen capture policy from Windows userland.".into()
    )
}
fn check_rdp_encryption() -> (String, bool, String) {
    let out = run_cmd(&["reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "/v", "MinEncryptionLevel"]);
    let ok = out.contains("0x3");
    (
        "RDP Encryption".into(),
        ok,
        if ok { "RDP NLA encryption set.".into() } else { "RDP NLA not set (insecure)".into() }
    )
}
fn check_bluetooth_block() -> (String, bool, String) {
    let out = run_powershell("Get-PnpDevice -Class Bluetooth | Select-Object -ExpandProperty Status");
    let ok = out.contains("Disabled") || out.trim().is_empty();
    (
        "Bluetooth Block".into(),
        ok,
        if ok { "Bluetooth disabled.".into() } else { "Bluetooth enabled.".into() }
    )
}
fn check_autorun_policy() -> (String, bool, String) {
    let out = run_cmd(&["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "/v", "NoDriveTypeAutoRun"]);
    let ok = out.contains("0xFF");
    (
        "Autorun Policy".into(),
        ok,
        if ok { "Autorun disabled for all drives.".into() } else { "Autorun not disabled.".into() }
    )
}
fn check_network_profile_privacy() -> (String, bool, String) {
    let out = run_powershell("Get-NetConnectionProfile | Select-Object -ExpandProperty NetworkCategory");
    let ok = out.contains("Private") || out.contains("DomainAuthenticated");
    (
        "Network Profile Privacy".into(),
        ok,
        format!("Profile(s): {out}")
    )
}
fn check_browser_policy() -> (String, bool, String) {
    // No easy way, but check Edge policy as example:
    let out = run_powershell("Get-ItemProperty -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Edge | Format-List");
    let ok = !out.is_empty();
    (
        "Browser Policy".into(),
        ok,
        if ok { "Edge browser policy detected.".into() } else { "No browser GPO policy found.".into() }
    )
}


