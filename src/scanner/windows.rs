use crate::report::ScanResult;

pub fn scan_device() -> Vec<ScanResult> {
    vec![
        ScanResult::new("OS up to date", true, "All critical updates installed (KB5026361 present)."),
        ScanResult::new("Antivirus enabled", true, "Microsoft Defender active and up to date."),
        ScanResult::new("Disk encryption enabled", false, "BitLocker not enabled. Company policy requires BitLocker."),
        ScanResult::new("Firewall enabled", true, "Windows Firewall enabled for all profiles."),
    ]
}
