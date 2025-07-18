pub struct ScanResult {
    pub name: &'static str,
    pub passed: bool,
}

impl ScanResult {
    pub fn new(name: &'static str, passed: bool) -> Self {
        Self { name, passed }
    }
}

pub fn print_summary(results: &[ScanResult]) {
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();

    for r in results {
        if r.passed {
            println!("\x1b[32m[✔] {}\x1b[0m", r.name); // Green
        } else {
            println!("\x1b[31m[✘] {}\x1b[0m", r.name); // Red
        }
    }

    println!("--------------------------------------");
    if passed == total {
        println!("\x1b[32mDevice is COMPLIANT.\x1b[0m");
    } else {
        println!("\x1b[31mDevice is NOT compliant.\x1b[0m");
    }
}
