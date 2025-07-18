mod gui;

fn main() -> eframe::Result<()> {
    // GUI window options (size, icons, etc) - can be customized
    let options = eframe::NativeOptions::default();

    // Launch the egui-based native app with the title and options
    eframe::run_native(
        "Compliatrixx",
        options,
        Box::new(|_cc| Box::new(gui::MainApp::default())),
    )
}