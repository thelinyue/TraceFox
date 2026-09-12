#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod desktop;
fn main() {
    if let Err(e) = run() {
        eprintln!("TraceFox：{e:#}");
        if std::env::args().len() == 1 {
            rfd::MessageDialog::new()
                .set_title("TraceFox 启动失败")
                .set_description(format!("{e:#}"))
                .show();
        }
        std::process::exit(1);
    }
}
fn run() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() > 2 && args[1] == "--analyze" {
        let rules = if args.len() > 3 {
            tracefox::rules::RuleSet::import(&std::fs::read_to_string(&args[3])?)?
        } else {
            tracefox::rules::RuleSet::defaults()
        };
        let p = tracefox::engine::analyze(
            std::path::Path::new(&args[2]),
            &rules,
            &std::sync::atomic::AtomicBool::new(false),
            |s| eprintln!("{s}"),
        )?;
        println!("{}", p.display());
        return Ok(());
    }
    desktop::run()
}
