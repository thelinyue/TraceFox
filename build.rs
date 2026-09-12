fn main() {
    slint_build::compile("ui/app.slint").expect("界面编译失败");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/branding/tracefox.ico")
            .set("ProductName", "TraceFox")
            .set("FileDescription", "NAS 诊断信息提取工具")
            .compile()
            .expect("Windows 资源编译失败");
    }
}
