use facelock_core::Config;

use crate::backend::Backend;
use crate::ipc_client;

pub fn run(config: &Config) -> anyhow::Result<()> {
    // DEC-6/N13: `ListDevices` is root-only now (was facelock-group).
    ipc_client::require_root("sudo facelock devices")?;

    // One selection, one enumeration (D1); both transports render here. The
    // renderers used to live twice — this one and a direct copy that printed
    // its own loop.
    let backend = Backend::select(config);
    let devices = backend.list_devices()?;

    if devices.is_empty() {
        println!("No video devices found.");
        println!("Check that your camera is connected and the v4l2 module is loaded.");
        return Ok(());
    }

    // Format detail is a direct-only capability (the D-Bus DeviceInfo does
    // not carry it) — stated by the caps instead of silently printing
    // nothing.
    let show_formats = backend.caps().device_formats;

    println!("Available video devices:\n");
    for dev in &devices {
        let ir_tag = if dev.is_ir { " [IR]" } else { "" };
        println!("  {}{ir_tag}", dev.path);
        println!("    Name:    {}", dev.name);
        println!("    Driver:  {}", dev.driver);

        if show_formats && !dev.formats.is_empty() {
            println!("    Formats:");
            for fmt in &dev.formats {
                let sizes: Vec<String> =
                    fmt.sizes.iter().map(|(w, h)| format!("{w}x{h}")).collect();
                println!(
                    "      {} ({}) — {}",
                    fmt.fourcc.trim(),
                    fmt.description,
                    if sizes.is_empty() {
                        "no sizes reported".to_string()
                    } else {
                        sizes.join(", ")
                    }
                );
            }
        }
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // Device listing requires hardware or a running daemon; the transport
    // fork and its failure policy are pinned in `crate::backend`.
}
