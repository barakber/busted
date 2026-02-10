use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs, io::BufRead};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Escape hatch: skip eBPF compilation (CI, or when xtask already built it).
    // The resulting stub binary will panic at runtime if loaded.
    if env::var("BUSTED_SKIP_EBPF_BUILD").is_ok() {
        fs::write(out_dir.join("busted-ebpf"), []).unwrap();
        return;
    }

    let ebpf_dir = find_ebpf_workspace().unwrap_or_else(|| download_ebpf_crate(&out_dir));

    println!("cargo:rerun-if-changed={ebpf_dir}");

    compile_ebpf(&ebpf_dir, &out_dir);
}

/// Compile busted-ebpf for the BPF target.
///
/// This replicates what `aya_build::build_ebpf` does, but uses a target
/// directory name that doesn't collide with the output binary name.
fn compile_ebpf(ebpf_dir: &str, out_dir: &Path) {
    let endian = env::var("CARGO_CFG_TARGET_ENDIAN").expect("CARGO_CFG_TARGET_ENDIAN not set");
    let target = match endian.as_str() {
        "little" => "bpfel-unknown-none",
        "big" => "bpfeb-unknown-none",
        other => panic!("unsupported endian: {other}"),
    };

    let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set");

    let mut rustflags = OsString::new();
    for s in [
        "--cfg=bpf_target_arch=\"",
        &arch,
        "\"",
        "\x1f",
        "-Cdebuginfo=2",
        "\x1f",
        "-Clink-arg=--btf",
    ] {
        rustflags.push(s);
    }

    // Use a target-dir name that won't collide with the output binary.
    let target_dir = out_dir.join("ebpf-target");

    let mut cmd = Command::new("rustup");
    cmd.args([
        "run",
        "nightly",
        "cargo",
        "build",
        "--package",
        "busted-ebpf",
        "-Z",
        "build-std=core",
        "--bins",
        "--message-format=json",
        "--release",
        "--target",
        target,
        "--target-dir",
    ]);
    cmd.arg(&target_dir);
    cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");
    cmd.current_dir(ebpf_dir);

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect(
            "failed to spawn cargo build for busted-ebpf — is `rustup` installed with nightly?",
        );

    // Forward stderr as cargo warnings.
    let stderr = child.stderr.take().unwrap();
    let stderr_thread = std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            println!("cargo:warning={line}");
        }
    });

    // Parse JSON messages to find the compiled binary.
    let stdout = child.stdout.take().unwrap();
    let reader = std::io::BufReader::new(stdout);
    let mut binary_path: Option<PathBuf> = None;

    for line in reader.lines() {
        let line = line.expect("read stdout line");
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&line) {
            if json.get("reason").and_then(|v| v.as_str()) == Some("compiler-artifact") {
                if let Some(exe) = json.get("executable").and_then(|v| v.as_str()) {
                    binary_path = Some(PathBuf::from(exe));
                }
            }
            if json.get("reason").and_then(|v| v.as_str()) == Some("compiler-message") {
                if let Some(rendered) = json
                    .get("message")
                    .and_then(|m| m.get("rendered"))
                    .and_then(|v| v.as_str())
                {
                    for l in rendered.split('\n') {
                        println!("cargo:warning={l}");
                    }
                }
            }
        }
    }

    let status = child.wait().expect("failed to wait for cargo build");
    assert!(
        status.success(),
        "cargo build for busted-ebpf failed: {status}"
    );

    stderr_thread.join().expect("stderr thread panicked");

    let binary = binary_path.expect("busted-ebpf binary not found in cargo output");
    let dst = out_dir.join("busted-ebpf");

    // Clean up stale stub file or directory at the destination.
    if dst.is_dir() {
        let _ = fs::remove_dir_all(&dst);
    }

    fs::copy(&binary, &dst).unwrap_or_else(|e| {
        panic!(
            "failed to copy {} to {}: {e}",
            binary.display(),
            dst.display()
        )
    });
}

/// Try to find busted-ebpf as a workspace member (local development).
fn find_ebpf_workspace() -> Option<String> {
    let metadata = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .ok()?;

    let pkg = metadata.packages.iter().find(|p| p.name == "busted-ebpf")?;

    Some(
        pkg.manifest_path
            .parent()
            .expect("busted-ebpf manifest has no parent")
            .as_str()
            .to_owned(),
    )
}

/// Download busted-ebpf source from crates.io (cargo install path).
fn download_ebpf_crate(out_dir: &Path) -> String {
    let version = env!("CARGO_PKG_VERSION");
    let extracted = out_dir.join(format!("busted-ebpf-{version}"));

    // Skip download if already extracted from a previous build.
    if extracted.join("Cargo.toml").exists() {
        return extracted.to_str().unwrap().to_owned();
    }

    eprintln!("busted-ebpf not found in workspace, downloading v{version} from crates.io...");

    let tarball = out_dir.join("busted-ebpf.tar.gz");
    let url = format!("https://crates.io/api/v1/crates/busted-ebpf/{version}/download");

    let status = Command::new("curl")
        .args(["-sfL", "-o"])
        .arg(&tarball)
        .arg(&url)
        .status()
        .expect("failed to run curl — is it installed?");
    assert!(
        status.success(),
        "failed to download busted-ebpf v{version} from crates.io (HTTP error)"
    );

    let status = Command::new("tar")
        .args(["xzf"])
        .arg(&tarball)
        .arg("-C")
        .arg(out_dir)
        .status()
        .expect("failed to run tar — is it installed?");
    assert!(status.success(), "failed to extract busted-ebpf tarball");

    assert!(
        extracted.join("Cargo.toml").exists(),
        "extracted busted-ebpf is missing Cargo.toml at {}",
        extracted.display()
    );

    extracted.to_str().unwrap().to_owned()
}
