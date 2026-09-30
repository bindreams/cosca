//! THROWAWAY (plan D, unit D0): measures private OS calls on CI. One `D0 <id> <key>=<value>` line
//! per fact; asserts only what later units rely on.

/// Prints one `D0 <id> <key>=<value>` line.
macro_rules! d0 {
    ($id:expr, $($arg:tt)*) => {
        println!("D0 {} {}", $id, format_args!($($arg)*))
    };
}

/// Kills and reaps its child on drop, so no failure path leaks a process.
struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
#[path = "private_call_probe/linux.rs"]
mod linux;

#[cfg(target_os = "macos")]
#[path = "private_call_probe/macos.rs"]
mod macos;

#[cfg(windows)]
#[path = "private_call_probe/win.rs"]
mod win;

/// Identifies the runner and its OS build.
#[test]
fn d0_env() {
    for k in ["RUNNER_OS", "RUNNER_ARCH", "RUNNER_NAME", "ImageOS", "ImageVersion"] {
        d0!("ENV", "{k}={}", std::env::var(k).unwrap_or_else(|_| "<unset>".into()));
    }
    d0!("ENV", "arch={}", std::env::consts::ARCH);
    #[cfg(unix)]
    {
        let out = |cmd: &str, args: &[&str]| {
            std::process::Command::new(cmd)
                .args(args)
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().replace('\n', " | "))
                .unwrap_or_else(|e| format!("<{e}>"))
        };
        d0!("ENV", "uname_a={}", out("uname", &["-a"]));
        #[cfg(target_os = "macos")]
        {
            d0!("ENV", "sw_vers={}", out("sw_vers", &[]));
        }
    }
    #[cfg(windows)]
    win::print_os_build();
}
