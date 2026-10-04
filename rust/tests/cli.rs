use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_capsule-host"))
        .args(args)
        .env_remove("HOME")
        .env_remove("XDG_STATE_HOME")
        .output()
        .unwrap()
}

#[test]
fn nested_help_works_without_a_daemon_or_home_directory() {
    for args in [
        vec!["agent", "register", "--help"],
        vec!["session", "attach", "-h"],
        vec!["help", "session", "list"],
        vec!["run", "--help"],
        vec!["serve", "--help"],
    ] {
        let output = cli(&args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    }
}

#[test]
fn invalid_arguments_are_rejected_before_resolving_state_or_connecting() {
    for args in [
        vec!["agent", "register", "--name", "bob"],
        vec!["session", "attach", "--agent", "agent_example"],
        vec!["activity", "--after", "bad"],
        vec!["activity", "--limit", "0"],
        vec!["activity", "--limit", "1001"],
        vec!["--state", "--unknown", "run"],
        vec!["info", "unexpected"],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.starts_with("error:"), "{error}");
        assert!(!error.contains("HOME is not set"), "{error}");
        assert!(!error.contains("connect to"), "{error}");
    }
}
