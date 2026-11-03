use std::process::{Command, Output};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_peerspan-host"))
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

#[test]
fn an_explicit_person_key_that_cannot_be_used_fails_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let state = state.to_str().unwrap();
    let missing = dir.path().join("missing").display().to_string();
    let encrypted = dir.path().join("encrypted");
    std::fs::write(
        &encrypted,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();
    let rsa = dir.path().join("rsa.pub");
    std::fs::write(&rsa, "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC0 rsa\n").unwrap();
    let token = "peerspan-invite-v1.e30";
    for key in [
        missing.as_str(),
        encrypted.to_str().unwrap(),
        rsa.to_str().unwrap(),
    ] {
        for args in [
            vec![
                "--state",
                state,
                "network",
                "join",
                "--token",
                token,
                "--person-key",
                key,
            ],
            vec![
                "--state",
                state,
                "network",
                "create",
                "--name",
                "team",
                "--member",
                "alice",
                "--person-key",
                key,
            ],
        ] {
            let output = Command::new(env!("CARGO_BIN_EXE_peerspan-host"))
                .args(&args)
                .env_remove("SSH_AUTH_SOCK")
                .output()
                .unwrap();
            assert!(!output.status.success(), "{args:?}: {output:?}");
            let error = String::from_utf8_lossy(&output.stderr);
            assert!(error.contains("--person-key"), "{error}");
            // Refused before any daemon request: no connection attempt, no state.
            assert!(!error.contains("connect"), "{error}");
            assert!(!std::path::Path::new(state).exists());
        }
    }
}
