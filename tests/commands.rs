use std::process::Command;

#[test]
fn help_lists_the_supported_commands() {
    let output = Command::new(env!("CARGO_BIN_EXE_veil"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for name in ["cloak", "uncloak", "redact", "verify-artifacts"] {
        assert!(help.contains(&format!("\n  {name} ")));
    }
    for name in [
        "restore",
        "tokenize",
        "detect",
        "encode",
        "bench",
        "verify-tokenizer",
    ] {
        assert!(!help.contains(&format!("\n  {name} ")));
    }
}

#[test]
fn removed_commands_are_rejected() {
    for name in [
        "restore",
        "tokenize",
        "detect",
        "encode",
        "bench",
        "verify-tokenizer",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_veil"))
            .arg(name)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
    }
}

#[test]
fn keeping_email_domains_is_an_explicit_redact_option() {
    for command in ["redact", "cloak", "uncloak"] {
        let output = Command::new(env!("CARGO_BIN_EXE_veil"))
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert_eq!(help.contains("--keep-email-domains"), command == "redact");
    }
    for command in ["cloak", "uncloak"] {
        let output = Command::new(env!("CARGO_BIN_EXE_veil"))
            .args([command, "--keep-email-domains", "--vault", "unused.vault"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("unexpected argument '--keep-email-domains'")
        );
    }
}
