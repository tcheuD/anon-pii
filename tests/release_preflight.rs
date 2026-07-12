#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempRepo(PathBuf);

impl TempRepo {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "anon-pii-release-preflight-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temporary repository");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("git output should be UTF-8")
        .trim()
        .to_owned()
}

fn write_manifest(repo: &Path, version: &str) {
    fs::write(
        repo.join("Cargo.toml"),
        format!("[package]\nname = \"fixture\"\nversion = \"{version}\"\n"),
    )
    .expect("write fixture manifest");
}

fn run_preflight(repo: &Path, tag: &str, release_ref: &str, main_ref: &str) -> Output {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/release-preflight.sh");
    Command::new("bash")
        .arg(script)
        .args([tag, release_ref, main_ref])
        .current_dir(repo)
        .output()
        .expect("run release preflight")
}

#[test]
fn release_preflight_enforces_tag_version_and_main_containment() {
    let repo = TempRepo::new();
    git(repo.path(), &["init"]);
    git(repo.path(), &["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(repo.path(), &["config", "user.name", "Release Test"]);
    git(
        repo.path(),
        &["config", "user.email", "release-test@example.com"],
    );
    write_manifest(repo.path(), "0.1.1");
    git(repo.path(), &["add", "Cargo.toml"]);
    git(repo.path(), &["commit", "-m", "release 0.1.1"]);
    let release_commit = git(repo.path(), &["rev-parse", "HEAD"]);
    git(repo.path(), &["tag", "v0.1.1", &release_commit]);

    fs::write(repo.path().join("after-release"), "main advanced\n")
        .expect("write main advancement");
    git(repo.path(), &["add", "after-release"]);
    git(repo.path(), &["commit", "-m", "advance main"]);
    let main_commit = git(repo.path(), &["rev-parse", "HEAD"]);

    let accepted = run_preflight(repo.path(), "v0.1.1", &release_commit, "main");
    assert!(
        accepted.status.success(),
        "an ancestor of main should be releasable:\n{}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    git(repo.path(), &["tag", "v0.1.0", &release_commit]);
    let wrong_version = run_preflight(repo.path(), "v0.1.0", &release_commit, "main");
    assert!(!wrong_version.status.success());
    assert!(
        String::from_utf8_lossy(&wrong_version.stderr).contains("does not match package version")
    );

    let wrong_commit = run_preflight(repo.path(), "v0.1.1", &main_commit, "main");
    assert!(!wrong_commit.status.success());
    assert!(String::from_utf8_lossy(&wrong_commit.stderr).contains("not release commit"));

    git(
        repo.path(),
        &["checkout", "-b", "side-release", &release_commit],
    );
    write_manifest(repo.path(), "0.1.2");
    git(repo.path(), &["add", "Cargo.toml"]);
    git(repo.path(), &["commit", "-m", "side release"]);
    let side_commit = git(repo.path(), &["rev-parse", "HEAD"]);
    git(repo.path(), &["tag", "v0.1.2", &side_commit]);

    let side_release = run_preflight(repo.path(), "v0.1.2", &side_commit, "main");
    assert!(!side_release.status.success());
    assert!(String::from_utf8_lossy(&side_release.stderr).contains("is not contained"));

    let malformed = run_preflight(repo.path(), "release-0.1.1", &release_commit, "main");
    assert!(!malformed.status.success());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("semantic version"));
}
