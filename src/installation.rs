//! Installed assets are resolved only beside the real executable, never from cwd or a cache.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const ASSET_LOCK: &str = include_str!("../assets.lock.json");
const LICENSE: &str = include_str!("../LICENSE");

#[derive(Deserialize)]
struct Asset {
    path: String,
    sha256: String,
}
#[derive(Deserialize)]
struct Platform {
    runtime: String,
    files: Vec<Asset>,
}
#[derive(Deserialize)]
struct Lock {
    schema: u32,
    asset_set: String,
    files: Vec<Asset>,
    platforms: BTreeMap<String, Platform>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    veil_version: String,
    asset_set: String,
    platform: String,
}

/// Both paths are explicit, or both come from one validated installed prefix.
pub enum Assets {
    Explicit {
        artifacts: PathBuf,
        runtime: PathBuf,
    },
    Installed(Installation),
}
pub struct Installation {
    root: PathBuf,
    lock: Lock,
    platform: String,
}

impl Assets {
    pub fn resolve(artifacts: Option<PathBuf>, runtime: Option<PathBuf>) -> Result<Self> {
        match (artifacts, runtime) {
            (Some(artifacts), Some(runtime)) => Ok(Self::Explicit { artifacts, runtime }),
            (None, None) => {
                let executable = std::env::current_exe().context("locate Veil executable")?;
                Ok(Self::Installed(Installation::from_executable(&executable).context(
                    "no usable Veil installation; run scripts/install --prefix PATH, or supply both --artifacts and --runtime (--artifacts is required for an uninstalled build)",
                )?))
            }
            _ => bail!("--artifacts and --runtime must be supplied together"),
        }
    }

    pub fn paths(&self) -> (PathBuf, PathBuf) {
        match self {
            Self::Explicit { artifacts, runtime } => (artifacts.clone(), runtime.clone()),
            Self::Installed(installation) => (
                installation.root.join("model"),
                installation
                    .root
                    .join(&installation.lock.platforms[&installation.platform].runtime),
            ),
        }
    }
}

impl Installation {
    pub fn from_executable(executable: &Path) -> Result<Self> {
        let executable = executable
            .canonicalize()
            .context("resolve Veil executable")?;
        let bin = executable
            .parent()
            .context("missing executable directory")?;
        ensure!(
            bin.file_name().is_some_and(|name| name == "bin"),
            "expected PREFIX/bin/veil"
        );
        let root = bin
            .parent()
            .context("missing installation prefix")?
            .to_owned();
        let manifest: Manifest = serde_json::from_slice(
            &fs::read(root.join("manifest.json")).context("read installation manifest")?,
        )
        .context("invalid installation manifest")?;
        let lock = lock()?;
        ensure!(
            manifest.schema == 1,
            "unsupported installation manifest schema"
        );
        ensure!(
            manifest.veil_version == env!("CARGO_PKG_VERSION"),
            "installation/executable version mismatch"
        );
        ensure!(
            manifest.asset_set == lock.asset_set,
            "installation asset set mismatch"
        );
        let platform = platform()?;
        ensure!(
            manifest.platform == platform,
            "installation platform mismatch"
        );
        ensure!(
            lock.platforms.contains_key(&platform),
            "unsupported installation platform"
        );
        Ok(Self {
            root,
            lock,
            platform,
        })
    }

    /// Only this explicit operation reads/hashes all asset files. Never loads native code.
    pub fn verify(&self) -> Result<Verification> {
        let license = Asset {
            path: "LICENSE".into(),
            sha256: format!("{:x}", Sha256::digest(LICENSE.as_bytes())),
        };
        let files = self
            .lock
            .files
            .iter()
            .chain(&self.lock.platforms[&self.platform].files)
            .chain(std::iter::once(&license))
            .map(|asset| {
                let sha256 = crate::hash_file(&self.root.join(&asset.path))
                    .with_context(|| format!("verify installed asset {}", asset.path))?;
                Ok(FileVerification {
                    path: asset.path.clone(),
                    verified: sha256 == asset.sha256,
                    expected_sha256: asset.sha256.clone(),
                    sha256,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Verification {
            source: "installation",
            root: self.root.clone(),
            asset_set: self.lock.asset_set.clone(),
            platform: self.platform.clone(),
            passed: files.iter().all(|file| file.verified),
            files,
        })
    }
}

#[derive(Serialize)]
pub struct Verification {
    source: &'static str,
    root: PathBuf,
    asset_set: String,
    platform: String,
    pub passed: bool,
    files: Vec<FileVerification>,
}
#[derive(Serialize)]
struct FileVerification {
    path: String,
    expected_sha256: String,
    sha256: String,
    verified: bool,
}

pub fn expected_model_hash() -> Result<String> {
    lock()?
        .files
        .into_iter()
        .find(|asset| asset.path == "model/onnx/model_q4.onnx")
        .map(|asset| asset.sha256)
        .context("model missing from compiled asset lock")
}
fn lock() -> Result<Lock> {
    let lock: Lock = serde_json::from_str(ASSET_LOCK).context("invalid compiled asset lock")?;
    ensure!(lock.schema == 1, "unsupported compiled asset lock schema");
    Ok(lock)
}
fn platform() -> Result<String> {
    ensure!(
        cfg!(any(
            target_os = "macos",
            all(target_os = "linux", target_env = "gnu")
        )),
        "installed assets support macOS and glibc Linux only"
    );
    Ok(format!(
        "{}-{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_overrides_are_rejected() {
        assert!(Assets::resolve(Some("model".into()), None).is_err());
        assert!(Assets::resolve(None, Some("runtime".into())).is_err());
    }
    #[test]
    fn explicit_paths_do_not_inspect_installation() {
        let paths = Assets::resolve(Some("model".into()), Some("runtime".into()))
            .unwrap()
            .paths();
        assert_eq!(paths, (PathBuf::from("model"), PathBuf::from("runtime")));
    }
    #[test]
    fn compiled_lock_has_expected_model_and_platforms() {
        let lock = lock().unwrap();
        assert_eq!(
            expected_model_hash().unwrap(),
            "9f27d24949b0581701071ea5ef522d77ccd3f50c525cc91eac4d265b0fc2afe5"
        );
        assert_eq!(lock.platforms.len(), 4);
        assert!(lock.platforms.contains_key(&platform().unwrap()));
    }
}
