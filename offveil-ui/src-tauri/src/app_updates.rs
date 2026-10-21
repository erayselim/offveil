//! Discover Mac releases (including prereleases), then use Tauri's signed updater.
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::{Manager, Webview};
use tauri_plugin_updater::UpdaterExt;

const REPO_DOWNLOADS: &str = "https://github.com/erayselim/offveil/releases/download/";

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    state: String,
}

// Do not use GitHub Latest: it excludes prereleases and may be Windows-only.
fn newest_manifest(
    releases: &[Release],
    current: &semver::Version,
) -> Option<(semver::Version, reqwest::Url)> {
    releases
        .iter()
        .filter(|r| !r.draft)
        .filter_map(|r| {
            let version =
                semver::Version::parse(r.tag_name.strip_prefix('v').unwrap_or(&r.tag_name)).ok()?;
            if version <= *current {
                return None;
            }
            let asset = r
                .assets
                .iter()
                .find(|a| a.name == "latest-mac.json" && a.state == "uploaded")?;
            let archive = r
                .assets
                .iter()
                .find(|a| a.name.ends_with("_aarch64.app.tar.gz") && a.state == "uploaded")?;
            if !r
                .assets
                .iter()
                .any(|a| a.name == format!("{}.sig", archive.name) && a.state == "uploaded")
            {
                return None;
            }
            let mut expected = reqwest::Url::parse(REPO_DOWNLOADS).ok()?;
            expected
                .path_segments_mut()
                .ok()?
                .pop_if_empty()
                .extend([r.tag_name.as_str(), "latest-mac.json"]);
            if reqwest::Url::parse(&asset.browser_download_url).ok()? != expected {
                return None;
            }
            Some((version, expected))
        })
        .max_by(|a, b| a.0.cmp(&b.0))
}

fn release_client() -> Result<reqwest::Client, String> {
    // Discovery runs before the updater's own request, which would normally
    // initialize ring. reqwest/rustls-no-provider otherwise panics here.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .user_agent(concat!("offveil/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())
}

async fn mac_manifest(
    current: &semver::Version,
) -> Result<Option<(semver::Version, reqwest::Url)>, String> {
    let client = release_client()?;
    let mut releases = Vec::new();
    // Bound discovery to the most recent 300 published releases / 3 requests.
    for page in 1..=3 {
        let batch = client
            .get(format!(
                "https://api.github.com/repos/erayselim/offveil/releases?per_page=100&page={page}"
            ))
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2026-03-10")
            .send()
            .await
            .map_err(|e| format!("Mac update discovery: {e}"))?
            .error_for_status()
            .map_err(|e| format!("Mac update discovery: {e}"))?
            .json::<Vec<Release>>()
            .await
            .map_err(|e| format!("Mac release JSON: {e}"))?;
        let last_page = batch.len() < 100;
        releases.extend(batch);
        if last_page {
            break;
        }
    }
    Ok(newest_manifest(&releases, current))
}

// Same public resource contract as the updater plugin's JS Update constructor.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    rid: tauri::ResourceId,
    current_version: String,
    version: String,
    body: Option<String>,
    raw_json: serde_json::Value,
}

#[tauri::command]
pub async fn check_app_update(webview: Webview) -> Result<Option<Metadata>, String> {
    let mut builder = webview.updater_builder().timeout(Duration::from_secs(20));
    let mut expected_version = None;
    if cfg!(target_os = "macos") {
        let current = &webview.app_handle().package_info().version;
        let Some((version, url)) = mac_manifest(current).await? else {
            return Ok(None);
        };
        expected_version = Some(version.to_string());
        builder = builder.endpoints(vec![url]).map_err(|e| e.to_string())?;
    }
    let Some(update) = builder
        .build()
        .map_err(|e| e.to_string())?
        .check()
        .await
        .map_err(|e| e.to_string())?
    else {
        return Ok(None);
    };
    if expected_version
        .as_deref()
        .is_some_and(|v| v != update.version)
    {
        return Err("Mac release tag and update manifest versions differ".into());
    }
    let metadata = Metadata {
        current_version: update.current_version.clone(),
        version: update.version.clone(),
        body: update.body.clone(),
        raw_json: update.raw_json.clone(),
        rid: webview.resources_table().add(update),
    };
    Ok(Some(metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_can_initialize_tls_before_the_updater() {
        release_client().unwrap();
    }
    fn release(tag: &str, draft: bool, has_mac: bool) -> Release {
        Release {
            tag_name: tag.into(),
            draft,
            assets: if has_mac {
                vec![
                    Asset {
                        name: "latest-mac.json".into(),
                        browser_download_url: format!("{REPO_DOWNLOADS}{tag}/latest-mac.json"),
                        state: "uploaded".into(),
                    },
                    Asset {
                        name: "offveil_aarch64.app.tar.gz".into(),
                        browser_download_url: String::new(),
                        state: "uploaded".into(),
                    },
                    Asset {
                        name: "offveil_aarch64.app.tar.gz.sig".into(),
                        browser_download_url: String::new(),
                        state: "uploaded".into(),
                    },
                ]
            } else {
                vec![]
            },
        }
    }
    #[test]
    fn finds_numeric_prerelease_order_ignoring_windows_and_drafts() {
        let releases = vec![
            release("v1.0.0-mac.9", false, true),
            release("v1.0.0-mac.10", false, true),
            release("v3.0.0", false, false),
            release("v4.0.0", true, true),
        ];
        let result =
            newest_manifest(&releases, &semver::Version::parse("1.0.0-mac.8").unwrap()).unwrap();
        assert_eq!(result.0.to_string(), "1.0.0-mac.10");
    }
    #[test]
    fn stable_beats_prerelease_and_never_downgrades() {
        let releases = vec![
            release("v1.0.0-mac.10", false, true),
            release("v1.0.0", false, true),
        ];
        assert_eq!(
            newest_manifest(&releases, &semver::Version::parse("1.0.0-mac.9").unwrap())
                .unwrap()
                .0
                .to_string(),
            "1.0.0"
        );
        assert!(newest_manifest(&releases, &semver::Version::parse("1.0.0").unwrap()).is_none());
    }

    #[test]
    fn shared_rc_upgrades_both_previous_mac_releases() {
        let releases = vec![release("v1.0.0-rc.1", false, true)];
        for version in ["1.0.0-mac.3", "1.0.0-mac.4"] {
            let selected =
                newest_manifest(&releases, &semver::Version::parse(version).unwrap()).unwrap();
            assert_eq!(selected.0.to_string(), "1.0.0-rc.1");
        }
    }

    #[test]
    fn rc_is_newer_than_the_previous_windows_versions() {
        let rc = semver::Version::parse("1.0.0-rc.1").unwrap();
        for prior in ["1.0.0-b4", "1.0.0-b5"] {
            assert!(rc > semver::Version::parse(prior).unwrap());
        }
    }
    #[test]
    fn rejects_manifest_outside_this_release() {
        let mut release = release("v1.0.1", false, true);
        release.assets[0].browser_download_url = "https://example.com/latest-mac.json".into();
        assert!(newest_manifest(&[release], &semver::Version::parse("1.0.0").unwrap()).is_none());
    }

    #[test]
    fn beta_updates_from_stable_and_then_to_final() {
        let beta = vec![release("v1.0.4-beta.1", false, true)];
        let stable = semver::Version::parse("1.0.3").unwrap();
        assert_eq!(
            newest_manifest(&beta, &stable).unwrap().0.to_string(),
            "1.0.4-beta.1"
        );
        let releases = vec![
            release("v1.0.4-beta.1", false, true),
            release("v1.0.4", false, true),
        ];
        let current = semver::Version::parse("1.0.4-beta.1").unwrap();
        assert_eq!(
            newest_manifest(&releases, &current).unwrap().0.to_string(),
            "1.0.4"
        );
    }

    #[test]
    fn beta_four_is_discovered_from_beta_three() {
        let releases = vec![
            release("v1.0.4-beta.3", false, true),
            release("v1.0.4-beta.4", false, true),
        ];
        let current = semver::Version::parse("1.0.4-beta.3").unwrap();
        assert_eq!(
            newest_manifest(&releases, &current).unwrap().0.to_string(),
            "1.0.4-beta.4"
        );
    }

    #[test]
    fn skips_releases_while_payloads_are_still_uploading() {
        let mut release = release("v1.0.1", false, true);
        release.assets[1].state = "open".into();
        assert!(newest_manifest(&[release], &semver::Version::parse("1.0.0").unwrap()).is_none());
        let mut release = self::release("v1.0.1", false, true);
        release.assets.pop();
        assert!(newest_manifest(&[release], &semver::Version::parse("1.0.0").unwrap()).is_none());
    }
}
