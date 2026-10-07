use std::{fs, io, sync::OnceLock};

use serde_json::Value;

#[cfg(any(target_os = "linux", test))]
pub(super) mod cpu;

pub(super) fn system_release() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        Some(detect_release(uname_release))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn uname_release() -> io::Result<String> {
    nix::sys::utsname::uname()
        .map(|uname| uname.release().to_string_lossy().into_owned())
        .map_err(io::Error::from)
}

#[cfg(any(target_os = "linux", test))]
fn detect_release(release: impl FnOnce() -> io::Result<String>) -> String {
    // Bun 1.4.2 ignores Linux uname errors and returns its zeroed release buffer.
    release().unwrap_or_default()
}

pub(super) fn memory() -> Value {
    #[cfg(target_os = "linux")]
    {
        detect_memory(|| {
            nix::sys::sysinfo::sysinfo()
                .map(|info| info.ram_total())
                .map_err(io::Error::from)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Value::Null
    }
}

#[cfg(any(target_os = "linux", test))]
fn detect_memory(probe: impl FnOnce() -> io::Result<u64>) -> Value {
    // Bun reports sysinfo failures as zero and exposes the u64 result as a JavaScript Number.
    let bytes = probe().unwrap_or_default();
    serde_json::json!(crate::field_value::serde::Json(&crate::FieldValue::Number(
        bytes as f64
    )))
}

pub(super) fn is_wsl() -> bool {
    #[cfg(target_os = "linux")]
    {
        detect_wsl(
            uname_release,
            || fs::read("/proc/version"),
            is_inside_container,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(any(target_os = "linux", test))]
fn detect_wsl(
    release: impl FnOnce() -> io::Result<String>,
    version: impl FnOnce() -> io::Result<Vec<u8>>,
    inside_container: impl FnOnce() -> bool,
) -> bool {
    let wsl_release = detect_release(release);
    let microsoft = wsl_release.to_lowercase().contains("microsoft")
        || version().is_ok_and(|bytes| {
            String::from_utf8_lossy(&bytes)
                .to_lowercase()
                .contains("microsoft")
        });
    microsoft && !inside_container()
}

#[cfg(target_os = "linux")]
fn is_inside_container() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    detect_inside_container(
        &CACHED,
        || fs::metadata("/run/.containerenv").map(|_| ()),
        is_docker,
    )
}

#[cfg(any(target_os = "linux", test))]
fn detect_inside_container(
    cached: &OnceLock<bool>,
    marker: impl FnOnce() -> io::Result<()>,
    docker: impl FnOnce() -> bool,
) -> bool {
    *cached.get_or_init(|| marker().is_ok() || docker())
}

pub(super) fn is_docker() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    detect_docker(
        &CACHED,
        || fs::metadata("/.dockerenv").map(|_| ()),
        || fs::read("/proc/self/cgroup"),
    )
}

fn detect_docker(
    cached: &OnceLock<bool>,
    marker: impl FnOnce() -> io::Result<()>,
    cgroup: impl FnOnce() -> io::Result<Vec<u8>>,
) -> bool {
    // Upstream treats probe errors as absence and caches either result for the process.
    *cached.get_or_init(|| {
        marker().is_ok()
            || cgroup().is_ok_and(|bytes| {
                // The upstream UTF-8 decoder preserves this ASCII substring beside invalid bytes.
                bytes.windows(b"docker".len()).any(|part| part == b"docker")
            })
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use serde_json::json;

    use super::*;

    #[test]
    fn memory_is_uncached_and_maps_probe_errors_to_zero() {
        let reads = Cell::new(0);
        for (bytes, expected) in [
            (Some(8_589_934_592), json!(8_589_934_592_u64)),
            (None, json!(0)),
            (Some(17_179_869_184), json!(17_179_869_184_u64)),
        ] {
            assert_eq!(
                detect_memory(|| {
                    reads.set(reads.get() + 1);
                    bytes.ok_or_else(|| io::ErrorKind::PermissionDenied.into())
                }),
                expected
            );
        }
        assert_eq!(reads.get(), 3);
    }

    #[test]
    fn memory_projects_unsigned_bytes_through_javascript_numbers() {
        assert_eq!(
            detect_memory(|| Ok(9_007_199_254_740_993)),
            json!(9_007_199_254_740_992_u64)
        );
        assert_eq!(
            detect_memory(|| Ok(u64::MAX)),
            json!(18_446_744_073_709_552_000.0)
        );
    }

    #[test]
    fn system_and_wsl_read_release_independently() {
        for (first, second, expected, expected_version_reads) in [
            (" first release\n", "5.15-MiCrOsOfT-standard", true, 0),
            ("5.15-Microsoft", "second release", false, 1),
        ] {
            let release_reads = Cell::new(0);
            let version_reads = Cell::new(0);
            let container_reads = Cell::new(0);
            let mut release = || {
                release_reads.set(release_reads.get() + 1);
                Ok(if release_reads.get() == 1 {
                    first
                } else {
                    second
                }
                .into())
            };
            let system_release = detect_release(&mut release);
            let is_wsl = detect_wsl(
                release,
                || {
                    version_reads.set(version_reads.get() + 1);
                    Ok(b"Linux version 6.17.0".to_vec())
                },
                || {
                    container_reads.set(container_reads.get() + 1);
                    false
                },
            );
            assert_eq!(system_release, first);
            assert_eq!(is_wsl, expected);
            assert_eq!(release_reads.get(), 2);
            assert_eq!(version_reads.get(), expected_version_reads);
            assert_eq!(container_reads.get(), u32::from(expected));
        }
    }

    #[test]
    fn wsl_version_decoding_matches_lowercase_substrings() {
        for (contents, expected) in [
            (Some(&b"Linux version MiCrOsOfT WSL2"[..]), true),
            (Some(&b"\xffMICROSOFT\xfe"[..]), true),
            (Some(&b"micro\xffsoft"[..]), false),
            (Some(&b"Linux version 6.17.0"[..]), false),
            (Some(&b""[..]), false),
            (None, false),
        ] {
            let container_reads = Cell::new(0);
            let is_wsl = detect_wsl(
                || Ok("6.17.0".into()),
                || {
                    contents
                        .map(<[u8]>::to_vec)
                        .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
                },
                || {
                    container_reads.set(container_reads.get() + 1);
                    false
                },
            );
            assert_eq!(is_wsl, expected, "{contents:?}");
            assert_eq!(container_reads.get(), u32::from(expected));
        }
    }

    #[test]
    fn uname_errors_preserve_empty_release_and_proc_fallback() {
        let release_reads = Cell::new(0);
        let version_reads = Cell::new(0);
        let mut release = || {
            release_reads.set(release_reads.get() + 1);
            Err(io::ErrorKind::PermissionDenied.into())
        };
        let system_release = detect_release(&mut release);
        let is_wsl = detect_wsl(
            release,
            || {
                version_reads.set(version_reads.get() + 1);
                Ok(b"Linux version Microsoft".to_vec())
            },
            || false,
        );
        assert_eq!(system_release, "");
        assert!(is_wsl);
        assert_eq!(release_reads.get(), 2);
        assert_eq!(version_reads.get(), 1);
    }

    #[test]
    fn containers_exclude_wsl_and_keep_independent_caches() {
        for (container_marker, docker_marker, docker_cgroup) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
            (false, false, false),
        ] {
            let container_cached = OnceLock::new();
            let docker_cached = OnceLock::new();
            let is_wsl = detect_wsl(
                || Ok("Microsoft".into()),
                || Err(io::ErrorKind::NotFound.into()),
                || {
                    detect_inside_container(
                        &container_cached,
                        || {
                            if container_marker {
                                Ok(())
                            } else {
                                Err(io::ErrorKind::PermissionDenied.into())
                            }
                        },
                        || {
                            detect_docker(
                                &docker_cached,
                                || {
                                    if docker_marker {
                                        Ok(())
                                    } else {
                                        Err(io::ErrorKind::NotFound.into())
                                    }
                                },
                                || {
                                    Ok(if docker_cgroup {
                                        b"docker".to_vec()
                                    } else {
                                        Vec::new()
                                    })
                                },
                            )
                        },
                    )
                },
            );
            assert_eq!(
                is_wsl,
                !(container_marker || docker_marker || docker_cgroup)
            );
            assert_eq!(
                docker_cached.get().copied(),
                (!container_marker).then_some(docker_marker || docker_cgroup)
            );
            let docker = detect_docker(
                &docker_cached,
                || Err(io::ErrorKind::NotFound.into()),
                || Ok(Vec::new()),
            );
            assert_eq!(docker, docker_marker || docker_cgroup);
        }
    }

    #[test]
    fn container_results_are_cached_while_kernel_probes_repeat() {
        for initial in [false, true] {
            let cached = OnceLock::new();
            let release_reads = Cell::new(0);
            let version_reads = Cell::new(0);
            let marker_reads = Cell::new(0);
            let docker_reads = Cell::new(0);
            for (microsoft, current) in [(true, initial), (false, !initial), (true, !initial)] {
                let mut release = || {
                    release_reads.set(release_reads.get() + 1);
                    Ok("6.17.0".into())
                };
                assert_eq!(detect_release(&mut release), "6.17.0");
                let is_wsl = detect_wsl(
                    release,
                    || {
                        version_reads.set(version_reads.get() + 1);
                        Ok(if microsoft {
                            b"Microsoft".to_vec()
                        } else {
                            Vec::new()
                        })
                    },
                    || {
                        detect_inside_container(
                            &cached,
                            || {
                                marker_reads.set(marker_reads.get() + 1);
                                Err(io::ErrorKind::NotFound.into())
                            },
                            || {
                                docker_reads.set(docker_reads.get() + 1);
                                current
                            },
                        )
                    },
                );
                assert_eq!(is_wsl, microsoft && !initial);
            }
            assert_eq!(release_reads.get(), 6);
            assert_eq!(version_reads.get(), 3);
            assert_eq!(marker_reads.get(), 1);
            assert_eq!(docker_reads.get(), 1);
        }
    }

    #[test]
    fn docker_marker_precedes_cgroup_read() {
        let cgroup_reads = Cell::new(0);
        assert!(detect_docker(
            &OnceLock::new(),
            || Ok(()),
            || {
                cgroup_reads.set(cgroup_reads.get() + 1);
                Err(io::ErrorKind::PermissionDenied.into())
            },
        ));
        assert_eq!(cgroup_reads.get(), 0);
    }

    #[test]
    fn cgroup_uses_case_sensitive_substrings_after_marker_errors() {
        for error in [io::ErrorKind::NotFound, io::ErrorKind::PermissionDenied] {
            for (contents, expected) in [
                (&b"0::/docker/container"[..], true),
                (&b"0::/system.slice/docker.service"[..], true),
                (&b"0::/mydockercontainer"[..], true),
                (&b"\xffdocker\xfe"[..], true),
                (&b"0::/Docker/container"[..], false),
                (&b"0::/podman/container"[..], false),
                (&b"d\xffocker"[..], false),
                (&b""[..], false),
            ] {
                assert_eq!(
                    detect_docker(
                        &OnceLock::new(),
                        || Err(error.into()),
                        || Ok(contents.to_vec()),
                    ),
                    expected,
                    "{contents:?}, {error:?}"
                );
            }
        }
    }

    #[test]
    fn cgroup_read_errors_are_cached_as_absence() {
        let cached = OnceLock::new();
        assert!(!detect_docker(
            &cached,
            || Err(io::ErrorKind::NotFound.into()),
            || Err(io::ErrorKind::PermissionDenied.into()),
        ));
        assert!(!detect_docker(
            &cached,
            || Ok(()),
            || Ok(b"docker".to_vec()),
        ));
    }

    #[test]
    fn cached_results_do_not_probe_again() {
        for initial in [false, true] {
            let cached = OnceLock::new();
            let marker_reads = Cell::new(0);
            let cgroup_reads = Cell::new(0);
            for current in [initial, !initial] {
                let detected = detect_docker(
                    &cached,
                    || {
                        marker_reads.set(marker_reads.get() + 1);
                        Err(io::ErrorKind::NotFound.into())
                    },
                    || {
                        cgroup_reads.set(cgroup_reads.get() + 1);
                        Ok(if current {
                            b"docker".to_vec()
                        } else {
                            Vec::new()
                        })
                    },
                );
                assert_eq!(detected, initial);
            }
            assert_eq!(marker_reads.get(), 1);
            assert_eq!(cgroup_reads.get(), 1);
        }
    }
}
