use std::{fs, io, sync::OnceLock};

pub(super) struct KernelInfo {
    pub(super) release: Option<String>,
    pub(super) is_wsl: bool,
}

pub(super) fn kernel_info() -> KernelInfo {
    #[cfg(target_os = "linux")]
    {
        detect_kernel(
            || {
                nix::sys::utsname::uname()
                    .map(|uname| uname.release().to_string_lossy().into_owned())
                    .map_err(io::Error::from)
            },
            || fs::read("/proc/version"),
            is_inside_container,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        KernelInfo {
            release: None,
            is_wsl: false,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn detect_kernel(
    mut release: impl FnMut() -> io::Result<String>,
    version: impl FnOnce() -> io::Result<Vec<u8>>,
    inside_container: impl FnOnce() -> bool,
) -> KernelInfo {
    // Bun 1.4.2 ignores Linux uname errors and returns its zeroed release buffer.
    let system_release = release().unwrap_or_default();
    let wsl_release = release().unwrap_or_default();
    let microsoft = wsl_release.to_lowercase().contains("microsoft")
        || version().is_ok_and(|bytes| {
            String::from_utf8_lossy(&bytes)
                .to_lowercase()
                .contains("microsoft")
        });
    KernelInfo {
        release: Some(system_release),
        is_wsl: microsoft && !inside_container(),
    }
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

    use super::*;

    #[test]
    fn kernel_reads_release_twice_and_uses_second_for_wsl() {
        for (first, second, expected, expected_version_reads) in [
            (" first release\n", "5.15-MiCrOsOfT-standard", true, 0),
            ("5.15-Microsoft", "second release", false, 1),
        ] {
            let release_reads = Cell::new(0);
            let version_reads = Cell::new(0);
            let container_reads = Cell::new(0);
            let info = detect_kernel(
                || {
                    release_reads.set(release_reads.get() + 1);
                    Ok(if release_reads.get() == 1 {
                        first
                    } else {
                        second
                    }
                    .into())
                },
                || {
                    version_reads.set(version_reads.get() + 1);
                    Ok(b"Linux version 6.17.0".to_vec())
                },
                || {
                    container_reads.set(container_reads.get() + 1);
                    false
                },
            );
            assert_eq!(info.release.as_deref(), Some(first));
            assert_eq!(info.is_wsl, expected);
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
            let info = detect_kernel(
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
            assert_eq!(info.is_wsl, expected, "{contents:?}");
            assert_eq!(container_reads.get(), u32::from(expected));
        }
    }

    #[test]
    fn uname_errors_preserve_empty_release_and_proc_fallback() {
        let release_reads = Cell::new(0);
        let version_reads = Cell::new(0);
        let info = detect_kernel(
            || {
                release_reads.set(release_reads.get() + 1);
                Err(io::ErrorKind::PermissionDenied.into())
            },
            || {
                version_reads.set(version_reads.get() + 1);
                Ok(b"Linux version Microsoft".to_vec())
            },
            || false,
        );
        assert_eq!(info.release.as_deref(), Some(""));
        assert!(info.is_wsl);
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
            let info = detect_kernel(
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
                info.is_wsl,
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
                let info = detect_kernel(
                    || {
                        release_reads.set(release_reads.get() + 1);
                        Ok("6.17.0".into())
                    },
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
                assert_eq!(info.is_wsl, microsoft && !initial);
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
