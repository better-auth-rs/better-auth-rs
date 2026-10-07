use std::{fs, io, sync::OnceLock};

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
