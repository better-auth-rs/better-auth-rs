//! Linux CPU policies from Bun 1.4.2, commit 744846f844374847c902b5e7fd59b4342a51ef99.
//! See `src/runtime/node/node_os.rs`, `src/js/node/os.ts`, and `src/bun_core/fmt.rs` upstream.

use std::{io, sync::OnceLock};

#[derive(Debug)]
pub(in crate::observability::telemetry) struct CpuInfo {
    pub(in crate::observability::telemetry) count: u32,
    /// None preserves an absent model property in a readable CPU inventory.
    pub(in crate::observability::telemetry) model: Option<String>,
    pub(in crate::observability::telemetry) speed: f64,
}

#[cfg(target_os = "linux")]
pub(in crate::observability::telemetry) fn probe() -> io::Result<CpuInfo> {
    static COUNT: OnceLock<u32> = OnceLock::new();
    // Rust samples count on first use; Bun samples count when its OS binding loads.
    detect(&COUNT, online_count, read_optional)
}

#[cfg(target_os = "linux")]
fn online_count() -> u32 {
    // Bun clamps unsupported, failed, and nonpositive sysconf results to one.
    let count = nix::unistd::sysconf(nix::unistd::SysconfVar::_NPROCESSORS_ONLN)
        .ok()
        .flatten()
        .unwrap_or(1);
    u32::try_from(count).unwrap_or(1).max(1)
}

#[cfg(target_os = "linux")]
fn read_optional(path: &str) -> io::Result<Option<Vec<u8>>> {
    use std::io::Read;

    // Only open failures select upstream defaults; failures after opening propagate.
    let Ok(mut file) = std::fs::File::open(path) else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn detect(
    cached_count: &OnceLock<u32>,
    mut online: impl FnMut() -> u32,
    mut read: impl FnMut(&str) -> io::Result<Option<Vec<u8>>>,
) -> io::Result<CpuInfo> {
    let count = *cached_count.get_or_init(&mut online);
    let Some(stat) = read("/proc/stat")? else {
        // Bun resamples its stub array length; telemetry already captured the cached count.
        let _stub_count = online();
        return Ok(CpuInfo {
            count,
            model: Some("unknown".into()),
            speed: 0.0,
        });
    };
    let populated_count = stat_count(&stat)?;
    let model = match read("/proc/cpuinfo")? {
        Some(info) => first_model(&info, populated_count)?,
        None => Some("unknown".into()),
    };
    let mut speed = 0.0;
    for index in 0..populated_count {
        let path = format!("/sys/devices/system/cpu/cpu{index}/cpufreq/scaling_cur_freq");
        let current = read(&path)?.as_deref().map_or(0.0, frequency);
        if index == 0 {
            speed = current;
        }
    }
    if populated_count == 0 {
        // Bun's lazy CPU-0 getter throws after population replaces the array with an empty array.
        return Err(invalid("the populated CPU inventory is empty"));
    }
    Ok(CpuInfo {
        count,
        model,
        speed,
    })
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
}

fn stat_count(bytes: &[u8]) -> io::Result<u32> {
    let mut count = 0_u32;
    for line in lines(bytes).skip(1) {
        let mut fields = line
            .split(|byte| matches!(byte, b' ' | b'\t'))
            .filter(|field| !field.is_empty());
        if !fields.next().is_some_and(|name| name.starts_with(b"cpu")) {
            break;
        }
        // Times are not emitted, but malformed times still fail upstream CPU population.
        for index in 0..6 {
            let value = fields.next().ok_or_else(|| invalid("missing CPU time"))?;
            if index != 4 && decimal(value).is_none() {
                return Err(invalid("invalid CPU time"));
            }
        }
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("CPU inventory exceeds the upstream index range"))?;
    }
    Ok(count)
}

fn first_model(bytes: &[u8], count: u32) -> io::Result<Option<String>> {
    let mut index = 0;
    let mut has_model = true;
    let mut first = None;
    for line in lines(bytes) {
        if let Some(digits) = line.strip_prefix(b"processor\t: ") {
            if !has_model && index == 0 {
                first = Some("unknown".into());
            }
            index = decimal(trim(digits, b" \t\n"))
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| invalid("invalid CPU index"))?;
            if index >= count {
                return Err(invalid("CPU index exceeds the populated inventory"));
            }
            has_model = false;
        } else if let Some(model) = line.strip_prefix(b"model name\t: ") {
            if count == 0 {
                return Err(invalid("CPU model has no populated CPU"));
            }
            if index == 0 {
                first = Some(String::from_utf8_lossy(model).into_owned());
            }
            has_model = true;
        }
    }
    if !has_model && index == 0 {
        first = Some("unknown".into());
    }
    Ok(first)
}

fn frequency(bytes: &[u8]) -> f64 {
    let digits = trim(bytes, b" \n");
    // Bun divides integer kHz before converting the result to a JavaScript number.
    (decimal(digits).unwrap_or(0) / 1000) as f64
}

fn trim<'a>(mut bytes: &'a [u8], characters: &[u8]) -> &'a [u8] {
    while let Some((first, rest)) = bytes.split_first()
        && characters.contains(first)
    {
        bytes = rest;
    }
    while let Some((last, rest)) = bytes.split_last()
        && characters.contains(last)
    {
        bytes = rest;
    }
    bytes
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    let (first, rest) = bytes.split_first()?;
    let (negative, digits) = match first {
        b'+' => (false, rest),
        b'-' => (true, rest),
        _ => (false, bytes),
    };
    if digits.is_empty() || digits.first() == Some(&b'_') || digits.last() == Some(&b'_') {
        return None;
    }
    let value = digits.iter().try_fold(0_u64, |value, byte| {
        if *byte == b'_' {
            return Some(value);
        }
        let digit = byte.checked_sub(b'0').filter(|digit| *digit < 10)?;
        value.checked_mul(10)?.checked_add(u64::from(digit))
    })?;
    (!negative || value == 0).then_some(value)
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Policy tests propagate setup errors and assert source-derived parser and probe behavior"
)]
mod tests {
    use std::cell::Cell;

    use super::*;

    const STAT: &[u8] = b"cpu aggregate\ncpu0 1 2 3 4 ignored 6\ncpu1 1 2 3 4 5 6\nintr 7\n";
    const CPU0: &str = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq";
    const CPU1: &str = "/sys/devices/system/cpu/cpu1/cpufreq/scaling_cur_freq";

    fn fixture(path: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(Some(match path {
            "/proc/stat" => STAT.to_vec(),
            "/proc/cpuinfo" => b"processor\t: 0\nmodel name\t: CPU A\nprocessor\t: 1\n".to_vec(),
            CPU0 => b"2500999\n".to_vec(),
            CPU1 => b"invalid\n".to_vec(),
            _ => return Err(invalid("unexpected probe path")),
        }))
    }

    #[test]
    fn decimal_and_frequency_keep_bun_grammar_and_integer_division() {
        for (input, parsed) in [
            (&b"+2__400_999"[..], Some(2_400_999)),
            (&b"-0"[..], Some(0)),
            (&b"18446744073709551615"[..], Some(u64::MAX)),
            (&b"18446744073709551616"[..], None),
            (&b"-1"[..], None),
            (&b"_1"[..], None),
            (&b"1_"[..], None),
            (&b"0x10"[..], None),
            (&b"1e6"[..], None),
            (&b"1.5"[..], None),
            (&b"+"[..], None),
            (&b"\xff"[..], None),
            (&b""[..], None),
        ] {
            assert_eq!(decimal(input), parsed, "{input:?}");
        }
        for (input, expected) in [
            (&b" \n+2__400_999\n "[..], 2400.0),
            (&b"999"[..], 0.0),
            (&b"\t2400000\n"[..], 0.0),
            (&b"2400000\r\n"[..], 0.0),
            (&b"2400000 1"[..], 0.0),
            (&b"18446744073709551615"[..], 18_446_744_073_709_552.0),
        ] {
            assert_eq!(frequency(input), expected, "{input:?}");
        }
    }

    #[test]
    fn stat_validates_times_and_stops_at_the_first_non_cpu_line() -> io::Result<()> {
        assert_eq!(stat_count(STAT)?, 2);
        assert_eq!(
            stat_count(b"aggregate\ncpuX\t1 2 3 4 any 6\nstop\ncpu9\n")?,
            1
        );
        assert_eq!(stat_count(b"\naggregate\n\n")?, 0);
        assert!(stat_count(b"aggregate\ncpu0 1 2 3 4 5\n").is_err());
        assert!(stat_count(b"aggregate\ncpu0 1 2 3 4 5 invalid\n").is_err());
        Ok(())
    }

    #[test]
    fn model_preserves_missing_empty_whitespace_and_section_updates() -> io::Result<()> {
        for (input, expected) in [
            (&b""[..], None),
            (&b"processor\t: 0\n"[..], Some("unknown")),
            (&b"processor\t: 1\n"[..], None),
            (&b"processor : 0\nmodel name : ignored\n"[..], None),
            (&b"processor\t: +0_0 \t\nmodel name\t: \n"[..], Some("")),
            (&b"model name\t:  CPU\t\r\n"[..], Some(" CPU\t\r")),
            (&b"model name\t: A\nmodel name\t: B\n"[..], Some("B")),
            (
                &b"processor\t: 0\nmodel name\t: A\nprocessor\t: 0\n"[..],
                Some("unknown"),
            ),
            (
                &b"processor\t: 0\nmodel name\t: \xffCPU\n"[..],
                Some("\u{fffd}CPU"),
            ),
        ] {
            assert_eq!(first_model(input, 2)?.as_deref(), expected, "{input:?}");
        }
        for input in [
            &b"processor\t: 2\n"[..],
            &b"processor\t: -1\n"[..],
            &b"processor\t: 4294967296\n"[..],
            &b"processor\t: 0\r\n"[..],
        ] {
            assert!(first_model(input, 2).is_err(), "{input:?}");
        }
        Ok(())
    }

    #[test]
    fn stat_open_failure_resamples_stub_count_without_later_probes() -> io::Result<()> {
        let cached = OnceLock::new();
        let counts = Cell::new(0);
        let mut paths = Vec::new();
        for _ in 0..2 {
            let info = detect(
                &cached,
                || {
                    counts.set(counts.get() + 1);
                    counts.get() * 4
                },
                |path| {
                    paths.push(path.to_owned());
                    Ok(None)
                },
            )?;
            assert_eq!(info.count, 4);
            assert_eq!(info.model.as_deref(), Some("unknown"));
            assert_eq!(info.speed, 0.0);
        }
        assert_eq!(counts.get(), 3);
        assert_eq!(paths, ["/proc/stat", "/proc/stat"]);
        Ok(())
    }

    #[test]
    fn read_errors_from_every_cpu_propagate_and_missing_files_use_defaults() -> io::Result<()> {
        let paths = ["/proc/stat", "/proc/cpuinfo", CPU0, CPU1];
        for failed in paths {
            let mut visited = Vec::new();
            let result = detect(
                &OnceLock::new(),
                || 4,
                |path| {
                    visited.push(path.to_owned());
                    if path == failed {
                        Err(io::ErrorKind::BrokenPipe.into())
                    } else {
                        fixture(path)
                    }
                },
            );
            assert_eq!(
                result.err().map(|error| error.kind()),
                Some(io::ErrorKind::BrokenPipe)
            );
            assert_eq!(visited.last().map(String::as_str), Some(failed));
        }
        let info = detect(
            &OnceLock::new(),
            || 4,
            |path| {
                if path == "/proc/cpuinfo" || path == CPU0 {
                    Ok(None)
                } else {
                    fixture(path)
                }
            },
        )?;
        assert_eq!(info.model.as_deref(), Some("unknown"));
        assert_eq!(info.speed, 0.0);
        Ok(())
    }

    #[test]
    fn population_repeats_but_count_keeps_its_first_sample() -> io::Result<()> {
        let cached = OnceLock::new();
        let counts = Cell::new(0);
        let mut paths = Vec::new();
        for (model, speed) in [("CPU A", 2500), ("CPU B", 2700)] {
            let info = detect(
                &cached,
                || {
                    counts.set(counts.get() + 1);
                    8
                },
                |path| {
                    paths.push(path.to_owned());
                    match path {
                        "/proc/cpuinfo" => {
                            Ok(Some(format!("model name\t: {model}\n").into_bytes()))
                        }
                        CPU0 => Ok(Some(format!("{}\n", speed * 1000).into_bytes())),
                        _ => fixture(path),
                    }
                },
            )?;
            assert_eq!(info.count, 8);
            assert_eq!(info.model.as_deref(), Some(model));
            assert_eq!(info.speed, f64::from(speed));
        }
        assert_eq!(counts.get(), 1);
        assert_eq!(paths, ["/proc/stat", "/proc/cpuinfo", CPU0, CPU1].repeat(2));
        assert!(detect(&OnceLock::new(), || 1, |_| Ok(Some(Vec::new()))).is_err());
        Ok(())
    }
}
