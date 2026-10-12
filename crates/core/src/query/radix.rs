//! Shared integer digit parsing with the pinned JavaScriptCore evaluation order.

#[derive(Clone, Copy)]
pub(crate) enum Radix {
    Binary = 2,
    Octal = 8,
    Hexadecimal = 16,
}

impl Radix {
    /// Require the complete input to contain digits from this radix.
    pub(crate) fn parse(self, input: &str) -> Option<f64> {
        let (length, number) = self.scan(input);
        if length != input.len() {
            return None;
        }
        self.finish(input, number)
    }

    /// Stop at the first invalid digit before applying the runtime's overflow path.
    pub(crate) fn parse_prefix(self, input: &str) -> Option<f64> {
        let (length, number) = self.scan(input);
        self.finish(input.split_at(length).0, number)
    }

    fn digit(self, byte: u8) -> Option<u8> {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        (digit < self as u8).then_some(digit)
    }

    fn scan(self, input: &str) -> (usize, f64) {
        let mut length = 0;
        let mut number = 0.0;
        for digit in input.bytes().map_while(|byte| self.digit(byte)) {
            number = number * f64::from(self as u8) + f64::from(digit);
            length += 1;
        }
        (length, number)
    }

    fn finish(self, digits: &str, number: f64) -> Option<f64> {
        if digits.is_empty() {
            return None;
        }
        if number < 9_007_199_254_740_992.0 {
            return Some(number);
        }
        // JSC reparses values at 2^53 from right to left. Complete-integer rounding differs at sticky bits and overflow.
        // Source: oven-sh/WebKit@2e2aa2290fac856d6f451ceacb58f7f5b44dd057, runtime/ParseInt.h, parseIntOverflow.
        let mut number = 0.0;
        let mut multiplier = 1.0_f64;
        for byte in digits.bytes().rev() {
            if multiplier.is_infinite() {
                if byte != b'0' {
                    return Some(f64::INFINITY);
                }
            } else {
                number += f64::from(self.digit(byte)?) * multiplier;
            }
            multiplier *= f64::from(self as u8);
        }
        Some(number)
    }
}

#[cfg(test)]
#[path = "radix_tests.rs"]
mod tests;
