//! Pure compatibility helpers for the upstream pad-spec format.

use php2shell_core::Error;
use serde_json::{Value, json};

pub fn bookworm_pads() -> Vec<(u32, u32)> {
    vec![(31, 31); 6]
}

pub fn lab_pads() -> Vec<(u32, u32)> {
    let mut pads = vec![(8, 7)];
    pads.extend(vec![(7, 7); 5]);
    pads
}

/// Parses `None`/`bookworm`/`lab` or an explicit `a:bxN,a:b,...` spec.
pub fn parse_pads(spec: Option<&str>) -> std::result::Result<Vec<(u32, u32)>, Error> {
    match spec.map(str::trim) {
        None | Some("") | Some("bookworm") => Ok(bookworm_pads()),
        Some("lab") => Ok(lab_pads()),
        Some(spec) => {
            let mut pads = Vec::new();
            for group in spec.split(',') {
                let group = group.trim();
                if group.is_empty() {
                    return Err(Error::Config("empty group in pad spec".into()));
                }
                let (pair, count) = match group.split_once('x') {
                    Some((pair, count)) => {
                        let count = count.parse::<usize>().map_err(|_| {
                            Error::Config(format!("invalid pad repetition: {count}"))
                        })?;
                        if count == 0 {
                            return Err(Error::Config("pad repetition must be positive".into()));
                        }
                        (pair, count)
                    }
                    None => (group, 1),
                };
                let (left, right) = pair
                    .split_once(':')
                    .ok_or_else(|| Error::Config(format!("invalid pad pair: {pair}")))?;
                let left = left
                    .parse::<u32>()
                    .map_err(|_| Error::Config(format!("invalid pad value: {left}")))?;
                let right = right
                    .parse::<u32>()
                    .map_err(|_| Error::Config(format!("invalid pad value: {right}")))?;
                pads.extend(std::iter::repeat_n((left, right), count));
            }
            Ok(pads)
        }
    }
}

/// Serialises pads back into the compact upstream spec.
pub fn pads_to_spec(pads: &[(u32, u32)]) -> String {
    let mut groups: Vec<String> = Vec::new();
    let mut index = 0;
    while index < pads.len() {
        let pair = pads[index];
        let mut count = 1;
        while index + count < pads.len() && pads[index + count] == pair {
            count += 1;
        }
        groups.push(if count == 1 {
            format!("{}:{}", pair.0, pair.1)
        } else {
            format!("{}:{}x{}", pair.0, pair.1, count)
        });
        index += count;
    }
    groups.join(",")
}

/// Mirrors upstream `stage3_profile_json` for the chosen pad layout.
pub fn stage3_profile_json(spec: Option<&str>) -> std::result::Result<Value, Error> {
    let pads = parse_pads(spec)?;
    let carrier = spec.map(str::trim) != Some("lab");
    Ok(json!({
        "stage3_pads": pads.iter().map(|(a, b)| vec![a, b]).collect::<Vec<_>>(),
        "stage3_carrier": carrier,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_preserved() {
        assert_eq!(parse_pads(None).unwrap(), bookworm_pads());
        assert_eq!(parse_pads(Some("bookworm")).unwrap(), vec![(31, 31); 6]);
        assert_eq!(parse_pads(Some("lab")).unwrap().first(), Some(&(8, 7)));
    }

    #[test]
    fn explicit_spec_with_repetition() {
        let pads = parse_pads(Some("4:4x5,31:31x6")).unwrap();
        assert_eq!(
            pads,
            vec![(4, 4); 5]
                .into_iter()
                .chain(vec![(31, 31); 6])
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn bad_spec_is_rejected() {
        assert!(parse_pads(Some("4:4x")).is_err());
        assert!(parse_pads(Some("nonsense")).is_err());
    }

    #[test]
    fn spec_round_trips() {
        let pads = parse_pads(Some("4:4x5,31:31x6")).unwrap();
        assert_eq!(pads_to_spec(&pads), "4:4x5,31:31x6");
    }

    #[test]
    fn profile_json_matches_upstream() {
        let bookworm = stage3_profile_json(Some("bookworm")).unwrap();
        assert_eq!(bookworm["stage3_carrier"], true);
        assert_eq!(bookworm["stage3_pads"][0], json!([31, 31]));
        let lab = stage3_profile_json(Some("lab")).unwrap();
        assert_eq!(lab["stage3_carrier"], false);
        assert_eq!(lab["stage3_pads"][0], json!([8, 7]));
    }
}
