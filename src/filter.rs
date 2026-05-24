use std::cmp::Ordering;

use anyhow::{Result, anyhow};
use serde::Deserialize;

use crate::model::{LogicalServer, PhysicalServer};
use crate::session::UserSession;

#[derive(Clone, Copy, Debug)]
pub struct FeatureMask;

impl FeatureMask {
    pub const SECURE_CORE: u64 = 1;
    pub const TOR: u64 = 2;
    pub const P2P: u64 = 4;
    pub const STREAM: u64 = 8;
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct FeatureFilter {
    #[serde(default)]
    pub secure_core: Option<bool>,
    #[serde(default)]
    pub p2p: Option<bool>,
    #[serde(default)]
    pub tor: Option<bool>,
    #[serde(default)]
    pub stream: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum CountryFilter {
    One(String),
    Many(Vec<String>),
}

impl CountryFilter {
    fn contains(&self, value: &str) -> bool {
        match self {
            Self::One(country) => country.eq_ignore_ascii_case(value),
            Self::Many(countries) => countries
                .iter()
                .any(|country| country.eq_ignore_ascii_case(value)),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SortMode {
    #[default]
    LoadAsc,
    ScoreDesc,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct ServerFilter {
    #[serde(default)]
    pub country: Option<CountryFilter>,
    #[serde(default)]
    pub city: Option<String>,
    #[serde(default)]
    pub tier: Option<String>,
    #[serde(default)]
    pub features: Option<FeatureFilter>,
    #[serde(default)]
    pub max_load: Option<u8>,
    #[serde(default)]
    pub status: Option<i32>,
    #[serde(default)]
    pub sort_by: SortMode,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SelectedTarget {
    pub logical: LogicalServer,
    pub physical: PhysicalServer,
}

pub fn select_target(
    servers: &[LogicalServer],
    filter: &ServerFilter,
    session: &UserSession,
) -> Result<SelectedTarget> {
    let requested_tier = filter
        .tier
        .as_deref()
        .unwrap_or(session.account_tier.as_str());
    let max_tier = tier_to_proton_value(requested_tier)?;
    let account_tier = tier_to_proton_value(&session.account_tier)?;
    let effective_tier = max_tier.min(account_tier);

    let mut candidates = Vec::new();
    for logical in servers {
        if !logical_matches(logical, filter, effective_tier) {
            continue;
        }

        for physical in &logical.servers {
            if physical.status == 0 || physical.services_down.unwrap_or(0) > 0 {
                continue;
            }

            candidates.push(SelectedTarget {
                logical: logical.clone(),
                physical: physical.clone(),
            });
        }
    }

    candidates.sort_by(|left, right| compare_candidates(left, right, &filter.sort_by));
    candidates.into_iter().next().ok_or_else(|| {
        anyhow!(
            "no Proton server matched the requested filter for {}",
            session.username
        )
    })
}

pub fn tier_to_proton_value(tier: &str) -> Result<u8> {
    match tier.trim().to_ascii_lowercase().as_str() {
        "free" => Ok(0),
        "basic" => Ok(1),
        "plus" | "visionary" => Ok(2),
        other => Err(anyhow!("unsupported Proton tier '{other}'")),
    }
}

fn logical_matches(logical: &LogicalServer, filter: &ServerFilter, max_tier: u8) -> bool {
    if let Some(country) = &filter.country
        && !country.contains(&logical.exit_country)
    {
        return false;
    }

    if let Some(city) = &filter.city
        && logical
            .city
            .as_deref()
            .map(|value| !value.eq_ignore_ascii_case(city))
            .unwrap_or(true)
    {
        return false;
    }

    if logical.tier > max_tier {
        return false;
    }

    if let Some(max_load) = filter.max_load
        && logical.load > max_load
    {
        return false;
    }

    if let Some(status) = filter.status
        && logical.status != status
    {
        return false;
    }

    filter
        .features
        .as_ref()
        .map(|features| feature_matches(logical.features, features))
        .unwrap_or(true)
}

fn feature_matches(mask: u64, filter: &FeatureFilter) -> bool {
    feature_value_matches(mask, FeatureMask::SECURE_CORE, filter.secure_core)
        && feature_value_matches(mask, FeatureMask::P2P, filter.p2p)
        && feature_value_matches(mask, FeatureMask::TOR, filter.tor)
        && feature_value_matches(mask, FeatureMask::STREAM, filter.stream)
}

fn feature_value_matches(mask: u64, flag: u64, requested: Option<bool>) -> bool {
    match requested {
        Some(true) => mask & flag != 0,
        Some(false) => mask & flag == 0,
        None => true,
    }
}

fn compare_candidates(
    left: &SelectedTarget,
    right: &SelectedTarget,
    sort_mode: &SortMode,
) -> Ordering {
    match sort_mode {
        SortMode::LoadAsc => candidate_load(left)
            .cmp(&candidate_load(right))
            .then_with(|| right.logical.score.total_cmp(&left.logical.score)),
        SortMode::ScoreDesc => right
            .logical
            .score
            .total_cmp(&left.logical.score)
            .then_with(|| candidate_load(left).cmp(&candidate_load(right))),
    }
}

fn candidate_load(candidate: &SelectedTarget) -> u8 {
    candidate.physical.load.unwrap_or(candidate.logical.load)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::UserSession;

    #[test]
    fn maps_human_tiers() {
        assert_eq!(tier_to_proton_value("Free").unwrap(), 0);
        assert_eq!(tier_to_proton_value("Basic").unwrap(), 1);
        assert_eq!(tier_to_proton_value("Plus").unwrap(), 2);
        assert_eq!(tier_to_proton_value("Visionary").unwrap(), 2);
    }

    #[test]
    fn selects_lowest_load_matching_server() {
        let session = UserSession::new("alice@example.com", "Plus");
        let filter = ServerFilter {
            country: Some(CountryFilter::Many(vec!["NL".into(), "CH".into()])),
            city: Some("Amsterdam".into()),
            tier: Some("Plus".into()),
            features: Some(FeatureFilter {
                secure_core: Some(false),
                p2p: Some(true),
                tor: Some(false),
                stream: None,
            }),
            max_load: Some(75),
            status: Some(1),
            sort_by: SortMode::LoadAsc,
        };

        let selected = select_target(&sample_servers(), &filter, &session).unwrap();
        assert_eq!(selected.logical.name, "NL#2");
        assert_eq!(selected.physical.name, "nl-physical-2");
    }

    fn sample_servers() -> Vec<LogicalServer> {
        vec![
            LogicalServer {
                id: "1".into(),
                name: "NL#1".into(),
                entry_country: Some("NL".into()),
                exit_country: "NL".into(),
                domain: None,
                city: Some("Amsterdam".into()),
                region: None,
                tier: 2,
                features: FeatureMask::P2P,
                load: 66,
                score: 1.0,
                status: 1,
                servers: vec![PhysicalServer {
                    id: "p1".into(),
                    name: "nl-physical-1".into(),
                    entry_ip: Some("203.0.113.1".into()),
                    entry_ipv6: None,
                    entry_per_protocol: Default::default(),
                    exit_ip: None,
                    domain: None,
                    label: None,
                    status: 1,
                    load: Some(66),
                    public_key: Some("key1".into()),
                    generation: None,
                    services_down: Some(0),
                    services_down_reason: None,
                }],
            },
            LogicalServer {
                id: "2".into(),
                name: "NL#2".into(),
                entry_country: Some("NL".into()),
                exit_country: "NL".into(),
                domain: None,
                city: Some("Amsterdam".into()),
                region: None,
                tier: 2,
                features: FeatureMask::P2P,
                load: 30,
                score: 0.7,
                status: 1,
                servers: vec![PhysicalServer {
                    id: "p2".into(),
                    name: "nl-physical-2".into(),
                    entry_ip: Some("203.0.113.2".into()),
                    entry_ipv6: None,
                    entry_per_protocol: Default::default(),
                    exit_ip: None,
                    domain: None,
                    label: None,
                    status: 1,
                    load: Some(30),
                    public_key: Some("key2".into()),
                    generation: None,
                    services_down: Some(0),
                    services_down_reason: None,
                }],
            },
        ]
    }
}
