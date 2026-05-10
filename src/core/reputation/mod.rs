pub mod providers;
pub mod manager;
pub mod aggregator;

#[cfg(test)]
mod tests;

pub use aggregator::{CachedReputation, ReputationAggregator, ReputationAggregatorConfig};
pub use manager::ReputationManager;
pub use providers::{
    AbuseIPDBProvider, GreyNoiseProvider, IPInfoProvider, ReputationProvider, SpamhausProvider,
    VirusTotalProvider,
};