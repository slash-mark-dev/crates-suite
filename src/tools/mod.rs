//! The 25 tools and the trait they share.

use crate::cli::{Args, Opt};
use crate::ctx::Ctx;
use crate::error::Result;
use crate::report::Report;

pub mod apieco_util;
pub mod common;

pub mod anomaly;
pub mod assurance;
pub mod autotraits;
pub mod buildtrace;
pub mod crev;
pub mod csys;
pub mod docscov;
pub mod edition;
pub mod featmatrix;
pub mod features_util;
pub mod features;
pub mod futurecompat;
pub mod miri;
pub mod mono;
pub mod nostd;
pub mod panics;
pub mod perf_util;
pub mod profile;
pub mod pubdeps;
pub mod runtimes;
pub mod srcverify;
pub mod successor;
pub mod supplychain_util;
pub mod targets;
pub mod timings;
pub mod trustpub;
pub mod unsafe_hotspots;
pub mod vet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Group {
    Soundness,
    SupplyChain,
    Features,
    Performance,
    Api,
    Ecosystem,
}

impl Group {
    pub fn title(&self) -> &'static str {
        match self {
            Group::Soundness => "Soundness & safety",
            Group::SupplyChain => "Compile-time supply chain",
            Group::Features => "Features & targets",
            Group::Performance => "Build performance",
            Group::Api => "API & evolution",
            Group::Ecosystem => "Ecosystem intelligence",
        }
    }
    pub const ALL: [Group; 6] =
        [Group::Soundness, Group::SupplyChain, Group::Features, Group::Performance, Group::Api, Group::Ecosystem];
}

pub trait Tool: Sync {
    /// Subcommand name.
    fn name(&self) -> &'static str;
    /// Display title, e.g. "Unsafe Soundness Hotspots".
    fn title(&self) -> &'static str;
    fn group(&self) -> Group;
    /// One-sentence description.
    fn summary(&self) -> &'static str;
    /// Usage line after `sm-crates NAME`, e.g. `[CRATE[@VERSION]...]`.
    fn usage(&self) -> &'static str;
    /// Longer explanation printed by `help NAME` (what it checks, data sources).
    fn about(&self) -> &'static str;
    /// Tool-specific options.
    fn options(&self) -> &'static [Opt] {
        &[]
    }
    /// Example invocations (full command lines starting with `sm-crates`).
    fn examples(&self) -> &'static [&'static str];
    /// What the tool needs besides the network, e.g. "cargo, nightly toolchain with miri".
    fn requires(&self) -> &'static str {
        "network"
    }
    fn run(&self, ctx: &Ctx, args: &Args) -> Result<Report>;
}

/// Every tool, in display order.
pub fn all() -> Vec<&'static dyn Tool> {
    vec![
        // Soundness & safety
        &unsafe_hotspots::UnsafeHotspots,
        &miri::Miri,
        &panics::Panics,
        &autotraits::AutoTraits,
        &assurance::Assurance,
        // Compile-time supply chain
        &buildtrace::BuildTrace,
        &csys::Csys,
        &srcverify::SrcVerify,
        &vet::Vet,
        &crev::Crev,
        // Features & targets
        &featmatrix::FeatMatrix,
        &features::Features,
        &nostd::NoStd,
        &runtimes::Runtimes,
        &targets::Targets,
        // Build performance
        &timings::Timings,
        &mono::Mono,
        &profile::Profile,
        // API & evolution
        &pubdeps::PubDeps,
        &docscov::DocsCov,
        &futurecompat::FutureCompat,
        &edition::Edition,
        // Ecosystem intelligence
        &anomaly::Anomaly,
        &successor::Successor,
        &trustpub::TrustPub,
    ]
}

pub fn find(name: &str) -> Option<&'static dyn Tool> {
    all().into_iter().find(|t| t.name() == name)
}
