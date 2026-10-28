//! Command-line parsing shared by every tool.
//!
//! Each tool declares its options as a static list of [`Opt`]. The parser
//! rejects unknown flags, so typos fail loudly instead of being ignored.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::report::Severity;

/// One command-line option a tool accepts.
#[derive(Debug, Clone, Copy)]
pub struct Opt {
    /// Long name without the leading `--`.
    pub name: &'static str,
    /// Optional one-letter short form without the leading `-`.
    pub short: Option<char>,
    /// Placeholder for the value (`None` means the option is a boolean flag).
    pub value: Option<&'static str>,
    /// One-line help text.
    pub help: &'static str,
}

impl Opt {
    pub const fn flag(name: &'static str, help: &'static str) -> Opt {
        Opt { name, short: None, value: None, help }
    }
    pub const fn value(name: &'static str, value: &'static str, help: &'static str) -> Opt {
        Opt { name, short: None, value: Some(value), help }
    }
}

/// Options every tool accepts.
pub const GLOBAL_OPTS: &[Opt] = &[
    Opt { name: "json", short: None, value: None, help: "Print machine-readable JSON instead of text" },
    Opt { name: "markdown", short: None, value: None, help: "Print a Markdown report (for PR comments and job summaries)" },
    Opt {
        name: "fail-on",
        short: None,
        value: Some("LEVEL"),
        help: "Exit 1 when a finding is at or above LEVEL: info, low, medium, high (default), critical, none",
    },
    Opt { name: "project", short: Some('p'), value: Some("DIR"), help: "Project directory containing Cargo.toml (default: current directory)" },
    Opt { name: "offline", short: None, value: None, help: "Use only cached data; never touch the network" },
    Opt { name: "refresh", short: None, value: None, help: "Ignore cached responses and fetch fresh data" },
    Opt { name: "no-color", short: None, value: None, help: "Disable colored output (also honors NO_COLOR)" },
    Opt { name: "quiet", short: Some('q'), value: None, help: "Only print findings, no tables or notes" },
    Opt { name: "help", short: Some('h'), value: None, help: "Show help for this tool" },
];

/// Output format selected on the command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Markdown,
}

/// Parsed arguments for one tool invocation.
#[derive(Debug, Clone, Default)]
pub struct Args {
    pub positional: Vec<String>,
    values: BTreeMap<String, Vec<String>>,
    flags: BTreeMap<String, bool>,
}

impl Args {
    /// Parse `argv` (everything after the tool name) against the tool's options plus the global ones.
    pub fn parse(argv: &[String], tool_opts: &[Opt]) -> Result<Args> {
        let mut args = Args::default();
        let all: Vec<&Opt> = tool_opts.iter().chain(GLOBAL_OPTS.iter()).collect();
        let find_long = |n: &str| all.iter().find(|o| o.name == n).copied();
        let find_short = |c: char| all.iter().find(|o| o.short == Some(c)).copied();
        let mut i = 0;
        let mut only_positional = false;
        while i < argv.len() {
            let a = &argv[i];
            i += 1;
            if only_positional {
                args.positional.push(a.clone());
                continue;
            }
            if a == "--" {
                only_positional = true;
                continue;
            }
            let (opt, inline): (&Opt, Option<String>) = if let Some(rest) = a.strip_prefix("--") {
                let (name, inline) = match rest.split_once('=') {
                    Some((n, v)) => (n, Some(v.to_string())),
                    None => (rest, None),
                };
                match find_long(name) {
                    Some(o) => (o, inline),
                    None => return Err(Error::Usage(format!("unknown option --{name}{}", suggest(name, &all)))),
                }
            } else if a.len() == 2 && a.starts_with('-') && a != "-" {
                let c = a.chars().nth(1).unwrap_or('?');
                match find_short(c) {
                    Some(o) => (o, None),
                    None => return Err(Error::Usage(format!("unknown option {a}"))),
                }
            } else {
                args.positional.push(a.clone());
                continue;
            };
            match opt.value {
                None => {
                    if inline.is_some() {
                        return Err(Error::Usage(format!("--{} does not take a value", opt.name)));
                    }
                    args.flags.insert(opt.name.to_string(), true);
                }
                Some(ph) => {
                    let v = match inline {
                        Some(v) => v,
                        None => {
                            if i >= argv.len() {
                                return Err(Error::Usage(format!("--{} needs a value ({ph})", opt.name)));
                            }
                            i += 1;
                            argv[i - 1].clone()
                        }
                    };
                    args.values.entry(opt.name.to_string()).or_default().push(v);
                }
            }
        }
        Ok(args)
    }

    /// Whether a boolean flag was given.
    pub fn flag(&self, name: &str) -> bool {
        self.flags.get(name).copied().unwrap_or(false)
    }

    /// Last value given for an option.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).and_then(|v| v.last()).map(|s| s.as_str())
    }

    /// All values given for an option, with comma-separated lists split apart.
    pub fn list(&self, name: &str) -> Vec<String> {
        self.values
            .get(name)
            .map(|vs| {
                vs.iter()
                    .flat_map(|v| v.split(','))
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Parse an option value, with a default when it is absent.
    pub fn parse_or<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T> {
        match self.value(name) {
            None => Ok(default),
            Some(v) => v.parse::<T>().map_err(|_| Error::Usage(format!("invalid value for --{name}: {v}"))),
        }
    }

    pub fn format(&self) -> Format {
        if self.flag("json") {
            Format::Json
        } else if self.flag("markdown") {
            Format::Markdown
        } else {
            Format::Text
        }
    }

    /// The `--fail-on` threshold; `None` means never fail on findings.
    pub fn fail_on(&self) -> Result<Option<Severity>> {
        match self.value("fail-on") {
            None => Ok(Some(Severity::High)),
            Some("none") | Some("never") => Ok(None),
            Some(v) => Severity::parse(v)
                .map(Some)
                .ok_or_else(|| Error::Usage(format!("invalid --fail-on level '{v}' (use info, low, medium, high, critical or none)"))),
        }
    }

    /// Test helper and programmatic use: set a flag.
    pub fn set_flag(&mut self, name: &str) {
        self.flags.insert(name.to_string(), true);
    }

    /// Test helper and programmatic use: set a value.
    pub fn set_value(&mut self, name: &str, v: &str) {
        self.values.insert(name.to_string(), vec![v.to_string()]);
    }
}

fn suggest(name: &str, opts: &[&Opt]) -> String {
    let best = opts
        .iter()
        .map(|o| (crate::util::edit_distance(name, o.name), o.name))
        .min_by_key(|(d, _)| *d);
    match best {
        Some((d, n)) if d <= 2 => format!(" (did you mean --{n}?)"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTS: &[Opt] = &[Opt::value("depth", "N", "depth"), Opt::flag("all", "all")];

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parses_values_flags_and_positionals() {
        let a = Args::parse(&v(&["serde@1.0.0", "--depth", "3", "--all", "--json", "x", "--fail-on=medium"]), OPTS).unwrap();
        assert_eq!(a.positional, v(&["serde@1.0.0", "x"]));
        assert_eq!(a.value("depth"), Some("3"));
        assert!(a.flag("all"));
        assert_eq!(a.format(), Format::Json);
        assert_eq!(a.fail_on().unwrap(), Some(Severity::Medium));
    }

    #[test]
    fn rejects_unknown_and_suggests() {
        let e = Args::parse(&v(&["--dept", "3"]), OPTS).unwrap_err();
        assert!(e.to_string().contains("did you mean --depth"), "{e}");
    }

    #[test]
    fn splits_comma_lists_and_short_project() {
        let a = Args::parse(&v(&["-p", "dir", "--depth", "1,2", "--depth", "3"]), OPTS).unwrap();
        assert_eq!(a.value("project"), Some("dir"));
        assert_eq!(a.list("depth"), v(&["1", "2", "3"]));
    }

    #[test]
    fn fail_on_none() {
        let a = Args::parse(&v(&["--fail-on", "none"]), OPTS).unwrap();
        assert_eq!(a.fail_on().unwrap(), None);
        assert!(Args::parse(&v(&["--fail-on", "bogus"]), OPTS).unwrap().fail_on().is_err());
    }

    #[test]
    fn double_dash_ends_options() {
        let a = Args::parse(&v(&["--", "--all"]), OPTS).unwrap();
        assert_eq!(a.positional, v(&["--all"]));
        assert!(!a.flag("all"));
    }
}
