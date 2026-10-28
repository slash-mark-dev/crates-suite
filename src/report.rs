//! Tool results and how they are printed.
//!
//! Every tool returns a [`Report`]. The same report renders as text, JSON or
//! Markdown, and its findings decide the exit code through `--fail-on`.

use serde::Serialize;
use serde_json::{Value, json};

use crate::cli::Format;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" | "moderate" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    fn color(&self) -> &'static str {
        match self {
            Severity::Info => "\x1b[36m",
            Severity::Low => "\x1b[34m",
            Severity::Medium => "\x1b[33m",
            Severity::High => "\x1b[31m",
            Severity::Critical => "\x1b[1;31m",
        }
    }
}

/// A source location a finding points at.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Location {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

/// One problem or notable fact a tool found.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine-readable identifier, e.g. `unsafe/set-len-before-init`.
    pub code: String,
    /// The crate this finding is about, if any.
    #[serde(rename = "crate", skip_serializing_if = "Option::is_none")]
    pub krate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Suggested fix or next step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Finding {
    pub fn new(severity: Severity, code: impl Into<String>, message: impl Into<String>) -> Finding {
        Finding {
            severity,
            code: code.into(),
            krate: None,
            version: None,
            message: message.into(),
            detail: None,
            location: None,
            fix: None,
        }
    }
    pub fn krate(mut self, name: impl Into<String>, version: Option<impl Into<String>>) -> Finding {
        self.krate = Some(name.into());
        self.version = version.map(Into::into);
        self
    }
    pub fn detail(mut self, d: impl Into<String>) -> Finding {
        self.detail = Some(d.into());
        self
    }
    pub fn at(mut self, file: impl Into<String>, line: Option<usize>) -> Finding {
        self.location = Some(Location { file: file.into(), line });
        self
    }
    pub fn fix(mut self, f: impl Into<String>) -> Finding {
        self.fix = Some(f.into());
        self
    }
}

/// A table of results.
#[derive(Debug, Clone, Serialize)]
pub struct Table {
    pub title: String,
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(title: impl Into<String>, headers: &[&str]) -> Table {
        Table { title: title.into(), headers: headers.iter().map(|s| s.to_string()).collect(), rows: Vec::new() }
    }
    pub fn row<I, S>(&mut self, cells: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.rows.push(cells.into_iter().map(Into::into).collect());
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// Everything a tool produced.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub tool: String,
    /// What was analyzed: a crate spec, a project path, ...
    pub subject: String,
    /// One-line headline result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub findings: Vec<Finding>,
    pub tables: Vec<Table>,
    pub notes: Vec<String>,
    /// Tool-specific structured data for `--json` consumers.
    pub data: Value,
}

impl Report {
    pub fn new(tool: &str, subject: impl Into<String>) -> Report {
        Report {
            tool: tool.to_string(),
            subject: subject.into(),
            summary: None,
            findings: Vec::new(),
            tables: Vec::new(),
            notes: Vec::new(),
            data: Value::Null,
        }
    }
    pub fn finding(&mut self, f: Finding) {
        self.findings.push(f);
    }
    pub fn table(&mut self, t: Table) {
        self.tables.push(t);
    }
    pub fn note(&mut self, n: impl Into<String>) {
        self.notes.push(n.into());
    }
    pub fn summary(&mut self, s: impl Into<String>) {
        self.summary = Some(s.into());
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Whether the report should make the process exit 1.
    pub fn fails(&self, threshold: Option<Severity>) -> bool {
        match (threshold, self.max_severity()) {
            (Some(t), Some(m)) => m >= t,
            _ => false,
        }
    }

    fn counts(&self) -> [(Severity, usize); 5] {
        let mut c = [
            (Severity::Critical, 0),
            (Severity::High, 0),
            (Severity::Medium, 0),
            (Severity::Low, 0),
            (Severity::Info, 0),
        ];
        for f in &self.findings {
            for e in c.iter_mut() {
                if e.0 == f.severity {
                    e.1 += 1;
                }
            }
        }
        c
    }

    fn sorted_findings(&self) -> Vec<&Finding> {
        let mut v: Vec<&Finding> = self.findings.iter().collect();
        v.sort_by(|a, b| b.severity.cmp(&a.severity));
        v
    }

    pub fn to_json(&self) -> Value {
        let counts: serde_json::Map<String, Value> =
            self.counts().iter().map(|(s, n)| (s.as_str().to_string(), json!(n))).collect();
        json!({
            "tool": self.tool,
            "suite": "sm-crates",
            "version": env!("CARGO_PKG_VERSION"),
            "generated_at": crate::util::now_rfc3339(),
            "subject": self.subject,
            "summary": self.summary,
            "counts": counts,
            "findings": self.sorted_findings(),
            "tables": self.tables,
            "notes": self.notes,
            "data": self.data,
        })
    }

    pub fn render(&self, format: Format, color: bool, quiet: bool) -> String {
        match format {
            Format::Json => serde_json::to_string_pretty(&self.to_json()).unwrap_or_default() + "\n",
            Format::Markdown => self.render_markdown(),
            Format::Text => self.render_text(color, quiet),
        }
    }

    fn render_text(&self, color: bool, quiet: bool) -> String {
        let (b, d, r) = if color { ("\x1b[1m", "\x1b[2m", "\x1b[0m") } else { ("", "", "") };
        let mut out = String::new();
        if !quiet {
            out.push_str(&format!("{b}sm-crates {}{r} {d}·{r} {}\n", self.tool, self.subject));
            if let Some(s) = &self.summary {
                out.push_str(&format!("{s}\n"));
            }
            for t in &self.tables {
                if t.rows.is_empty() {
                    continue;
                }
                out.push('\n');
                if !t.title.is_empty() {
                    out.push_str(&format!("{b}{}{r}\n", t.title));
                }
                out.push_str(&text_table(t, color));
            }
        }
        if !self.findings.is_empty() {
            if !quiet {
                out.push_str(&format!("\n{b}Findings{r}\n"));
            }
            for f in self.sorted_findings() {
                let sev = if color {
                    format!("{}{:<8}{r}", f.severity.color(), f.severity.as_str().to_uppercase())
                } else {
                    format!("{:<8}", f.severity.as_str().to_uppercase())
                };
                let who = match (&f.krate, &f.version) {
                    (Some(k), Some(v)) => format!("{k}@{v}: "),
                    (Some(k), None) => format!("{k}: "),
                    _ => String::new(),
                };
                out.push_str(&format!("{sev} {who}{}  {d}[{}]{r}\n", f.message, f.code));
                if let Some(l) = &f.location {
                    match l.line {
                        Some(n) => out.push_str(&format!("         at {}:{n}\n", l.file)),
                        None => out.push_str(&format!("         at {}\n", l.file)),
                    }
                }
                if let Some(dt) = &f.detail {
                    for line in dt.lines() {
                        out.push_str(&format!("         {d}{line}{r}\n"));
                    }
                }
                if let Some(fx) = &f.fix {
                    out.push_str(&format!("         fix: {fx}\n"));
                }
            }
        }
        if !quiet && !self.notes.is_empty() {
            out.push('\n');
            for n in &self.notes {
                out.push_str(&format!("{d}note: {n}{r}\n"));
            }
        }
        if !quiet {
            let c = self.counts();
            let parts: Vec<String> =
                c.iter().filter(|(_, n)| *n > 0).map(|(s, n)| format!("{n} {}", s.as_str())).collect();
            if parts.is_empty() {
                out.push_str("\nNo findings.\n");
            } else {
                out.push_str(&format!("\n{} finding(s): {}\n", self.findings.len(), parts.join(", ")));
            }
        }
        out
    }

    fn render_markdown(&self) -> String {
        let mut out = format!("## sm-crates {} — {}\n\n", self.tool, md_escape(&self.subject));
        if let Some(s) = &self.summary {
            out.push_str(&format!("{}\n\n", md_escape(s)));
        }
        for t in &self.tables {
            if t.rows.is_empty() {
                continue;
            }
            if !t.title.is_empty() {
                out.push_str(&format!("### {}\n\n", md_escape(&t.title)));
            }
            out.push_str(&format!("| {} |\n", t.headers.iter().map(|h| md_escape(h)).collect::<Vec<_>>().join(" | ")));
            out.push_str(&format!("|{}\n", "---|".repeat(t.headers.len())));
            for row in &t.rows {
                out.push_str(&format!("| {} |\n", row.iter().map(|c| md_escape(c)).collect::<Vec<_>>().join(" | ")));
            }
            out.push('\n');
        }
        if !self.findings.is_empty() {
            out.push_str("### Findings\n\n| Severity | Crate | Finding | Code |\n|---|---|---|---|\n");
            for f in self.sorted_findings() {
                let who = match (&f.krate, &f.version) {
                    (Some(k), Some(v)) => format!("{k}@{v}"),
                    (Some(k), None) => k.clone(),
                    _ => String::new(),
                };
                let mut msg = md_escape(&f.message);
                if let Some(l) = &f.location {
                    msg.push_str(&format!(" (`{}{}`)", l.file, l.line.map(|n| format!(":{n}")).unwrap_or_default()));
                }
                if let Some(fx) = &f.fix {
                    msg.push_str(&format!("<br>Fix: {}", md_escape(fx)));
                }
                out.push_str(&format!("| {} | {} | {} | `{}` |\n", f.severity.as_str(), md_escape(&who), msg, f.code));
            }
            out.push('\n');
        } else {
            out.push_str("No findings.\n\n");
        }
        for n in &self.notes {
            out.push_str(&format!("> {}\n", md_escape(n)));
        }
        out
    }
}

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', "<br>")
}

fn display_width(s: &str) -> usize {
    s.chars().count()
}

fn text_table(t: &Table, color: bool) -> String {
    let cols = t.headers.len();
    let mut w: Vec<usize> = t.headers.iter().map(|h| display_width(h)).collect();
    for row in &t.rows {
        for (i, c) in row.iter().enumerate().take(cols) {
            w[i] = w[i].max(display_width(c).min(70));
        }
    }
    let (d, r) = if color { ("\x1b[2m", "\x1b[0m") } else { ("", "") };
    let fmt_row = |cells: &[String]| -> String {
        let mut line = String::from("  ");
        for (i, c) in cells.iter().enumerate().take(cols) {
            let mut cell: String = c.chars().take(70).collect();
            if display_width(c) > 70 {
                cell.pop();
                cell.push('…');
            }
            if i + 1 == cols {
                line.push_str(&cell);
            } else {
                let pad = w[i].saturating_sub(display_width(&cell));
                line.push_str(&cell);
                line.push_str(&" ".repeat(pad + 2));
            }
        }
        line.trim_end().to_string() + "\n"
    };
    let mut out = format!("{d}{}{r}", fmt_row(&t.headers));
    for row in &t.rows {
        out.push_str(&fmt_row(row));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_threshold() {
        let mut r = Report::new("x", "y");
        assert!(!r.fails(Some(Severity::Low)));
        r.finding(Finding::new(Severity::Medium, "a/b", "m"));
        assert!(r.fails(Some(Severity::Medium)));
        assert!(!r.fails(Some(Severity::High)));
        assert!(!r.fails(None));
    }

    #[test]
    fn renders_all_formats() {
        let mut r = Report::new("unsafe", "serde@1.0.0");
        let mut t = Table::new("Crates", &["Crate", "Count"]);
        t.row(["serde", "3"]);
        r.table(t);
        r.finding(Finding::new(Severity::High, "x/y", "bad | thing").krate("serde", Some("1.0.0")).at("src/lib.rs", Some(4)));
        let txt = r.render(Format::Text, false, false);
        assert!(txt.contains("HIGH") && txt.contains("serde@1.0.0") && txt.contains("src/lib.rs:4"), "{txt}");
        let md = r.render(Format::Markdown, false, false);
        assert!(md.contains("bad \\| thing"), "{md}");
        let js: Value = serde_json::from_str(&r.render(Format::Json, false, false)).unwrap();
        assert_eq!(js["counts"]["high"], 1);
        assert_eq!(js["findings"][0]["crate"], "serde");
    }
}
