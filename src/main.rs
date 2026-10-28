#![allow(dead_code)] // shared helpers kept for future tools
//! sm-crates: the Slash Mark Crates.io Suite.

mod cli;
mod ctx;
mod error;
mod http;
mod project;
mod registry;
mod report;
mod rustsrc;
mod tools;
mod util;

use std::io::Write;

use cli::{Args, GLOBAL_OPTS, Opt};
use error::exit;
use tools::{Group, Tool};

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&argv);
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

fn run(argv: &[String]) -> i32 {
    let Some(first) = argv.first() else {
        print!("{}", main_help());
        return exit::OK;
    };
    match first.as_str() {
        "-h" | "--help" => {
            print!("{}", main_help());
            exit::OK
        }
        "-V" | "--version" | "version" => {
            println!("sm-crates {}", env!("CARGO_PKG_VERSION"));
            exit::OK
        }
        "help" => match argv.get(1) {
            None => {
                print!("{}", main_help());
                exit::OK
            }
            Some(name) => match tools::find(name) {
                Some(t) => {
                    print!("{}", tool_help(t));
                    exit::OK
                }
                None => unknown(name),
            },
        },
        "list" => {
            let json = argv.iter().any(|a| a == "--json");
            if json {
                let v: Vec<serde_json::Value> = tools::all()
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "name": t.name(), "title": t.title(), "group": t.group().title(),
                            "summary": t.summary(), "requires": t.requires(), "examples": t.examples(),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                for t in tools::all() {
                    println!("{:<14}{}", t.name(), t.summary());
                }
            }
            exit::OK
        }
        name => match tools::find(name) {
            Some(t) => run_tool(t, &argv[1..]),
            None => unknown(name),
        },
    }
}

fn unknown(name: &str) -> i32 {
    let best = tools::all()
        .into_iter()
        .map(|t| (util::edit_distance(name, t.name()), t.name()))
        .min_by_key(|(d, _)| *d)
        .filter(|(d, _)| *d <= 3)
        .map(|(_, n)| format!(" Did you mean `{n}`?"))
        .unwrap_or_default();
    eprintln!("error: unknown tool `{name}`.{best} Run `sm-crates help` for the list.");
    exit::USAGE
}

fn run_tool(tool: &dyn Tool, rest: &[String]) -> i32 {
    let args = match Args::parse(rest, tool.options()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\nRun `sm-crates help {}` for usage.", tool.name());
            return e.exit_code();
        }
    };
    if args.flag("help") {
        print!("{}", tool_help(tool));
        return exit::OK;
    }
    let fail_on = match args.fail_on() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e}");
            return e.exit_code();
        }
    };
    let ctx = match ctx::Ctx::from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return e.exit_code();
        }
    };
    match tool.run(&ctx, &args) {
        Ok(report) => {
            print!("{}", report.render(args.format(), ctx.color, args.flag("quiet")));
            if report.fails(fail_on) { exit::FINDINGS } else { exit::OK }
        }
        Err(e) => {
            if args.format() == cli::Format::Json {
                let v = serde_json::json!({"tool": tool.name(), "error": e.to_string(), "exit_code": e.exit_code()});
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            }
            eprintln!("error: {e}");
            e.exit_code()
        }
    }
}

fn main_help() -> String {
    let mut s = format!(
        "sm-crates {} — Crates.io Suite by Slash Mark\n\
         Rust Package Intelligence: 25 advanced tools on live crates.io data.\n\n\
         USAGE\n  sm-crates <TOOL> [ARGS] [OPTIONS]\n  sm-crates help <TOOL>\n\n",
        env!("CARGO_PKG_VERSION")
    );
    let all = tools::all();
    for g in Group::ALL {
        s.push_str(&format!("{}\n", g.title().to_uppercase()));
        for t in all.iter().filter(|t| t.group() == g) {
            s.push_str(&format!("  {:<14}{}\n", t.name(), t.summary()));
        }
        s.push('\n');
    }
    s.push_str("GLOBAL OPTIONS\n");
    s.push_str(&opts_help(GLOBAL_OPTS));
    s.push_str(
        "\nEXIT CODES\n  0  no findings at or above --fail-on\n  1  findings at or above --fail-on (default: high)\n  \
         2  invalid command line\n  3  could not complete (network, toolchain, project)\n",
    );
    s
}

fn opts_help(opts: &[Opt]) -> String {
    let mut s = String::new();
    for o in opts {
        let mut left = match o.short {
            Some(c) => format!("-{c}, --{}", o.name),
            None => format!("    --{}", o.name),
        };
        if let Some(v) = o.value {
            left.push(' ');
            left.push_str(v);
        }
        s.push_str(&format!("  {left:<28}{}\n", o.help));
    }
    s
}

fn tool_help(t: &dyn Tool) -> String {
    let mut s = format!("sm-crates {} — {}\n\n{}\n\n", t.name(), t.title(), t.summary());
    s.push_str(&format!("USAGE\n  sm-crates {} {}\n\n", t.name(), t.usage()));
    s.push_str(&format!("{}\n", t.about().trim()));
    s.push_str(&format!("\nREQUIRES\n  {}\n", t.requires()));
    if !t.options().is_empty() {
        s.push_str("\nOPTIONS\n");
        s.push_str(&opts_help(t.options()));
    }
    s.push_str("\nGLOBAL OPTIONS\n");
    s.push_str(&opts_help(GLOBAL_OPTS));
    s.push_str("\nEXAMPLES\n");
    for e in t.examples() {
        s.push_str(&format!("  {e}\n"));
    }
    s
}
