//! `tuned zswap` — the zswap subsystem of the `tuned` daemon.
//!
//! This binary is a thin CLI over the `tuned-zswap` library: argument parsing
//! and output formatting only. All logic, including the frozen decision
//! semantics, lives in `tuned_zswap::…` so the fused daemon drives the exact
//! same code paths.
//!
//! The library has zero third-party dependencies and must stay that way; see
//! the root `AGENTS.md` for why.

use std::env;
use std::process::ExitCode;

use tuned_zswap::{print_report, print_stats, run_once, Args};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{}", tuned_zswap::USAGE);
        return ExitCode::SUCCESS;
    }

    match Args::parse(&args) {
        Err(e) => {
            eprintln!("tuned zswap: {}", e);
            ExitCode::from(2)
        }
        Ok(parsed) => {
            let result = if parsed.stats {
                print_stats();
                Ok(())
            } else if let Some(path) = &parsed.report {
                print_report(path)
            } else if parsed.once {
                run_once(parsed.dry_run)
            } else {
                // The daemon loop belongs to `tuned run`; here we only ever
                // run a single poll, so the loop is not reachable from this
                // binary on purpose.
                eprintln!(
                    "tuned zswap: daemon mode moved to `tuned run`\n\n{}",
                    tuned_zswap::USAGE
                );
                Err("use `tuned run` to start the daemon".to_string())
            };
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("tuned zswap: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tuned_zswap::{Args, STATS_PATH};

    #[test]
    fn args_accept_each_mode_and_reject_combinations() {
        let run = |args: &[&str]| -> Result<Args, String> {
            Args::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        };

        let daemon = run(&[]).expect("no args");
        assert!(!daemon.once && !daemon.stats && daemon.report.is_none());

        let once = run(&["--once"]).expect("once");
        assert!(once.once && !once.dry_run);

        let dry = run(&["--once", "--dry-run"]).expect("dry run");
        assert!(dry.once && dry.dry_run);

        let stats = run(&["--stats"]).expect("stats");
        assert!(stats.stats);

        let default_report = run(&["--report"]).expect("report");
        assert_eq!(
            default_report.report.as_deref(),
            Some(std::path::Path::new(STATS_PATH))
        );

        let path_report = run(&["--report", "/somewhere.jsonl"]).expect("report with path");
        assert_eq!(
            path_report.report.as_deref(),
            Some(std::path::Path::new("/somewhere.jsonl"))
        );

        assert!(run(&["--dry-run"]).is_err(), "needs --once");
        assert!(run(&["--stats", "--once"]).is_err(), "modes are exclusive");
        assert!(
            run(&["--report", "--stats"]).is_err(),
            "modes are exclusive"
        );
        assert!(run(&["--bogus"]).is_err(), "unknown flag");
    }
}
