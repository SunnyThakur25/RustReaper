use clap::{Parser, Subcommand};
use crossbeam_channel::{unbounded, Sender};
use lazy_static::lazy_static;
use log::{error, info, warn};
use rustreaper::{analyzer::MemoryAnalyzer, gui_server, models::Artifact, output, parser};
use serde_json::Value;
use sqlite::Connection;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;
use anyhow::{Context, Result};

lazy_static! {
    static ref PROGRESS_CHANNEL: Mutex<Option<(Sender<f32>, Sender<f32>)>> = Mutex::new(None);
}

#[derive(Parser)]
#[command(
    name = "rustreaper",
    about = "Advanced memory forensic analyzer for malware artifacts",
    version = "0.1.0",
    author = "Sunny thakur"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,
    
    /// Output directory for reports
    #[arg(short, long, global = true, default_value = "./reports")]
    output_dir: PathBuf,
    
    /// YARA rules file
    #[arg(long, global = true, default_value = "./rules/rules.yara")]
    yara_rules: PathBuf,
    
    /// Scanning profile (quick, deep, stealth)
    #[arg(long, global = true, default_value = "deep")]
    profile: String,
}

#[derive(Subcommand)]
enum Commands {
    Analyze {
        #[arg(short, long, value_name = "FILE")]
        dump: PathBuf,
        #[arg(short, long, default_value_t = false)]
        skip_known: bool,
    },
    Scan {
        #[arg(short, long, default_value_t = false)]
        live: bool,
        #[arg(short, long, value_name = "PID")]
        pid: Option<u32>,
        #[arg(short, long, value_name = "FILE", conflicts_with = "live")]
        dump: Option<PathBuf>,
    },
    Report {
        #[arg(short, long, value_name = "FORMAT", default_value = "json")]
        format: output::OutputFormat,
        #[arg(short, long, default_value_t = false)]
        include_context: bool,
    },
    Serve {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        addr: String,
        #[arg(short, long, default_value_t = false)]
        auth: bool,
    },
    Profiles,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .format_timestamp_micros()
        .init();

    let start_time = Instant::now();
    info!("Starting RustReaper memory forensic analyzer");

    let cli = Cli::parse();
    fs::create_dir_all(&cli.output_dir).context("Failed to create output directory")?;

    // Initialize SQLite database
    let db_path = cli.output_dir.join("rustreaper.db");
    let conn = sqlite::open(&db_path).context("Failed to open SQLite database")?;
    init_db(&conn)?;

    match &cli.command {
        Commands::Analyze { dump, skip_known } => {
            info!("Analyzing memory dump: {}", dump.display());
            let data = fs::read(dump)
                .with_context(|| format!("Failed to read dump file: {}", dump.display()))?;
            
            let (parse_tx, parse_rx) = unbounded::<f32>();
            let (analyze_tx, analyze_rx) = unbounded::<f32>();
            {
                let mut progress_channel = PROGRESS_CHANNEL.lock().unwrap();
                *progress_channel = Some((parse_tx.clone(), analyze_tx.clone()));
            }

            // Log progress milestones
            let progress_task = tokio::spawn(async move {
                let mut last_parse = 0.0;
                let mut last_analyze = 0.0;
                while let Ok(parse_progress) = parse_rx.try_recv() {
                    let rounded = (parse_progress / 25.0).floor() * 25.0;
                    if rounded > last_parse && rounded <= 100.0 {
                        info!("Parsing progress: {}%", rounded);
                        last_parse = rounded;
                    }
                }
                while let Ok(analyze_progress) = analyze_rx.try_recv() {
                    let rounded = (analyze_progress / 25.0).floor() * 25.0;
                    if rounded > last_analyze && rounded <= 100.0 {
                        info!("Analysis progress: {}%", rounded);
                        last_analyze = rounded;
                    }
                }
            });

            let parse_start = Instant::now();
            let regions = parser::parse_memory(&data, *skip_known, |progress| {
                parse_tx.send(progress).unwrap();
            }).context("Memory parsing failed")?;
            info!("Parsed {} memory regions in {:?}", regions.len(), parse_start.elapsed());
            
            let analysis_start = Instant::now();
            let analyzer = MemoryAnalyzer::new_with_rules(&cli.yara_rules).context("Failed to initialize analyzer")?;
            let artifacts = analyzer.analyze(®ions, |progress| {
                analyze_tx.send(progress).unwrap();
            }).context("Memory analysis failed")?;
            info!("Found {} artifacts in {:?}", artifacts.len(), analysis_start.elapsed());
            
            progress_task.await.unwrap();

            save_artifacts_to_db(&conn, &artifacts)?;
            let report_path = cli.output_dir.join("memory_analysis.json");
            output::ReportWriter::new()
                .with_format(output::OutputFormat::JsonPretty)
                .write(&artifacts, &report_path)
                .context("Failed to write report")?;
            
            info!("Analysis completed in {:?}. Report saved to {}", 
                start_time.elapsed(), report_path.display());
        }
        Commands::Scan { live, pid, dump } => {
            let (parse_tx, parse_rx) = unbounded::<f32>();
            let (analyze_tx, analyze_rx) = unbounded::<f32>();
            {
                let mut progress_channel = PROGRESS_CHANNEL.lock().unwrap();
                *progress_channel = Some((parse_tx.clone(), analyze_tx.clone()));
            }

            let progress_task = tokio::spawn(async move {
                let mut last_parse = 0.0;
                let mut last_analyze = 0.0;
                while let Ok(parse_progress) = parse_rx.try_recv() {
                    let rounded = (parse_progress / 25.0).floor() * 25.0;
                    if rounded > last_parse && rounded <= 100.0 {
                        info!("Parsing progress: {}%", rounded);
                        last_parse = rounded;
                    }
                }
                while let Ok(analyze_progress) = analyze_rx.try_recv() {
                    let rounded = (analyze_progress / 25.0).floor() * 25.0;
                    if rounded > last_analyze && rounded <= 100.0 {
                        info!("Analysis progress: {}%", rounded);
                        last_analyze = rounded;
                    }
                }
            });

            if *live {
                let pid = pid.ok_or_else(|| anyhow::anyhow!("PID required for live scanning"))?;
                info!("Scanning live process (PID: {})", pid);
                
                let scan_start = Instant::now();
                let regions = parser::parse_live_process(pid, |progress| {
                    parse_tx.send(progress).unwrap();
                }).context("Live process scanning failed")?;
                let analyzer = MemoryAnalyzer::new_with_rules(&cli.yara_rules).context("Failed to initialize analyzer")?;
                let artifacts = match cli.profile.as_str() {
                    "quick" => analyzer.analyze_quick(®ions, |progress| analyze_tx.send(progress).unwrap()),
                    "stealth" => analyzer.analyze_stealth(®ions, |progress| analyze_tx.send(progress).unwrap()),
                    _ => analyzer.analyze(®ions, |progress| analyze_tx.send(progress).unwrap()),
                }.context("Live process analysis failed")?;
                
                save_artifacts_to_db(&conn, &artifacts)?;
                let report_path = cli.output_dir.join(format!("live_scan_{}.json", pid));
                output::ReportWriter::new()
                    .write(&artifacts, &report_path)
                    .context("Failed to write report")?;
                
                progress_task.await.unwrap();
                
                info!("Live scan completed in {:?}. Report saved to {}",
                    scan_start.elapsed(), report_path.display());
            } else if let Some(dump) = dump {
                info!("Scanning memory dump: {}", dump.display());
                let scan_start = Instant::now();
                let data = fs::read(dump)
                    .with_context(|| format!("Failed to read dump file: {}", dump.display()))?;
                let regions = parser::parse_memory(&data, false, |progress| {
                    parse_tx.send(progress).unwrap();
                }).context("Memory parsing failed")?;
                let analyzer = MemoryAnalyzer::new_with_rules(&cli.yara_rules).context("Failed to initialize analyzer")?;
                let artifacts = match cli.profile.as_str() {
                    "quick" => analyzer.analyze_quick(®ions, |progress| analyze_tx.send(progress).unwrap()),
                    "stealth" => analyzer.analyze_stealth(®ions, |progress| analyze_tx.send(progress).unwrap()),
                    _ => analyzer.analyze(®ions, |progress| analyze_tx.send(progress).unwrap()),
                }.context("Memory analysis failed")?;
                
                save_artifacts_to_db(&conn, &artifacts)?;
                let report_path = cli.output_dir.join("memory_scan.json");
                output::ReportWriter::new()
                    .write(&artifacts, &report_path)
                    .context("Failed to write report")?;
                
                progress_task.await.unwrap();
                
                info!("Scan completed in {:?}. Report saved to {}",
                    scan_start.elapsed(), report_path.display());
            } else {
                return Err(anyhow::anyhow!("Either --live with --pid or --dump must be specified"));
            }
        }
        Commands::Report { format, include_context } => {
            info!("Generating consolidated report in {:?} format", format);
            
            let mut aggregated = Vec::new();
            let mut statement = conn.prepare("SELECT data FROM artifacts")?;
            while let Ok(sqlite::State::Row) = statement.next() {
                let data: String = statement.read(0)?;
                let artifact: Value = serde_json::from_str(&data)?;
                aggregated.push(artifact);
            }
            
            if aggregated.is_empty() {
                warn!("No report files found in database");
                return Ok(());
            }
            
            let consolidated_path = cli.output_dir.join("consolidated_report");
            output::ReportWriter::new()
                .with_format(*format)
                .with_context(*include_context)
                .write(&aggregated, &consolidated_path)
                .context("Failed to write consolidated report")?;
            
            info!("Consolidated report generated at {}.{}", 
                consolidated_path.display(), format.extension());
        }
        Commands::Serve { addr, auth } => {
            info!("Starting web interface on {} (auth: {})", addr, auth);
            gui_server::start_server(addr, *auth, &db_path).await?;
        }
        Commands::Profiles => {
            println!("Available scanning profiles:");
            println!("- quick: Fast scan for common artifacts");
            println!("- deep: Comprehensive scan with entropy and YARA analysis");
            println!("- stealth: Minimal impact scanning for live systems");
        }
    }

    Ok(())
}

fn init_db(conn: &Connection) -> Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            data TEXT NOT NULL
        )"
    )?;
    Ok(())
}

fn save_artifacts_to_db(conn: &Connection, artifacts: &[Artifact]) -> Result<()> {
    let mut stmt = conn.prepare("INSERT INTO artifacts (data) VALUES (?)")?;
    for artifact in artifacts {
        let data = serde_json::to_string(artifact)?;
        stmt.bind((1, data.as_str()))?;
        stmt.next()?;
    }
    Ok(())
}
