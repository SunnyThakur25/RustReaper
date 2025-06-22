use crate::models::Artifact;
use serde_json::Value;
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    Json,
    JsonPretty,
    Html,
}

impl OutputFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            OutputFormat::Json => "json",
            OutputFormat::JsonPretty => "json",
            OutputFormat::Html => "html",
        }
    }
}

pub struct ReportWriter {
    format: OutputFormat,
    include_context: bool,
}

impl ReportWriter {
    pub fn new() -> Self {
        ReportWriter {
            format: OutputFormat::Json,
            include_context: false,
        }
    }

    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }

    pub fn with_context(mut self, include_context: bool) -> Self {
        self.include_context = include_context;
        self
    }

    pub fn write(&self, artifacts: &[impl serde::Serialize], path: &Path) -> std::io::Result<()> {
        match self.format {
            OutputFormat::Json => {
                let json = serde_json::to_string(&artifacts)?;
                File::create(path)?.write_all(json.as_bytes())?;
            }
            OutputFormat::JsonPretty => {
                let json = serde_json::to_string_pretty(&artifacts)?;
                File::create(path)?.write_all(json.as_bytes())?;
            }
            OutputFormat::Html => {
                let mut html = String::from("<!DOCTYPE html><html><head><title>RustReaper Report</title>");
                html.push_str("<style>table {border-collapse: collapse; width: 100%;} th, td {border: 1px solid black; padding: 8px; text-align: left;} th {background-color: #f2f2f2;}</style>");
                html.push_str("</head><body><h1>RustReaper Analysis Report</h1><table>");
                html.push_str("<tr><th>Address</th><th>Type</th><th>Description</th><th>Confidence</th><th>Entropy</th>");
                if self.include_context {
                    html.push_str("<th>Context</th>");
                }
                html.push_str("</tr>");

                for artifact in artifacts {
                    let artifact: Value = serde_json::to_value(artifact)?;
                    html.push_str(&format!(
                        "<tr><td>0x{:x}</td><td>{}</td><td>{}</td><td>{:.2}</td><td>{}</td>",
                        artifact["address"].as_u64().unwrap_or(0),
                        artifact["artifact_type"].as_str().unwrap_or("Unknown"),
                        artifact["description"].as_str().unwrap_or(""),
                        artifact["confidence"].as_f64().unwrap_or(0.0),
                        artifact["entropy"].as_f64().map(|e| format!("{:.2}", e)).unwrap_or("N/A".to_string())
                    ));
                    if self.include_context {
                        let context = artifact["context"].as_array()
                            .map(|ctx| ctx.iter().map(|b| format!("{:02x}", b.as_u64().unwrap_or(0))).collect::<Vec<_>>().join(" "))
                            .unwrap_or("N/A".to_string());
                        html.push_str(&format!("<td>{}</td>", context));
                    }
                    html.push_str("</tr>");
                }
                html.push_str("</table></body></html>");
                File::create(path)?.write_all(html.as_bytes())?;
            }
        }
        Ok(())
    }
}