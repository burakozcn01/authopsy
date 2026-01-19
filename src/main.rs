use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

mod analyzer;
mod cli;
mod fuzzer;
mod http;
mod models;
mod reporter;
mod scanner;

use cli::{Cli, Commands};
use models::{Role, RoleConfig};
use reporter::{ConsoleReporter, HtmlExporter, JsonExporter};
use scanner::{EndpointParser, FuzzerScanner, OpenApiParser, Scanner, print_fuzz_results};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            url,
            spec,
            endpoints,
            admin,
            user,
            anon,
            header,
            concurrency,
            timeout,
            output,
            ignore,
            verbose,
            params,
            bodies,
            skip_paths,
            public_paths,
        } => {
            if spec.is_none() && endpoints.is_none() {
                anyhow::bail!("Either --spec or --endpoints must be provided");
            }
            run_scan(
                url,
                spec,
                endpoints,
                admin,
                user,
                anon,
                header,
                concurrency,
                timeout,
                output,
                ignore,
                verbose,
                params,
                bodies,
                skip_paths,
                public_paths,
            )
            .await?;
        }
        Commands::Report {
            input,
            format,
            output,
        } => {
            run_report(input, format, output)?;
        }
        Commands::Parse { spec } => {
            run_parse(spec)?;
        }
        Commands::Fuzz {
            url,
            spec,
            endpoints,
            user,
            header,
            concurrency,
            timeout,
            params,
            verbose,
        } => {
            if spec.is_none() && endpoints.is_none() {
                anyhow::bail!("Either --spec or --endpoints must be provided");
            }
            run_fuzz(
                url,
                spec,
                endpoints,
                user,
                header,
                concurrency,
                timeout,
                params,
                verbose,
            )
            .await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_scan(
    url: String,
    spec: Option<PathBuf>,
    endpoints_arg: Option<String>,
    admin: String,
    user: String,
    anon: bool,
    header: String,
    concurrency: usize,
    timeout: u64,
    output: Option<String>,
    ignore: Option<String>,
    verbose: bool,
    params: Option<String>,
    bodies: Option<PathBuf>,
    skip_paths: Option<String>,
    public_paths: Option<String>,
) -> Result<()> {
    let skip_list = skip_paths.map(|s| parse_path_list(&s)).unwrap_or_default();
    let public_list = public_paths
        .map(|s| parse_path_list(&s))
        .unwrap_or_default();

    let mut endpoints = match (&spec, &endpoints_arg) {
        (Some(spec_path), _) => {
            let parser = OpenApiParser::new();
            parser.parse_file(spec_path.to_str().unwrap())?
        }
        (None, Some(ep_str)) => EndpointParser::parse(ep_str)?,
        (None, None) => {
            anyhow::bail!("Either --spec or --endpoints must be provided");
        }
    };

    let original_count = endpoints.len();
    endpoints.retain(|ep| !skip_list.iter().any(|skip| ep.path.contains(skip)));

    if verbose {
        if original_count != endpoints.len() {
            println!(
                "Skipped {} endpoints, scanning {}",
                original_count - endpoints.len(),
                endpoints.len()
            );
        } else {
            println!("Found {} endpoints to scan", endpoints.len());
        }
    }

    let mut roles = vec![
        RoleConfig::new(Role::Admin, Some(admin), header.clone()),
        RoleConfig::new(Role::User, Some(user), header.clone()),
    ];

    if anon {
        roles.push(RoleConfig::new(Role::Anonymous, None, header));
    }

    let path_params = params.map(|p| parse_params(&p)).unwrap_or_default();
    let request_bodies = bodies
        .map(|b| load_bodies(b.to_str().unwrap()))
        .transpose()?
        .unwrap_or_default();
    let ignore_fields = ignore.map(|i| parse_ignore(&i)).unwrap_or_default();

    let scanner = Scanner::new(
        url,
        roles,
        concurrency,
        timeout,
        path_params,
        request_bodies,
        ignore_fields,
        public_list,
    );
    let results = scanner.scan_all(endpoints, verbose).await;

    let reporter = ConsoleReporter::new();
    reporter.print_matrix(&results);
    reporter.print_details(&results);
    reporter.print_summary(&results);

    if let Some(output_path) = output {
        JsonExporter::export(&results, &output_path)?;
        println!("\nResults saved to: {}", output_path);
    }

    Ok(())
}

fn run_report(input: PathBuf, format: String, output: Option<String>) -> Result<()> {
    let results = JsonExporter::load(input.to_str().unwrap())?;

    match format.as_str() {
        "html" => {
            let output_path = output.unwrap_or_else(|| "report.html".to_string());
            HtmlExporter::export(&results, &output_path)?;
            println!("HTML report generated: {}", output_path);
        }
        "json" => {
            let output_path = output.unwrap_or_else(|| "report.json".to_string());
            JsonExporter::export(&results, &output_path)?;
            println!("JSON report generated: {}", output_path);
        }
        _ => {
            anyhow::bail!("Unsupported format: '{}'. Use 'html' or 'json'", format);
        }
    }

    Ok(())
}

fn run_parse(spec: PathBuf) -> Result<()> {
    let parser = OpenApiParser::new();
    let spec_str = spec.to_str().unwrap();
    let endpoints = parser.parse_file(spec_str)?;

    println!("Parsed {} endpoints from {}\n", endpoints.len(), spec_str);

    for ep in &endpoints {
        println!("  {} {}", ep.method, ep.path);
    }

    Ok(())
}

fn parse_params(input: &str) -> std::collections::HashMap<String, String> {
    input
        .split(',')
        .filter_map(|pair| {
            let mut parts = pair.trim().splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(k), Some(v)) => Some((k.trim().to_string(), v.trim().to_string())),
                _ => None,
            }
        })
        .collect()
}

fn load_bodies(path: &str) -> Result<std::collections::HashMap<String, serde_json::Value>> {
    let content = std::fs::read_to_string(path)?;
    let bodies: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_str(&content)?;
    Ok(bodies)
}

fn parse_ignore(input: &str) -> Vec<String> {
    input.split(',').map(|s| s.trim().to_string()).collect()
}

fn parse_path_list(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[allow(clippy::too_many_arguments)]
async fn run_fuzz(
    url: String,
    spec: Option<PathBuf>,
    endpoints_arg: Option<String>,
    user: String,
    header: String,
    concurrency: usize,
    timeout: u64,
    params: Option<String>,
    verbose: bool,
) -> Result<()> {
    let endpoints = match (&spec, &endpoints_arg) {
        (Some(spec_path), _) => {
            let parser = OpenApiParser::new();
            parser.parse_file(spec_path.to_str().unwrap())?
        }
        (None, Some(ep_str)) => EndpointParser::parse(ep_str)?,
        (None, None) => {
            anyhow::bail!("Either --spec or --endpoints must be provided");
        }
    };

    if verbose {
        println!("Found {} endpoints to fuzz", endpoints.len());
    }

    let user_role = RoleConfig::new(Role::User, Some(user), header);
    let path_params = params.map(|p| parse_params(&p)).unwrap_or_default();

    let fuzzer = FuzzerScanner::new(url, user_role, concurrency, timeout, path_params);
    let results = fuzzer.fuzz_all(endpoints, verbose).await;

    print_fuzz_results(&results);

    Ok(())
}
