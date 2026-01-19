use clap::{Parser, Subcommand};
use std::path::PathBuf;

fn validate_url(s: &str) -> Result<String, String> {
    let trimmed = s.trim();

    if trimmed.is_empty() {
        return Err("URL cannot be empty".to_string());
    }

    let url = if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        format!("https://{}", trimmed)
    } else {
        trimmed.to_string()
    };

    let without_protocol = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(&url);

    if without_protocol.is_empty() {
        return Err(format!("Invalid URL: '{}' - missing host", s));
    }

    let host = without_protocol.split('/').next().unwrap_or("");

    if host.is_empty() {
        return Err(format!("Invalid URL: '{}' - missing host", s));
    }

    let is_localhost = host.starts_with("localhost") || host.starts_with("127.0.0.1");
    let has_port = host.contains(':');
    let has_domain = host.contains('.');

    if !is_localhost && !has_domain {
        return Err(format!("Invalid URL: '{}' - must be a valid domain or localhost", s));
    }

    if has_port {
        let parts: Vec<&str> = host.rsplitn(2, ':').collect();
        if let Some(port_str) = parts.first() {
            if port_str.parse::<u16>().is_err() {
                return Err(format!("Invalid URL: '{}' - invalid port number", s));
            }
        }
    }

    Ok(url)
}

fn validate_file_exists(s: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(s);
    if !path.exists() {
        return Err(format!("File not found: {}", s));
    }
    if !path.is_file() {
        return Err(format!("Not a file: {}", s));
    }
    Ok(path)
}

fn validate_optional_file(s: &str) -> Result<PathBuf, String> {
    validate_file_exists(s)
}

#[derive(Parser)]
#[command(name = "authopsy")]
#[command(version, about = "High-performance RBAC vulnerability scanner")]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(about = "Scan API endpoints for RBAC vulnerabilities")]
    Scan {
        #[arg(short, long, help = "API base URL (e.g., https://api.example.com)", value_parser = validate_url)]
        url: String,

        #[arg(short, long, help = "OpenAPI/Swagger spec file path", value_parser = validate_optional_file)]
        spec: Option<PathBuf>,

        #[arg(
            short,
            long,
            help = "Manual endpoint list (e.g., \"GET /api/users, POST /api/users\")"
        )]
        endpoints: Option<String>,

        #[arg(long, help = "Admin role auth token")]
        admin: String,

        #[arg(long, help = "User role auth token")]
        user: String,

        #[arg(long, default_value = "true", help = "Include anonymous role testing")]
        anon: bool,

        #[arg(long, default_value = "Authorization", help = "Auth header name")]
        header: String,

        #[arg(short, long, default_value = "50", help = "Max concurrent requests")]
        concurrency: usize,

        #[arg(short, long, default_value = "10", help = "Request timeout in seconds")]
        timeout: u64,

        #[arg(short, long, help = "Output file path for JSON results")]
        output: Option<String>,

        #[arg(long, help = "Fields to ignore in comparison (comma-separated)")]
        ignore: Option<String>,

        #[arg(short, long, help = "Show detailed progress")]
        verbose: bool,

        #[arg(short, long, help = "Path parameters (e.g., \"id=123,userId=abc\")")]
        params: Option<String>,

        #[arg(short, long, help = "Request bodies JSON file", value_parser = validate_optional_file)]
        bodies: Option<PathBuf>,

        #[arg(long, help = "Paths to skip (comma-separated)")]
        skip_paths: Option<String>,

        #[arg(long, help = "Paths that are intentionally public (comma-separated)")]
        public_paths: Option<String>,
    },

    #[command(about = "Generate report from scan results")]
    Report {
        #[arg(short, long, help = "Input JSON file from scan", value_parser = validate_file_exists)]
        input: PathBuf,

        #[arg(
            short,
            long,
            default_value = "html",
            help = "Output format (html, json)"
        )]
        format: String,

        #[arg(short, long, help = "Output file path")]
        output: Option<String>,
    },

    #[command(about = "Parse and list endpoints from OpenAPI spec")]
    Parse {
        #[arg(short, long, help = "OpenAPI/Swagger spec file", value_parser = validate_file_exists)]
        spec: PathBuf,
    },

    #[command(about = "Fuzz endpoints to find authorization bypasses")]
    Fuzz {
        #[arg(short, long, help = "API base URL", value_parser = validate_url)]
        url: String,

        #[arg(short, long, help = "OpenAPI/Swagger spec file", value_parser = validate_optional_file)]
        spec: Option<PathBuf>,

        #[arg(short, long, help = "Manual endpoint list")]
        endpoints: Option<String>,

        #[arg(long, help = "User role auth token")]
        user: String,

        #[arg(long, default_value = "Authorization", help = "Auth header name")]
        header: String,

        #[arg(short, long, default_value = "20", help = "Max concurrent requests")]
        concurrency: usize,

        #[arg(short, long, default_value = "10", help = "Request timeout in seconds")]
        timeout: u64,

        #[arg(short, long, help = "Path parameters")]
        params: Option<String>,

        #[arg(short, long, help = "Show detailed progress")]
        verbose: bool,
    },
}
