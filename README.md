# Rust Data Pipeline

A high-performance, configurable data pipeline built in Rust with support for multiple data sources, transformations, validation, and output formats.

## Features

- **Multi-source Data Ingestion**: CSV files, JSON files, databases, APIs, and directories
- **Flexible Data Processing**: Field transformations, filtering, aggregations, and custom processors
- **Comprehensive Validation**: Data quality checks, schema validation, and business rule validation
- **Multiple Output Formats**: CSV, JSON, JSON Lines, databases, and APIs
- **Monitoring & Observability**: Prometheus metrics, health checks, and structured logging
- **Configuration Management**: YAML/TOML configuration with environment variable support
- **Parallel Processing**: Async/await with configurable parallelism and batch processing
- **Error Handling**: Comprehensive error handling with retry mechanisms

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd data-pipeline

# Build the project
cargo build --release
```

### Basic Usage

1. **Generate a sample configuration file:**
```bash
cargo run -- config -o my-pipeline.yaml
```

2. **Run the pipeline once:**
```bash
cargo run -- run -c my-pipeline.yaml
```

3. **Start continuous processing:**
```bash
cargo run -- start -c my-pipeline.yaml -i 300  # Run every 5 minutes
```

4. **Validate configuration:**
```bash
cargo run -- validate -c my-pipeline.yaml
```

5. **Check pipeline health:**
```bash
cargo run -- health -c my-pipeline.yaml
```

### Environment Variables

You can use environment variables instead of configuration files:

```bash
# Set configuration via environment variables
export DATA_PIPELINE__PIPELINE__NAME="my-pipeline"
export DATA_PIPELINE__INGESTION__SOURCES__0__SOURCE_TYPE="csv_file"
export DATA_PIPELINE__INGESTION__SOURCES__0__PARAMETERS__PATH="./data/input.csv"

# Run with environment configuration
cargo run -- run --from-env
```

## Configuration

### Pipeline Settings

```yaml
pipeline:
  name: "my-data-pipeline"
  description: "Description of what this pipeline does"
  version: "1.0.0"
  parallel_processing: true
  batch_size: 1000
  max_retries: 3
  timeout_seconds: 300
```

### Data Sources

```yaml
ingestion:
  concurrent_sources: 4
  retry_failed_sources: true
  sources:
    # CSV File
    - name: "sales_data"
      source_type: "csv_file"
      enabled: true
      parameters:
        path: "./data/sales.csv"
    
    # JSON File
    - name: "customers"
      source_type: "json_file"
      enabled: true
      parameters:
        path: "./data/customers.json"
    
    # Database Query
    - name: "products_db"
      source_type: "database"
      enabled: true
      parameters:
        connection_string: "postgresql://user:pass@localhost/db"
        query: "SELECT * FROM products WHERE active = true"
    
    # REST API
    - name: "external_api"
      source_type: "api"
      enabled: true
      parameters:
        url: "https://api.example.com/data"
        headers:
          Authorization: "Bearer token"
    
    # Directory of files
    - name: "data_directory"
      source_type: "directory"
      enabled: true
      parameters:
        path: "./data/input"
        pattern: "*.csv"
```

### Data Processing

```yaml
processing:
  enabled: true
  parallel_processing: true
  batch_size: 1000
  rules:
    - name: "clean_email"
      enabled: true
      operations:
        - operation_type: "lower_case"
          parameters:
            field: "email"
        - operation_type: "trim"
          parameters:
            field: "email"
    
    - name: "filter_active_users"
      enabled: true
      operations:
        - operation_type: "filter_equals"
          parameters:
            field: "status"
            value: "active"
```

#### Available Operations

- **Field Operations**: `rename_field`, `remove_field`, `add_field`
- **Type Conversions**: `convert_to_string`, `convert_to_number`, `convert_to_boolean`
- **String Operations**: `upper_case`, `lower_case`, `trim`, `replace`
- **Aggregations**: `sum`, `average`, `count`
- **Filtering**: `filter_equals`, `filter_greater_than`, `filter_less_than`, `filter_contains`
- **Custom**: `custom` (with custom transformers)

### Data Validation

```yaml
validation:
  enabled: true
  fail_on_validation_error: false
  max_error_percentage: 10.0
  rules:
    - name: "required_email"
      description: "Email is required"
      enabled: true
      rule_type: "required_field"
      severity: "error"
      parameters:
        field: "email"
    
    - name: "valid_email"
      description: "Email must be valid format"
      enabled: true
      rule_type: "is_email"
      severity: "error"
      parameters:
        field: "email"
    
    - name: "age_range"
      description: "Age must be between 0 and 150"
      enabled: true
      rule_type: "min_value"
      severity: "warning"
      parameters:
        field: "age"
        min: 0
```

#### Available Validation Rules

- **Required Fields**: `required_field`
- **Type Validation**: `is_string`, `is_number`, `is_boolean`, `is_email`, `is_url`, `is_date`
- **Value Constraints**: `min_value`, `max_value`, `min_length`, `max_length`
- **Pattern Matching**: `regex`, `in_set`, `not_in_set`
- **Cross-field**: `unique_field`, `conditional_required`
- **Custom**: `custom` (with custom validators)

### Data Output

```yaml
output:
  concurrent_sinks: 2
  config:
    compression: "gzip"  # Optional: "gzip" or "deflate"
    encoding: "utf-8"
    include_metadata: true
    timestamp_format: "%Y-%m-%d %H:%M:%S UTC"
  sinks:
    # CSV File
    - name: "output_csv"
      sink_type: "csv_file"
      enabled: true
      parameters:
        path: "./data/output.csv"
        headers: ["id", "name", "email", "age"]
        append: false
    
    # JSON File
    - name: "output_json"
      sink_type: "json_file"
      enabled: true
      parameters:
        path: "./data/output.json"
        pretty: true
        append: false
    
    # Database
    - name: "output_db"
      sink_type: "database"
      enabled: true
      parameters:
        connection_string: "postgresql://user:pass@localhost/db"
        table: "processed_data"
        batch_size: 100
```

### Monitoring

```yaml
monitoring:
  logging:
    level: "info"           # trace, debug, info, warn, error
    format: "json"          # json or text
    output: "stdout"        # stdout or file
    file_path: "./logs/pipeline.log"
    max_file_size_mb: 100
    max_files: 10
  
  metrics:
    enabled: true
    port: 9090
    path: "/metrics"
    collect_system_metrics: true
  
  health_check:
    enabled: true
    port: 8080
    path: "/health"
    interval_seconds: 30
```

## Monitoring & Observability

### Metrics

The pipeline exposes Prometheus metrics on port 9090 (configurable):

- `pipeline_records_processed_total` - Total records processed by stage
- `pipeline_processing_duration_seconds` - Processing time by stage
- `pipeline_active_records` - Current active records being processed
- `pipeline_errors_total` - Total errors by type and component
- `pipeline_validation_errors_total` - Validation errors by rule
- `pipeline_data_quality_score` - Overall data quality score (0-100)
- `pipeline_status` - Pipeline status (0=stopped, 1=running, 2=error)

### Health Checks

Health endpoint available at `http://localhost:8080/health` (configurable):

```json
{
  "status": "running",
  "version": "0.1.0",
  "uptime_seconds": 3600,
  "last_run": "2023-10-29T10:30:00Z",
  "components": {
    "ingestion": {
      "status": "healthy",
      "last_check": "2023-10-29T10:29:45Z",
      "details": {
        "records_ingested": "1000",
        "duration_seconds": "5.23"
      }
    }
  },
  "metrics": {
    "records_ingested": 1000,
    "records_processed": 950,
    "records_output": 900,
    "data_quality_score": 95.5
  }
}
```

### Logging

Structured logging with configurable levels and formats:

```json
{
  "timestamp": "2023-10-29T10:30:00.123Z",
  "level": "INFO",
  "target": "data_pipeline::pipeline",
  "message": "Pipeline run completed successfully",
  "fields": {
    "records_processed": 1000,
    "duration_seconds": 45.67
  }
}
```

## Extending the Pipeline

### Custom Transformers

Create custom data transformers by implementing the `CustomTransformer` trait:

```rust
use data_pipeline::processing::{CustomTransformer, DataRecord};
use std::collections::HashMap;
use serde_json::Value;

pub struct MyCustomTransformer;

impl CustomTransformer for MyCustomTransformer {
    fn transform(&self, record: &mut DataRecord, parameters: &HashMap<String, Value>) -> Result<()> {
        // Your custom transformation logic here
        Ok(())
    }
}
```

### Custom Validators

Create custom validators by implementing the `CustomValidator` trait:

```rust
use data_pipeline::validation::{CustomValidator, ValidationError, DataRecord};
use std::collections::HashMap;
use serde_json::Value;

pub struct MyCustomValidator;

impl CustomValidator for MyCustomValidator {
    fn validate(&self, record: &DataRecord, parameters: &HashMap<String, Value>) -> Result<Vec<ValidationError>> {
        // Your custom validation logic here
        Ok(Vec::new())
    }
}
```

## Performance Tips

1. **Batch Size**: Adjust `batch_size` based on your memory and processing requirements
2. **Parallel Processing**: Enable parallel processing for CPU-intensive operations
3. **Database Connections**: Use connection pooling for database sources and sinks
4. **Memory Management**: Monitor memory usage with large datasets
5. **Error Handling**: Set appropriate `max_error_percentage` for your use case

## Troubleshooting

### Common Issues

1. **Configuration Errors**: Use `validate` command to check configuration
2. **Permission Issues**: Ensure read/write permissions for input/output paths
3. **Database Connections**: Verify connection strings and credentials
4. **Memory Issues**: Reduce batch size for large datasets
5. **Network Issues**: Check API endpoints and network connectivity

### Debug Mode

Run with verbose logging to see detailed information:

```bash
cargo run -- run -c config.yaml --verbose
```

### Environment Variables

Set `RUST_LOG=debug` for even more detailed logging:

```bash
RUST_LOG=debug cargo run -- run -c config.yaml
```

## Examples

See the `examples/` directory for complete pipeline configurations for common use cases:

- Customer data processing
- Sales data aggregation
- Log file analysis
- API data synchronization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.