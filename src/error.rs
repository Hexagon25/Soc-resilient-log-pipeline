use std::fmt;

#[derive(Debug)]
pub enum DataPipelineError {
    Io(std::io::Error),
    Serde(serde_json::Error),
    Validation(String),
    Processing(String),
    Pipeline(String),
    DataSourceNotFound(String),
    DataSinkUnavailable(String),
    Generic(String),
}

impl fmt::Display for DataPipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataPipelineError::Io(err) => write!(f, "IO error: {}", err),
            DataPipelineError::Serde(err) => write!(f, "Serialization error: {}", err),
            DataPipelineError::Validation(msg) => write!(f, "Validation error: {}", msg),
            DataPipelineError::Processing(msg) => write!(f, "Processing error: {}", msg),
            DataPipelineError::Pipeline(msg) => write!(f, "Pipeline error: {}", msg),
            DataPipelineError::DataSourceNotFound(source) => write!(f, "Data source not found: {}", source),
            DataPipelineError::DataSinkUnavailable(sink) => write!(f, "Data sink not available: {}", sink),
            DataPipelineError::Generic(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for DataPipelineError {}

impl From<std::io::Error> for DataPipelineError {
    fn from(err: std::io::Error) -> Self {
        DataPipelineError::Io(err)
    }
}

impl From<serde_json::Error> for DataPipelineError {
    fn from(err: serde_json::Error) -> Self {
        DataPipelineError::Serde(err)
    }
}

pub type Result<T> = std::result::Result<T, DataPipelineError>;