use goblin::elf::Elf;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use thiserror::Error;


#[derive(Debug, Clone)]
pub enum Architecture {
    X86_64,
    X86,
    ARM,
    AARCH64,
    Unknown(u16),
}

#[derive(Debug, Clone)]
pub enum RelroStatus {
    Full,
    Partial,
    None,
}

#[derive(Debug, Clone)]
pub enum PieStatus {
    PIE,
    NonPIE,
}

#[derive(Debug, Clone)]
pub enum NxStatus {
    NX,
    NoNX,
}

#[derive(Debug, Clone)]
pub enum CanaryStatus {
    Enabled,
    Disabled,
}

#[derive(Debug, Clone)]
pub enum FortifyStatus {
    Enabled,
    Disabled,
}

#[derive(Debug, Error)]
pub enum BinaryAnalysisError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid ELF format: {0}")]
    InvalidElf(String),
    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(u16),
}

#[derive(Debug, Clone)]
pub struct SecurityFeatures {
    pub relro: RelroStatus,
    pub pie: PieStatus,
    pub nx: NxStatus,
    pub canary: CanaryStatus,
    pub fortify_source: FortifyStatus,
}

#[derive(Debug)]
pub struct ELFBinary {
    pub path: PathBuf,
    pub architecture: Architecture,
    pub security_features: SecurityFeatures,
}

impl ELFBinary {
    pub fn analyze(path: impl Into<PathBuf>) -> Result<Self, BinaryAnalysisError> {
        let path = path.into();
        let mut file = File::open(&path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = Elf::parse(&buffer)
            .map_err(|e| BinaryAnalysisError::InvalidElf(e.to_string()))?;

        let architecture = match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => Architecture::X86_64,
            goblin::elf::header::EM_386 => Architecture::X86,
            goblin::elf::header::EM_ARM => Architecture::ARM,
            goblin::elf::header::EM_AARCH64 => Architecture::AARCH64,
            unknown => Architecture::Unknown(unknown),
        };

        // Check RELRO status from dynamic entries
        let relro = if let Some(dynamic) = &elf.dynamic {
            let has_relro = dynamic.dyns.iter().any(|dyn_entry| dyn_entry.d_tag == goblin::elf::dynamic::DT_FLAGS_1);
            let has_bind_now = dynamic.dyns.iter().any(|dyn_entry| dyn_entry.d_tag == goblin::elf::dynamic::DT_BIND_NOW);
            
            if has_relro && has_bind_now {
                RelroStatus::Full
            } else if has_relro {
                RelroStatus::Partial
            } else {
                RelroStatus::None
            }
        } else {
            RelroStatus::None
        };

        // Basic security feature analysis
        let security_features = SecurityFeatures {
            relro,  // Now using actual analysis
            pie: PieStatus::NonPIE,    // TODO: Implement actual analysis
            nx: NxStatus::NoNX,        // TODO: Implement actual analysis
            canary: CanaryStatus::Disabled, // TODO: Implement actual analysis
            fortify_source: FortifyStatus::Disabled, // TODO: Implement actual analysis
        };

        Ok(Self {
            path,
            architecture,
            security_features,
        })
    }
    
    pub fn security_score(&self) -> u8 {
        let mut score = 0;
        
        // Add points for each security feature
        match self.security_features.relro {
            RelroStatus::Full => score += 2,
            RelroStatus::Partial => score += 1,
            RelroStatus::None => {},
        }
        
        match self.security_features.pie {
            PieStatus::PIE => score += 2,
            PieStatus::NonPIE => {},
        }
        
        match self.security_features.nx {
            NxStatus::NX => score += 2,
            NxStatus::NoNX => {},
        }
        
        match self.security_features.canary {
            CanaryStatus::Enabled => score += 2,
            CanaryStatus::Disabled => {},
        }
        
        match self.security_features.fortify_source {
            FortifyStatus::Enabled => score += 2,
            FortifyStatus::Disabled => {},
        }
        
        score
    }
    
    pub fn generate_report(&self) -> String {
        format!(
            "Binary Analysis Report for: {}\n\
             Architecture: {:?}\n\
             Security Features:\n\
             - RELRO: {:?}\n\
             - PIE: {:?}\n\
             - NX: {:?}\n\
             - Stack Canary: {:?}\n\
             - FORTIFY_SOURCE: {:?}\n\
             Security Score: {}/10",
            self.path.display(),
            self.architecture,
            self.security_features.relro,
            self.security_features.pie,
            self.security_features.nx,
            self.security_features.canary,
            self.security_features.fortify_source,
            self.security_score()
        )
    }
}
