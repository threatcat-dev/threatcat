// Package common provides core data models and utilities for threat modeling.
// It defines the fundamental types used across the threat modeling tool, including
// ThreatModel, Asset, DataFlow, TrustBoundary, and associated enumerations following
// the STRIDE threat model (Spoofing, Tampering, Repudiation, Information Disclosure,
// Denial of Service, Elevation of Privilege).
package common

// MaxIDHashLength defines the number of characters to use from the SHA-256 hash for the ID.
// This constant is set to 32 characters (half of a SHA-256 hash in hexadecimal),
// providing sufficient uniqueness while keeping IDs reasonably short.
const MaxIDHashLength = 32

// ThreatModel represents the internal threat model containing assets, data flows, trust boundaries and extra metadata.
// This is the central data structure that aggregates all components of a threat model.
//
// Fields:
//   - Assets: all components/systems in the model (applications, databases, servers, etc.)
//   - DataFlows: communication channels and data exchanges between assets
//   - Boundaries: trust boundaries that group assets by security context
//   - Extra: additional data
type ThreatModel struct {
	Assets     []Asset
	DataFlows  []DataFlow
	Boundaries []TrustBoundary
	Extra      map[string]any
}

// EmptyThreatModel creates and returns an empty ThreatModel instance with properly initialized fields.
//
// Returns:
//   - ThreatModel with empty but initialized slices for Assets and DataFlows,
//     nil Boundaries, and an empty Extra map
//
// This constructor ensures all non-nil fields are initialized, preventing
// nil pointer panics when adding elements to a new threat model.
func EmptyThreatModel() ThreatModel {
	return ThreatModel{
		Assets:     make([]Asset, 0),
		DataFlows:  make([]DataFlow, 0),
		Boundaries: nil,
		Extra:      make(map[string]any),
	}
}

// Asset represents an asset within the threat model, including its ID, display name, type, associated threats, data source, and extra metadata.
// An asset is any component or system that processes, stores, or transmits data.
//
// Fields:
//   - ID: unique identifier (typically a hash generated from file path and name)
//   - DisplayName: human-readable name shown in UI and reports
//   - Type: classification (Application, Database, Webserver, Infrastructure)
//   - Threats: list of threats associated with this asset
//   - Source: origin of this asset (ThreatDragon, DockerCompose, or Merged)
//   - Extra: additional data
type Asset struct {
	ID          string
	DisplayName string
	Type        AssetType
	Threats     []Threat
	Source      DataSource
	Extra       map[string]any
}

// AssetType defines the type of asset in the threat model.
type AssetType int

const (
	// AssetTypeUnknown represents an asset with an unspecified or unknown type.
	AssetTypeUnknown AssetType = iota
	// AssetTypeApplication represents an application or service asset.
	AssetTypeApplication
	// AssetTypeDatabase represents a database system asset.
	AssetTypeDatabase
	// AssetTypeWebserver represents a web server asset.
	AssetTypeWebserver
	// AssetTypeInfrastructure represents an infrastructure component asset.
	AssetTypeInfrastructure
)

// String converts the AssetType enum to the corresponding string representation.
//
// Returns:
//   - String representation of the asset type
//   - "AssetTypeUnknown" for unknown or invalid enum values
//
// Implements the fmt.Stringer interface for use in formatting and logging.
func (assetType AssetType) String() string {
	switch assetType {
	case AssetTypeApplication:
		return "AssetTypeApplication"
	case AssetTypeDatabase:
		return "AssetTypeDatabase"
	case AssetTypeWebserver:
		return "AssetTypeWebserver"
	case AssetTypeInfrastructure:
		return "AssetTypeInfrastructure"
	}
	return "AssetTypeUnknown"
}

// DataSource defines the source of the data within the threat model.
type DataSource int

const (
	// DataSourceUnknown represents an unknown or unspecified data source.
	DataSourceUnknown DataSource = iota
	// DataSourceThreatDragon represents data sourced from OWASP Threat Dragon models.
	DataSourceThreatDragon
	// DataSourceDockerCompose represents data sourced from Docker Compose files.
	DataSourceDockerCompose
	// DataSourceMerged represents data merged from multiple sources.
	DataSourceMerged
)

// ShortString converts the DataSource enum to a short, human-readable string representation.
//
// Returns:
//   - Short display name for the data source
//   - "Unknown" for invalid or unspecified sources
//
// These short strings are designed for display in logs, UI elements, and error messages.
func (dataSource DataSource) ShortString() string {
	switch dataSource {
	case DataSourceUnknown:
		return "Unknown"
	case DataSourceThreatDragon:
		return "Threat Dragon"
	case DataSourceDockerCompose:
		return "Docker Compose"
	case DataSourceMerged:
		return "Merged"
	}
	return "Unknown"
}

// ThreatType defines the type of threat in the threat model.
type ThreatType int

const (
	// ThreatTypeUnknown represents an unknown or unspecified threat type.
	ThreatTypeUnknown ThreatType = iota
	// Spoofing represents threats related to identity spoofing (STRIDE).
	Spoofing
	// Tampering represents threats related to data or code tampering (STRIDE).
	Tampering
	// Repudiation represents threats where actions cannot be traced (STRIDE).
	Repudiation
	// InformationDisclosure represents threats of information exposure (STRIDE).
	InformationDisclosure
	// DenialOfService represents threats that deny service to users (STRIDE).
	DenialOfService
	// ElevationOfPrivilege represents threats of unauthorized privilege escalation (STRIDE).
	ElevationOfPrivilege
	//The following are currently not supported due to only supporting STRIDE
	// Integrity
	// Availability
	// Confidentiality
)

// String returns the string representation of the ThreatType.
//
// Returns:
//   - Human-readable name of the threat type (e.g., "Spoofing", "Tampering")
//   - "ThreatTypeUnknown" for invalid or unspecified threat types
//
// The returned strings match the STRIDE threat model terminology.
// Implements the fmt.Stringer interface.
func (t ThreatType) String() string {
	switch t {
	case Spoofing:
		return "Spoofing"
	case Tampering:
		return "Tampering"
	case Repudiation:
		return "Repudiation"
	case InformationDisclosure:
		return "Information disclosure"
	case DenialOfService:
		return "Denial of service"
	case ElevationOfPrivilege:
		return "Elevation of privilege"
	default:
		return "ThreatTypeUnknown"
	}
}

// ModelType defines the type of threat model.
type ModelType int

const (
	// STRIDE represents the STRIDE threat modeling methodology (currently only STRIDE is supported).
	STRIDE ModelType = iota
	// NotSupported represents an unsupported or unrecognized threat model type.
	NotSupported
	// CIA
	// DIE
	// LINDDUN
	// PLOT4ai
	// Generic
)

// String returns the string representation of the ModelType.
//
// Returns:
//   - "STRIDE" for the STRIDE threat model (currently the only supported type)
//   - "NotSupported" for unsupported or invalid model types
//
// Implements the fmt.Stringer interface.
func (m ModelType) String() string {
	switch m {
	case STRIDE:
		return "STRIDE"
	default:
		return "NotSupported"
	}
}

// Status defines the status of a threat in the threat model.
type Status int

const (
	// Open indicates that a threat has been identified but not yet addressed.
	Open Status = iota
	// Mitigated indicates that a threat has been mitigated or resolved.
	Mitigated
	// NotApplicable indicates that a threat is not applicable to the current context.
	NotApplicable
	// UnknownStatus indicates that the threat status is unknown or unspecified.
	UnknownStatus
)

// String returns the string representation of the Status.
//
// Returns:
//   - "Open" for identified but unaddressed threats
//   - "Mitigated" for resolved threats
//   - "Not Applicable" for threats that don't apply
//   - "UnknownStatus" for invalid or unspecified status values
//
// Implements the fmt.Stringer interface.
func (s Status) String() string {
	switch s {
	case Open:
		return "Open"
	case Mitigated:
		return "Mitigated"
	case NotApplicable:
		return "Not Applicable"
	default:
		return "UnknownStatus"
	}
}

// Threat represents a threat within the threat model, including its ID, title, status, severity, type, description, mitigation, model type, and other metadata.
// A threat represents a potential security risk associated with an asset or data flow.
//
// Fields:
//   - InternalID: internal unique identifier for tracking
//   - ID: external/display identifier
//   - Title: short, descriptive name of the threat
//   - Status: current state (Open, Mitigated, NotApplicable, UnknownStatus)
//   - Severity: severity level (e.g., "High", "Medium", "Low")
//   - Type: STRIDE category (Spoofing, Tampering, Repudiation, etc.)
//   - Description: detailed explanation of the threat
//   - Mitigation: recommended actions to address the threat
//   - ModelType: threat modeling methodology used (e.g., STRIDE)
//   - Number: sequence number for ordering
//   - Score: risk score or rating
//   - IsGeneratedByUser: true if manually added, false if auto-generated
//   - Source: origin of this threat (ThreatDragon, DockerCompose, or Merged)
//   - MapIndex: index in original model's threat list (-1 if not applicable or shouldn't be searched)
type Threat struct {
	InternalID        string
	ID                string
	Title             string
	Status            Status
	Severity          string
	Type              ThreatType
	Description       string
	Mitigation        string
	ModelType         ModelType
	Number            int64
	Score             string
	IsGeneratedByUser bool
	Source            DataSource
	MapIndex          int //index in the original model's threat list (set to -1 if not applicable) (then it will not be searched for in existing threats)
}

// ParseThreatType converts a threat type string to the corresponding ThreatType enum.
//
// Parameters:
//   - threatType: string representation of a threat type (e.g., "Spoofing", "Tampering")
//
// Returns:
//   - Corresponding ThreatType enum value
//   - ThreatTypeUnknown if the string doesn't match any known STRIDE threat type
//
// This function is case-sensitive and expects exact matches to STRIDE terminology.
// Used when deserializing threat models from JSON, YAML, or other formats.
func ParseThreatType(threatType string) ThreatType {
	switch threatType {
	case "Spoofing":
		return Spoofing
	case "Tampering":
		return Tampering
	case "Repudiation":
		return Repudiation
	case "Information disclosure":
		return InformationDisclosure
	case "Denial of service":
		return DenialOfService
	case "Elevation of privilege":
		return ElevationOfPrivilege
	default:
		return ThreatTypeUnknown
	}
}

// ParseModelType converts a model type string to the corresponding ModelType enum.
//
// Parameters:
//   - modelType: string representation of a threat model type (e.g., "STRIDE")
//
// Returns:
//   - Corresponding ModelType enum value
//   - NotSupported if the string doesn't match any known model type
//
// Currently only "STRIDE" is supported. Used when parsing threat model metadata.
func ParseModelType(modelType string) ModelType {
	switch modelType {
	case "STRIDE":
		return STRIDE
	default:
		return NotSupported
	}
}

// ParseStatus converts a status string to the corresponding Status enum.
//
// Parameters:
//   - status: string representation of a threat status (e.g., "Open", "Mitigated")
//
// Returns:
//   - Corresponding Status enum value
//   - UnknownStatus if the string doesn't match any known status
//
// Recognized values are "Open", "Mitigated", and "Not Applicable".
// Used when loading saved threat models or importing from external tools.
func ParseStatus(status string) Status {
	switch status {
	case "Open":
		return Open
	case "Mitigated":
		return Mitigated
	case "Not Applicable":
		return NotApplicable
	default:
		return UnknownStatus
	}
}

// DataFlow represents a data flow within the threat model, including its ID, name, protocol, encryption status, source and target assets, associated threats, data source, and extra metadata.
// A data flow represents communication or data exchange between two assets.
//
// Fields:
//   - ID: unique identifier for this data flow
//   - Name: descriptive name of the data flow
//   - Protocol: communication protocol (e.g., "HTTPS", "TCP", "gRPC")
//   - Encrypted: true if communication is encrypted (e.g., TLS/SSL)
//   - PublicNetwork: true if data flows over public/untrusted networks (e.g., internet)
//   - Source: ID of the source asset
//   - Target: ID of the target asset
//   - Bidirectional: true if data flows in both directions
//   - Threats: list of threats associated with this data flow
//   - DataSource: origin of this data flow definition
//   - IsGeneratedByUser: true if manually defined, false if auto-discovered
//   - Extra: additional metadata for tool-specific extensions
type DataFlow struct {
	ID                string
	Name              string `yaml:"name"`
	Protocol          string `yaml:"protocol"`
	Encrypted         bool   `yaml:"encrypted"`
	PublicNetwork     bool   `yaml:"publicnetwork"`
	Source            string `yaml:"source"`
	SourceID          string
	Target            string `yaml:"target"`
	TargetID          string
	Bidirectional     bool `yaml:"bidirectional"`
	Threats           []Threat
	DataSource        DataSource
	IsGeneratedByUser bool
	Extra             map[string]any
}

// TrustBoundary represents a trust boundary within the threat model, including its ID, display name, contained assets, data source, and extra metadata.
// A trust boundary groups assets that share the same security context or trust level.
//
// Fields:
//   - ID: unique identifier for this trust boundary
//   - DisplayName: human-readable name shown in UI and diagrams
//   - ContainedAssets: list of asset IDs within this boundary
//   - Source: origin of this trust boundary definition
//   - Extra: additional metadata for tool-specific extensions
//
// Trust boundaries are important for identifying where data crosses security contexts,
// which often represents higher-risk attack surfaces.
type TrustBoundary struct {
	ID              string
	DisplayName     string
	ContainedAssets []string
	Source          DataSource
	Extra           map[string]any
}
