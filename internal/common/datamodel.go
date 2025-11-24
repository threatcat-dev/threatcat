package common

type ThreatModel struct {
	Assets     []Asset
	DataFlows  []DataFlow
	Boundaries []TrustBoundary
	Extra      map[string]any
}

func EmptyThreatModel() ThreatModel {
	return ThreatModel{
		Assets:     make([]Asset, 0),
		DataFlows:  make([]DataFlow, 0),
		Boundaries: nil,
		Extra:      make(map[string]any),
	}
}

const MaxIDHashLength = 32

type Asset struct {
	ID          string
	DisplayName string
	Type        AssetType
	Threats     []Threat
	Source      DataSource
	Extra       map[string]any
}

type AssetType int

const (
	AssetTypeUnknown AssetType = iota
	AssetTypeApplication
	AssetTypeDatabase
	AssetTypeWebserver
	AssetTypeInfrastructure
	//AssetTypeDataFlow
)

func (assetType AssetType) String() string {
	switch assetType {
	case AssetTypeApplication:
		return "AssetTypeApplication"
	case AssetTypeDatabase:
		return "AssetTypeDatabase"
	case AssetTypeWebserver:
		return "AssetTypeWebserver"
	}
	return "AssetTypeUnknown"
}

type DataSource int

const (
	DataSourceUnknown DataSource = iota
	DataSourceThreatDragon
	DataSourceDockerCompose
	DataSourceMerged
)

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

type ThreatType int

const (
	ThreatTypeUnknown ThreatType = iota
	Spoofing
	Tampering
	Repudiation
	InformationDisclosure
	DenialOfService
	ElevationOfPrivilege
	// Integrity
	// Availability
	// Confidentiality
)

type ModelType int

const (
	STRIDE ModelType = iota //currently only STRIDE is supported
	NotSupported
	// CIA
	// DIE
	// LINDDUN
	// PLOT4ai
	// Generic
)

type Status int

const (
	Open Status = iota
	Mitigated
	NotApplicable
	UnknownStatus
)

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

// TypeString converts the ThreatType enum to the corresponding threat type string
func TypeString(threatType ThreatType) string {
	switch threatType {
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

// ModelString converts the ModelType enum to the corresponding model type string
func ModelString(modelType ModelType) string {
	switch modelType {
	case STRIDE:
		return "STRIDE"
	default:
		return "NotSupported"
	}
}

// StatusString converts the Status enum to the corresponding status string
func StatusString(status Status) string {
	switch status {
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

// ThreatType converts the threat type string to the corresponding ThreatType enum
func ThreatThreatType(threatType string) ThreatType {
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

// ThreatModelType converts the model type string to the corresponding ModelType enum
func ThreatModelType(modelType string) ModelType {
	switch modelType {
	case "STRIDE":
		return STRIDE
	default:
		return NotSupported
	}
}

// ThreatStatus converts the status string to the corresponding Status enum
func ThreatStatus(status string) Status {
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

type DataFlow struct {
	ID            string
	Name          string `yaml:"name"`
	Protocol      string `yaml:"protocol"`
	Encrypted     bool   `yaml:"encrypted"`
	PublicNetwork bool   `yaml:"publicnetwork"`
	Source        string `yaml:"source"`
	Target        string `yaml:"target"`
	Bidirectional bool   `yaml:"bidirectional"`
}

type TrustBoundary struct {
	ID              string
	DisplayName     string
	ContainedAssets []string
	Source          DataSource
	Extra           map[string]any
}
