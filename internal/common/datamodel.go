package common

type ThreatModel struct {
	Assets []Asset
	Extra  map[string]any
}

func EmptyThreatModel() ThreatModel {
	return ThreatModel{
		Assets: make([]Asset, 0),
		Extra:  make(map[string]any),
	}
}

const MaxIDHashLength = 32

type Asset struct {
	ID          string
	DisplayName string
	Type        AssetType
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
