package dockercompose

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"maps"

	"github.com/threatcat-dev/threatcat/internal/common"
	"gopkg.in/yaml.v3"
)

type DockerImageMap map[string]common.AssetType

// NewDockerImageMap creates a new DockerImageMap instance.
// It initializes the DockerImageMap with a predefined set of images.
// If a configPath is provided, it reads the Docker image map configuration from the specified YAML file
// and merges it with the internal image map.
func NewDockerImageMap(configPath string) (DockerImageMap, error) {
	// Create a copy of the internal image map to avoid modifying the original
	copiedMap := maps.Clone(internalImageMap)

	// If a config path is provided, read the Docker image map configuration
	if configPath != "" {
		externalImageMap, err := readDockerImageMapConfig(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read Docker image map config: %w", err)
		}
		// Merge the external image map into the copied internal image map
		if err := mergeDockerImageMaps(copiedMap, externalImageMap); err != nil {
			return nil, fmt.Errorf("failed to merge Docker image maps: %w", err)
		}
	}

	return copiedMap, nil
}

// mergeDockerImageMaps merges the external Docker image map into the internal Docker image map.
// It adds the images from the external map to the internal map, overwriting any existing entries
// with the same image name.
func mergeDockerImageMaps(internalImageMap DockerImageMap, externalImageMap DockerImageMap) error {
	if internalImageMap == nil || externalImageMap == nil {
		return fmt.Errorf("no image maps to merge")
	}

	maps.Copy(internalImageMap, externalImageMap)
	return nil
}

// readDockerImageMapConfig reads the Docker image map configuration from a YAML file.
// It returns a DockerImageMap containing the images and their corresponding asset types.
func readDockerImageMapConfig(configFilePath string) (DockerImageMap, error) {
	//get the configuration
	config, err := readConfig(configFilePath)
	if err != nil {
		return nil, err
	}

	// Initialize the DockerImageMap to hold the images and their asset types
	result := make(DockerImageMap)

	// Populate the DockerImageMap with images from the configuration
	result.addImagesToMap(config.Applications, common.AssetTypeApplication)
	result.addImagesToMap(config.Databases, common.AssetTypeDatabase)
	result.addImagesToMap(config.Webservers, common.AssetTypeWebserver)
	result.addImagesToMap(config.Infrastructure, common.AssetTypeInfrastructure)

	return result, nil
}

// determineAssetType determines the asset type based on the service image
func (m DockerImageMap) determineAssetType(image string, logger *slog.Logger) common.AssetType {
	logger = logger.With("sub-component", "DockerImageMap")
	imageName := getImageName(image)
	logger.Debug("Attempting to determine asset type", "image", image, "extractedName", imageName)
	logger = logger.With("imageName", imageName)
	logger.Info("Searching image map for direct match")
	if assetType, exists := m[imageName]; exists {
		return assetType
	}
	logger.Debug("No direct match. Expanding search")
	for key, assetType := range m {
		imageName := removeVersion(image)
		if strings.HasSuffix(imageName, key) {
			return assetType
		}
	}
	logger.Debug("No asset type found. Defaulting to AssetTypeUnknown")
	return common.AssetTypeUnknown
}

func removeVersion(image string) string {
	return strings.Split(image, ":")[0]
}

// getImageName extracts the image name from the full image string
func getImageName(image string) string {
	// Get the image name without the tag and registry/repository
	parts := strings.Split(image, "/")
	nameWithoutRegistry := parts[len(parts)-1]
	return strings.Split(nameWithoutRegistry, ":")[0]
}

// addImagesToMap adds a list of images to the DockerImageMap with the specified asset type.
// It iterates over the provided images and assigns the given asset type to each image in the
// DockerImageMap.
func (m DockerImageMap) addImagesToMap(images []string, assetType common.AssetType) {
	for _, image := range images {
		m[image] = assetType
	}
}

// readConfig reads the Docker image configuration from a YAML file
// and returns a DockerImageConfig struct containing the categorized lists of images.
func readConfig(configFilePath string) (*DockerImageConfig, error) {
	file, err := os.Open(configFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config DockerImageConfig
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// DockerImageConfig represents the structure of the Docker image configuration file
// It contains lists of images categorized by their asset types
type DockerImageConfig struct {
	Applications   []string `yaml:"applications"`
	Databases      []string `yaml:"databases"`
	Webservers     []string `yaml:"webservers"`
	Infrastructure []string `yaml:"infrastructure"`
}

// internalImageMap is a predefined map of Docker images to their asset types.
// This map is used as a default set of known images and their classifications.
var internalImageMap = DockerImageMap{
	//Applications
	"vitess/lite":            common.AssetTypeApplication,
	"vault":                  common.AssetTypeApplication,
	"portainer":              common.AssetTypeApplication,
	"portainer/portainer-ce": common.AssetTypeApplication,
	"grafana":                common.AssetTypeApplication,
	"promtail":               common.AssetTypeApplication,
	"loki":                   common.AssetTypeApplication,
	"artifactory-resource":   common.AssetTypeApplication,
	"drupal":                 common.AssetTypeApplication,
	"mimir":                  common.AssetTypeApplication,
	"cassandra":              common.AssetTypeApplication,
	"znc":                    common.AssetTypeApplication,
	"irssi":                  common.AssetTypeApplication,
	"radarr":                 common.AssetTypeApplication,
	"sonarr":                 common.AssetTypeApplication,
	"jackett":                common.AssetTypeApplication,
	"wordpress":              common.AssetTypeApplication,
	"joomla":                 common.AssetTypeApplication,
	"monica":                 common.AssetTypeApplication,
	"redmine":                common.AssetTypeApplication,
	"xwiki":                  common.AssetTypeApplication,
	"mediawiki":              common.AssetTypeApplication,
	"backdrop":               common.AssetTypeApplication,
	"geonetwork":             common.AssetTypeApplication,
	"gazebo":                 common.AssetTypeApplication,
	"convertigo":             common.AssetTypeApplication,
	"odoo":                   common.AssetTypeApplication,
	"fiendica":               common.AssetTypeApplication,
	"silverpeas":             common.AssetTypeApplication,
	"rocket.chat":            common.AssetTypeApplication,
	"plone":                  common.AssetTypeApplication,
	"bonita":                 common.AssetTypeApplication,
	"lightstreamer":          common.AssetTypeApplication,
	"eggdrop":                common.AssetTypeApplication,
	// These were previously classified as AssetTypeApplication, but are now classified as AssetTypeUnknown,
	// as they are not specific applications but rather base images or distributions that can be used for various purposes.
	"busybox":     common.AssetTypeUnknown,
	"alpine":      common.AssetTypeUnknown,
	"ubuntu":      common.AssetTypeUnknown,
	"debian":      common.AssetTypeUnknown,
	"rockylinux":  common.AssetTypeUnknown,
	"ros":         common.AssetTypeUnknown,
	"archlinux":   common.AssetTypeUnknown,
	"photon":      common.AssetTypeUnknown,
	"almalinux":   common.AssetTypeUnknown,
	"clearlinux":  common.AssetTypeUnknown,
	"cirros":      common.AssetTypeUnknown,
	"mageia":      common.AssetTypeUnknown,
	"alt":         common.AssetTypeUnknown,
	"oraclelinux": common.AssetTypeUnknown,
	//Databases
	"postgres":   common.AssetTypeDatabase,
	"mongo":      common.AssetTypeDatabase,
	"mysql":      common.AssetTypeDatabase,
	"mariadb":    common.AssetTypeDatabase,
	"influxdb":   common.AssetTypeDatabase,
	"neo4j":      common.AssetTypeDatabase,
	"percona":    common.AssetTypeDatabase,
	"couchdb":    common.AssetTypeDatabase,
	"arangodb":   common.AssetTypeDatabase,
	"couchbase":  common.AssetTypeDatabase,
	"rethinkdb":  common.AssetTypeDatabase,
	"crate":      common.AssetTypeDatabase,
	"aerospike":  common.AssetTypeDatabase,
	"orientdb":   common.AssetTypeDatabase,
	"clickhouse": common.AssetTypeDatabase,

	//Webservers
	"nginx":              common.AssetTypeWebserver,
	"httpd":              common.AssetTypeWebserver,
	"haproxy":            common.AssetTypeWebserver,
	"tomcat":             common.AssetTypeWebserver,
	"caddy":              common.AssetTypeWebserver,
	"jetty":              common.AssetTypeWebserver,
	"tomee":              common.AssetTypeWebserver,
	"istio/proxyv2":      common.AssetTypeWebserver,
	"pomerium":           common.AssetTypeWebserver,
	"nginx-unprivileged": common.AssetTypeWebserver,
	"phpmyadmin":         common.AssetTypeWebserver,
	"unit":               common.AssetTypeWebserver,
	"notary":             common.AssetTypeWebserver,
	"postfixadmin":       common.AssetTypeWebserver,

	//infrastructure
	"sapmachine":                      common.AssetTypeInfrastructure,
	"watchtower":                      common.AssetTypeInfrastructure,
	"fluent-bit":                      common.AssetTypeInfrastructure,
	"memcached":                       common.AssetTypeInfrastructure,
	"datadog/agent":                   common.AssetTypeInfrastructure,
	"redis":                           common.AssetTypeInfrastructure,
	"python":                          common.AssetTypeInfrastructure,
	"curl":                            common.AssetTypeInfrastructure,
	"envoyproxy/envoy":                common.AssetTypeInfrastructure,
	"node":                            common.AssetTypeInfrastructure,
	"kubectl":                         common.AssetTypeInfrastructure,
	"jenkins":                         common.AssetTypeInfrastructure,
	"timberio/vector":                 common.AssetTypeInfrastructure,
	"rabbitmq":                        common.AssetTypeInfrastructure,
	"gitlab-runner":                   common.AssetTypeInfrastructure,
	"prom/node-exporter":              common.AssetTypeInfrastructure,
	"newrelic/infrastructure-bundle":  common.AssetTypeInfrastructure,
	"traefik":                         common.AssetTypeInfrastructure,
	"docker":                          common.AssetTypeInfrastructure,
	"eclipse-mosquitto":               common.AssetTypeInfrastructure,
	"sealed-secrets-controller":       common.AssetTypeInfrastructure,
	"aws-for-fluent-bit":              common.AssetTypeInfrastructure,
	"percona-xtradb-cluster-operator": common.AssetTypeInfrastructure,
	"golang":                          common.AssetTypeInfrastructure,
	"nri-kubernetes":                  common.AssetTypeInfrastructure,
	"prom/prometheus":                 common.AssetTypeInfrastructure,
	"minio":                           common.AssetTypeInfrastructure,
	"registry":                        common.AssetTypeInfrastructure,
	"cloudwatch-agent":                common.AssetTypeInfrastructure,
	"pi-node-docker":                  common.AssetTypeInfrastructure,
	"github-pr-resource":              common.AssetTypeInfrastructure,
	"ruby":                            common.AssetTypeInfrastructure,
	"airflow":                         common.AssetTypeInfrastructure,
	"api-firewall":                    common.AssetTypeInfrastructure,
	"k8s-sidecar":                     common.AssetTypeInfrastructure,
	"lacework/datacollector":          common.AssetTypeInfrastructure,
	"laws-xray-daemon":                common.AssetTypeInfrastructure,
	"portainer/agent":                 common.AssetTypeInfrastructure,
	"amazon-ecs-agent":                common.AssetTypeInfrastructure,
	"php":                             common.AssetTypeInfrastructure,
	"newrelic-fluentbit-output":       common.AssetTypeInfrastructure,
	"openvpn":                         common.AssetTypeInfrastructure,
	"aws-cli":                         common.AssetTypeInfrastructure,
	"dynatrace-operator":              common.AssetTypeInfrastructure,
	"rust":                            common.AssetTypeInfrastructure,
	"flink":                           common.AssetTypeInfrastructure,
	"groovy":                          common.AssetTypeInfrastructure,
	"erlang":                          common.AssetTypeInfrastructure,
	"elixir":                          common.AssetTypeInfrastructure,
	"kapacitor":                       common.AssetTypeInfrastructure,
	"jruby":                           common.AssetTypeInfrastructure,
	"pypy":                            common.AssetTypeInfrastructure,
	"clojure":                         common.AssetTypeInfrastructure,
	"swift":                           common.AssetTypeInfrastructure,
	"hylang":                          common.AssetTypeInfrastructure,
	"gcc":                             common.AssetTypeInfrastructure,
	"haxe":                            common.AssetTypeInfrastructure,
	"yourls":                          common.AssetTypeInfrastructure,
	"varnish":                         common.AssetTypeInfrastructure,
	"julia":                           common.AssetTypeInfrastructure,
	"ibmjava":                         common.AssetTypeInfrastructure,
	"fluentd":                         common.AssetTypeInfrastructure,
	"r-base":                          common.AssetTypeInfrastructure,
	"neurodebian":                     common.AssetTypeInfrastructure,
	"strom":                           common.AssetTypeInfrastructure,
	"haskell":                         common.AssetTypeInfrastructure,
	"ibm-semeru-runtimes":             common.AssetTypeInfrastructure,
	"spiped":                          common.AssetTypeInfrastructure,
	"swipl":                           common.AssetTypeInfrastructure,
	"emqx":                            common.AssetTypeInfrastructure,
	"dart":                            common.AssetTypeInfrastructure,
	"rakudo-star":                     common.AssetTypeInfrastructure,
	"spark":                           common.AssetTypeInfrastructure,
	"satosa":                          common.AssetTypeInfrastructure,
	"krakend":                         common.AssetTypeInfrastructure,
	"liquibase":                       common.AssetTypeInfrastructure,
}
