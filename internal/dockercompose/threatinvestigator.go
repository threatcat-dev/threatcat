// This file implements functionality for scanning services for security threats using STRIDE.
// It applies a series of checks to identify potential security issues in Docker Compose service configurations and generates corresponding Threat instances.

package dockercompose

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/compose-spec/compose-go/v2/types"
	"github.com/threatcat-dev/threatcat/internal/common"
)

// secretKeywordRegex matches common secret keywords (case-insensitive)
var secretKeywordRegex = regexp.MustCompile("(?i)(user|password|secret|token|api[_-]*key|key|certificate)")

// DockerComposeThreatInvestigator investigates threats in Docker Compose services
type DockerComposeThreatInvestigator struct {
	logger *slog.Logger
}

// NewDockerComposeThreatInvestigator creates a new instance of DockerComposeThreatInvestigator
func NewDockerComposeThreatInvestigator(logger *slog.Logger) *DockerComposeThreatInvestigator {
	return &DockerComposeThreatInvestigator{
		logger: logger.With("package", "dockercompose", "component", "DockerComposeThreatInvestigator"),
	}
}

// InvestigateForThreats investigates the given service for potential threats and returns a list of threats
// the returned list of threats is empty if no threats were found
func (ti *DockerComposeThreatInvestigator) InvestigateForThreats(service types.ServiceConfig) []common.Threat {
	// Slice of investigation functions to be applied to the service
	investigationFunctions := []func(types.ServiceConfig) []common.Threat{
		ti.checkForBindMounts,
		ti.checkForHardcodedSecrets,
		ti.checkForPoorLoggingConfiguration,
		ti.checkForPrivilegedContainers,
		ti.checkForPublishedPorts,
		ti.checkForRootUser,
		ti.checkForUnlimitedResources,
		ti.checkForUnspecificImageVersion,
		// Additional investigation functions can be added here
	}

	ti.logger.Debug("Beginning docker-compose threat investigation for service", "service.Name", service.Name)
	threats := make([]common.Threat, 0)
	// Apply each investigation function to the service
	for _, ivgFunc := range investigationFunctions {
		ivgdThreats := ivgFunc(service)
		for _, threat := range ivgdThreats {
			ti.logger.Debug("Found threat", "threat.Title", threat.Title)
			threats = append(threats, threat)
		}
	}
	ti.logger.Info("Identified threats for service", "threat_count", len(threats), "service.Name", service.Name)
	return threats
}

// checkForBindMounts checks if the service is using bind mounts and returns Threats if found
func (ti *DockerComposeThreatInvestigator) checkForBindMounts(service types.ServiceConfig) []common.Threat {
	ti.logger.Debug("Checking for bind mounts", "service.Name", service.Name)

	threats := []common.Threat{}

	// If there are no volumes defined, return no threats
	if service.Volumes == nil {
		return threats
	}

	for _, volume := range service.Volumes {
		ti.logger.Debug("Checking volume for Bind Mounts", "source", volume.Source)

		// Skip named volumes
		if strings.EqualFold(volume.Type, "volume") {
			continue
		}

		// Check if the volume is mounting the Docker socket
		if ti.isDockerSocket(volume.Source) {
			threatTitle := fmt.Sprintf("Mounts Docker Socket '%s'", volume.Source)
			threatType := common.ElevationOfPrivilege
			description := fmt.Sprintf("The service mounts the Docker socket ('%s'), which can expose full Docker control to the container. An attacker who compromises the container could exploit this to gain elevated privileges on the host system.", volume.Source)
			mitigation := "Avoid mounting the Docker socket. Use alternative methods for Docker communication that do not expose the socket directly."
			threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
			continue
		}

		// Check if the volume is a bind mount
		// A volume is considered a bind mount if:
		// - volume.Bind is not nil
		// - volume.Type is "bind" (case-insensitive)
		// - volume.Type is empty and the source path appears to be a host path
		if strings.EqualFold(volume.Type, "bind") || volume.Bind != nil || (volume.Type == "" && ti.isHostPath(volume.Source)) {
			// General bind mount threat
			secondThreatTitle := fmt.Sprintf("Bind Mount '%s'", volume.Source)
			secondThreatType := common.Tampering
			secondDescription := fmt.Sprintf("The service uses a bind mount ('%s'), which can expose the host filesystem to the container. An attacker who compromises the container could exploit this to modify sensitive host files.", volume.Source)
			secondMitigation := "Avoid using bind mounts. Use named volumes or other storage solutions that do not expose the host filesystem directly."
			threats = append(threats, ti.generateThreat(service.Name, secondThreatTitle, secondThreatType, secondDescription, secondMitigation))
		}
	}

	return threats
}

// checkForHardcodedSecrets checks for hardcoded secrets in command arguments and environment variables
func (ti *DockerComposeThreatInvestigator) checkForHardcodedSecrets(service types.ServiceConfig) []common.Threat {
	ti.logger.Debug("Checking for hardcoded secrets", "service.Name", service.Name)

	threats := []common.Threat{}

	// Check command arguments for hardcoded secrets
	for _, v := range service.Command {
		ti.logger.Debug("Checking command argument", "value", v)
		if secretKeywordRegex.MatchString(v) {
			// Extract the key part if the argument is in key=value format
			secretKey := v
			if strings.Contains(v, "=") {
				secretKey = strings.Split(v, "=")[0]
			}
			threatTitle := fmt.Sprintf("Hardcoded Secret in Command Arguments '%s'", secretKey)
			threatType := common.InformationDisclosure
			description := fmt.Sprintf("The service has a hardcoded secret in its command arguments ('%s'). An attacker who gains access to the command arguments could exploit this secret to compromise the service or related systems.", secretKey)
			mitigation := "Avoid hardcoding secrets in command arguments. Use secret management solutions like Docker Secrets or environment variable injection at runtime."
			threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
		}
	}

	// Check environment variables for hardcoded secrets
	for k, v := range service.Environment {
		ti.logger.Debug("Checking environment variable", "key", k, "value", v)
		if secretKeywordRegex.MatchString(k) && v != nil && *v != "" {
			threatTitle := fmt.Sprintf("Hardcoded Secret in Environment Variables '%s'", k)
			threatType := common.InformationDisclosure
			description := fmt.Sprintf("The service has a hardcoded secret in its environment variables ('%s'). An attacker who gains access to the environment variables could exploit this secret to compromise the service or related systems.", k)
			mitigation := "Avoid hardcoding secrets in environment variables. Use secret management solutions like Docker Secrets or environment variable injection at runtime."
			threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
		}
	}

	return threats
}

// checkForPoorLoggingConfiguration checks if the service has a poor logging configuration
func (ti *DockerComposeThreatInvestigator) checkForPoorLoggingConfiguration(service types.ServiceConfig) []common.Threat {
	ti.logger.Debug("Checking for poor logging configuration", "service.Name", service.Name)

	threats := []common.Threat{}

	// Check if logging is not configured or disabled
	// If Logging is nil or Driver is empty, logging is seen as not configured
	if service.Logging == nil || service.Logging.Driver == "" {
		threatTitle := "No specific Logging Configuration"
		threatType := common.Repudiation
		description := "The service does not have a specific logging configuration defined. Poor logging practices can hinder incident response and forensic investigations, making it difficult to trace malicious activities."
		mitigation := "Implement a robust logging configuration for the service, ensuring that logs are securely stored and monitored for suspicious activities."
		threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
		return threats
	}

	// If Logging Driver is set to "none", logging is disabled
	if strings.EqualFold(service.Logging.Driver, "none") {
		threatTitle := "Logging Disabled"
		threatType := common.Repudiation
		description := "The service has logging disabled. Without proper logging, it becomes challenging to monitor activities, detect anomalies, and investigate incidents."
		mitigation := "Enable logging for the service using a suitable logging driver and ensure that logs are securely stored and monitored."
		threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
	}

	return threats
}

// checkForPrivilegedContainers checks if the service is running in privileged mode or has dangerous capabilities that come close to privileged mode
func (ti *DockerComposeThreatInvestigator) checkForPrivilegedContainers(service types.ServiceConfig) []common.Threat {
	ti.logger.Debug("Checking for privileged containers", "service.Name", service.Name)

	threats := []common.Threat{}

	// Check if the service is directly running in privileged mode
	if service.Privileged {
		threatTitle := "Running in Privileged Mode"
		threatType := common.ElevationOfPrivilege
		description := "The service is running in privileged mode, which grants it extended capabilities and access to host resources. An attacker who compromises the container could exploit this to gain elevated privileges on the host system."
		mitigation := "Avoid running containers in privileged mode. Use specific capabilities and security options to limit the container's access to host resources."
		threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
	}

	// Check for dangerous capabilities in cap_add
	// List of dangerous capabilities that could lead to container escape or privilege escalation
	dangerousCapabilities := map[string]string{
		"all":             "grants all capabilities",
		"sys_admin":       "allows performing system administration operations",
		"net_admin":       "allows performing network administration operations",
		"sys_module":      "allows loading and unloading kernel modules",
		"sys_rawio":       "allows raw I/O port operations",
		"sys_ptrace":      "allows process tracing and debugging",
		"dac_override":    "allows bypassing file read, write, and execute permission checks",
		"dac_read_search": "allows bypassing file read permission checks and directory read and execute permission checks",
	}

	for _, cap := range service.CapAdd {
		capLower := strings.ToLower(cap)
		if reason, isDangerous := dangerousCapabilities[capLower]; isDangerous {
			var threatTitle string
			if capLower == "all" {
				threatTitle = "Using 'ALL' Capability"
			} else {
				threatTitle = fmt.Sprintf("Using Dangerous Capability '%s'", cap)
			}
			threatType := common.ElevationOfPrivilege
			description := fmt.Sprintf("The service is using the dangerous capability '%s' in cap_add, which %s. An attacker who compromises the container could exploit this to gain elevated privileges on the host system.", cap, reason)
			mitigation := fmt.Sprintf("Avoid using the '%s' capability in cap_add. Instead, specify only the necessary capabilities required for the container's operation.", cap)
			threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
		}
	}

	return threats
}

// checkForPublishedPorts checks if the service has published ports and returns Threats if found
func (ti *DockerComposeThreatInvestigator) checkForPublishedPorts(service types.ServiceConfig) []common.Threat {
	ti.logger.Debug("Checking for published ports", "service.Name", service.Name)

	threats := []common.Threat{}

	// If there are no ports defined, return no threats
	if len(service.Ports) == 0 {
		return threats
	}

	// Check each port for published ports
	for _, port := range service.Ports {
		ti.logger.Debug("Checking port", "port.Published", port.Published, "port.Target", port.Target)
		// Only flag ports that are actually published to the host
		// port.Published indicates the host port; if empty, the port is only internal
		if port.Published != "" {
			threatTitle := fmt.Sprintf("Published Port (Published: %s) (Target: %d)", port.Published, port.Target)
			threatType := common.DenialOfService
			description := fmt.Sprintf("The service has a published port (Published: %s) (Target: %d), which exposes the service to external networks. An attacker could exploit this exposure to launch denial of service attacks against the service.", port.Published, port.Target)
			mitigation := "Restrict published ports to trusted networks and implement proper firewall rules to limit exposure."
			threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
		}
	}

	return threats
}

// checkForRootUser checks if the service is running as the root user
func (ti *DockerComposeThreatInvestigator) checkForRootUser(service types.ServiceConfig) []common.Threat {
	ti.logger.Debug("Checking for root user", "service.Name", service.Name)

	threats := []common.Threat{}

	// Check if the service is running as root user
	var threatTitle string
	var description string

	if service.User == "" {
		// User not specified - will default to Dockerfile's USER or root
		threatTitle = "Service User Not Explicitly Set - May Default to Root"
		description = "The service does not explicitly specify a user, which means it will use the default user from the container image (often root). Running as root grants unrestricted access to the container and potentially the host system. An attacker who compromises the container could exploit this to gain elevated privileges."
	} else if service.User == "0" || strings.EqualFold(service.User, "root") {
		// Explicitly set to root
		threatTitle = "Service Running as Root User"
		description = "The service is explicitly configured to run as the root user, which has unrestricted access to the container and potentially the host system. An attacker who compromises the container could exploit this to gain elevated privileges."
	} else {
		// Non-root user specified, no threat
		return threats
	}

	threatType := common.ElevationOfPrivilege
	mitigation := "Specify a non-root user for the service to limit its privileges and reduce the risk of privilege escalation."
	threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))

	return threats
}

// checkForUnlimitedResources checks if the service has resource limits defined
func (ti *DockerComposeThreatInvestigator) checkForUnlimitedResources(service types.ServiceConfig) []common.Threat {
	ti.logger.Debug("Checking for unlimited resources", "service.Name", service.Name)

	threats := []common.Threat{}

	// Check if resources are defined
	if service.Deploy == nil || service.Deploy.Resources.Limits == nil {
		threatTitle := "No Resource Limits Defined"
		threatType := common.DenialOfService
		description := "The service does not have resource limits defined. An attacker who compromises the container could exploit this to consume excessive host resources, leading to denial of service for other services."
		mitigation := "Define resource limits for CPU and memory in the service's deployment configuration to prevent resource exhaustion."
		threats = append(threats, ti.generateThreat(service.Name, threatTitle, threatType, description, mitigation))
	}

	return threats
}

// checkForUnspecificImageVersion checks if the service is using an unspecific image version (e.g. 'latest')
// and returns a Threat if found, otherwise returns an empty Threat
func (ti *DockerComposeThreatInvestigator) checkForUnspecificImageVersion(service types.ServiceConfig) []common.Threat {
	ti.logger.Debug("Checking for unspecific or mutable image references", "service.Name", service.Name)

	// If the service has no image, return no threat
	if service.Image == "" {
		return []common.Threat{}
	}

	image := service.Image
	threats := []common.Threat{}

	// Split off digest if present: image:tag@sha256:...
	hasDigest := strings.Contains(image, "@")
	imageWithoutDigest := image
	if hasDigest {
		if idx := strings.Index(image, "@"); idx != -1 {
			imageWithoutDigest = image[:idx]
		}
	}

	// Extract tag if any
	lastColonIdx := strings.LastIndex(imageWithoutDigest, ":")
	lastSlashIdx := strings.LastIndex(imageWithoutDigest, "/")

	hasTag := false
	tag := "" // empty = no tag

	if lastColonIdx > lastSlashIdx {
		tagPart := imageWithoutDigest[lastColonIdx+1:]
		if tagPart != "" {
			hasTag = true
			tag = strings.ToLower(tagPart)
		}
	}

	// ---- Case 1: No tag at all → implicit latest ----
	if !hasTag {
		threats = append(threats, ti.generateThreat(
			service.Name,
			"Missing Image Tag (Implicit 'latest')",
			common.Tampering,
			fmt.Sprintf("The service uses a container image without specifying a tag ('%s'). "+
				"Docker will implicitly use the mutable 'latest' tag, leading to non-deterministic deployments "+
				"and increasing the risk of unintentionally pulling malicious or modified image versions.",
				image),
			"Specify a concrete version tag or digest to ensure deterministic and secure deployments.",
		))
		return threats
	}

	// ---- Case 2: Explicit latest tag, but no digest ----
	if tag == "latest" && !hasDigest {
		threats = append(threats, ti.generateThreat(
			service.Name,
			"Use of Mutable Image Tag ('latest')",
			common.Tampering,
			fmt.Sprintf("The service uses the mutable 'latest' tag ('%s'). This tag may change over time, "+
				"leading to unpredictable deployments and increased exposure if the upstream image is modified or compromised.",
				image),
			"Use a fixed version tag or, preferably, pin the image using an immutable digest.",
		))
		return threats
	}

	// ---- Case 3: Has a specific tag, but no digest ----
	if !hasDigest {
		threats = append(threats, ti.generateThreat(
			service.Name,
			"Image Not Pinned with an Immutable Digest",
			common.Tampering,
			fmt.Sprintf("The service references a tagged image ('%s') but does not specify a digest. "+
				"Tags can be overwritten in the registry, meaning the image content is not guaranteed "+
				"and could be replaced by a malicious or unexpected version.",
				image),
			"Pin the image using an immutable digest (e.g., image:tag@sha256:...) to ensure image integrity.",
		))
		return threats
	}

	// ---- All good: specific tag + digest ----
	return threats
}

// generateThreat creates a new Threat instance with default values and given parameters
func (ti *DockerComposeThreatInvestigator) generateThreat(serviceName string, threatTitle string, threatType common.ThreatType, description string, mitigation string) common.Threat {
	idHash := generateThreatIDHash(serviceName, threatTitle)

	// Default values for new threats
	status := common.Open
	severity := "TBD"
	modelType := common.STRIDE
	score := ""
	isGeneratedByUser := false
	source := common.DataSourceDockerCompose
	mapIndex := -1
	number := int64(0)

	return common.Threat{
		InternalID:        idHash,
		ID:                idHash,
		Title:             threatTitle,
		Status:            status,
		Severity:          severity,
		Type:              threatType,
		Description:       description,
		Mitigation:        mitigation,
		ModelType:         modelType,
		Number:            number,
		Score:             score,
		IsGeneratedByUser: isGeneratedByUser,
		Source:            source,
		MapIndex:          mapIndex,
	}
}

// generateThreatIDHash generates a unique ID hash from a given serviceName and threatTitle
func generateThreatIDHash(serviceName string, threatTitle string) string {
	return common.GenerateIDHashFromEntityNames(serviceName, threatTitle)
}

// isDockerSocket checks if the given volume source is the Docker socket path
func (ti *DockerComposeThreatInvestigator) isDockerSocket(v string) bool {
	return strings.HasPrefix(v, "/var/run/docker.sock")
}

// isHostPath checks if the given path appears to be a host path based on common path patterns
func (ti *DockerComposeThreatInvestigator) isHostPath(path string) bool {
	// Simple heuristic to determine if a path is a host path
	return strings.HasPrefix(path, "/") || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") || strings.HasPrefix(path, "~/")
}
