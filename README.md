# Threatcat 🐈

[![GitHub issues](https://img.shields.io/github/issues/threatcat-dev/threatcat)](https://github.com/threatcat-dev/threatcat/issues)
[![GitHub stars](https://img.shields.io/github/stars/threatcat-dev/threatcat)](https://github.com/threatcat-dev/threatcat/stargazers)
[![License](https://img.shields.io/github/license/threatcat-dev/threatcat)](https://github.com/threatcat-dev/threatcat/blob/main/LICENSE.txt)

Threatcat is a command-line tool designed to support the threat modeling process by automating parts of the model creation. It is built to be easily integrated into your CI/CD pipeline, helping you to keep your threat models up-to-date with your evolving system architecture.

The main goal of Threatcat is to gather information from various sources, merge them, and create a foundational threat model. This allows security and development teams to focus on analyzing and mitigating threats rather than on the manual and often time-consuming task of diagramming and data entry.

***

## ✨ Features

Threatcat offers a range of features to streamline your threat modeling workflow:

* **Automated Model Generation**: Automatically create a baseline threat model from your infrastructure-as-code definitions.
* **Support for Docker Compose**: Currently, Threatcat can read `docker-compose.yml` files and generate a corresponding [OWASP Threat Dragon](https://owasp.org/www-project-threat-dragon/) model.
* **Model Updates**: You can also use a `docker-compose.yml` file to update an existing Threat Dragon model with new or changed services.
* **CI/CD Integration**: As a command-line tool, Threatcat can be seamlessly integrated into your CI/CD pipeline to ensure your threat models are always current.

***

### 🚀 Upcoming Features

We have an exciting roadmap for Threatcat, with plans to introduce:

* **Broader Input Format Support**: We are planning to add support for other input formats, for example [Terraform](https://developer.hashicorp.com/terraform) files that describe infrastructure and even direct source code analysis.
* **Multiple Output Formats**: In the future, you will be able to generate threat models in various formats, such as [Threagile](https://threagile.io/) YAML files.
* **Enhanced Merging Capabilities**: We aim to improve the merging logic to intelligently handle more complex scenarios and a wider array of input sources.
* **Automatic generation of threats**: Automatic generation of common threat scenarios for recognized components.
* **Extensibility**: Enhanced extensibility through custom configuration files, allowing users to define new rules and integrations.

***

## ⚙️ Installation

To get started with Threatcat, you'll need a working [Go installation](https://go.dev/doc/install) on your system.

If you just want to use the tool and are not interested in modifying the source code, you can install it directly with a single command.

* **Install to your PATH**: To build the binary and automatically place it in your Go bin directory (which should be part of your system's `PATH`), use:
    ```bash
    go install github.com/threatcat-dev/threatcat/cmd/threatcat@latest
    ```
    This will make the `threatcat` command available globally in your terminal.

To build/install from a local copy of the source code:

1.  First, clone the repository to your local machine:
    ```bash
    git clone https://github.com/threatcat-dev/threatcat.git
    ```

2.  Navigate to the project directory:
    ```bash
    cd threatcat
    ```

3.  From here, you have two options:

    * **Build the executable**: Run the following command to compile the `threatcat` binary in the current directory.
        ```bash
        go build ./cmd/threatcat
        ```

    * **Install to your PATH**: To build the binary and automatically place it in your Go bin directory (which should be part of your system's `PATH`), use:
        ```bash
        go install ./cmd/threatcat
        ```

    [🎥 Video: Installation](https://youtu.be/7meFm0g6JSQ)

***

## 🛠️ Usage

Threatcat is designed to be straightforward to use from the command line.

### Creating a New Threat Dragon Model

To create a new Threat Dragon model from a `docker-compose.yml` file, use the following command:

```bash
threatcat -d /path/to/your/docker-compose.yml -o /path/to/your/threatdragon-model.json
```

[🎥 Video: Creating a new ThreatDragon model from docker-compose](https://youtu.be/WKcW93qTxBs)

### Updating an Existing Threat Dragon Model

To update an existing Threat Dragon model with the containers from a `docker-compose.yml` file, run:

```bash
threatcat -d /path/to/your/docker-compose.yml -t /path/to/your/threatdragon-input-model.json -o /path/to/your/threatdragon-output-model.json
```

To overwrite your existing model with the updates, simply use the same file path for both the `-t` parameter  and the `-o` parameter.

[🎥 Video: Updating an existing ThreatDragon model](https://youtu.be/9KrcOa4rW8k)

### Custom Component Mapping

Threatcat automatically classifies components into categories (`applications`, `databases`, `webservers`, `infrastructure`) based on the Docker image name. While Threatcat recognizes many common public images by default, you can extend this mapping to include your private or less common images.

To do this, create a configuration file (e.g., `threatcat.config`) with your custom image names under the appropriate categories:

```yaml
applications:
  - my-custom-app
  - my-other-app-image:latest
databases:
  - my-special-db
webservers:
  - my-nginx-proxy
infrastructure:
  - my-message-queue
```
To apply your custom definitions during a run, pass the configuration file to the tool using the `-i` flag. Threatcat will then correctly classify any components using these image names.

```bash
threatcat -d /path/to/your/docker-compose.yml -i /path/to/your/threatcat.config -o /path/to/your/threatdragon-model.json
```
### Further Usage

For a full list of all available commands and flags, you can always use the `-h` flag. This will provide you with the most up-to-date information.

```bash
threatcat -h
```
***

## 🙌 Contributing

We welcome and greatly appreciate feedback from the community! If you have suggestions for new features, ideas for improvement, or have found a bug, please let us know by opening an issue.

**A Note on Pull Requests**

As Threatcat is currently being developed as part of a student project, we need to handle the core implementation ourselves. For this reason, **we are currently not able to accept pull requests.**

We may be able to open up for code contributions in the future. We appreciate your understanding!

***

## 📄 License

Threatcat is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for more information.
