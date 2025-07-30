# Firebolt Auror
Firebolt Auror is a Kubernetes Image Admission Controller


## Key Features

### 🔐 **Image Signature Validation**
- Uses Cosign to verify container image signatures
- Ensures only signed images are deployed
- Supports both deny and audit modes for flexible deployment

### �� **Registry Control**
- Restricts deployments to specified AWS ECR registries
- Prevents unauthorized external images from being deployed
- Configurable registry allowlist

### ⚡ **Performance Optimization**
- Three-tier caching system for verification results
- Digest-based and tag-based caching strategies
- Owner reference caching for improved performance

### 📊 **Monitoring & Observability**
- Prometheus metrics for monitoring
- OpenTelemetry integration for distributed tracing
- Detailed logging with configurable levels

### 🔧 **Flexible Configuration**
- Support for multiple Kubernetes resource types (Pods, Deployments, StatefulSets, etc.)
- Configurable cache sizes and TTLs
- Environment-based configuration
- Helm chart for easy deployment

## How To Use

### Prerequisites

```bash
# Install required tools
task dependencies-install-mac
```

### Quick Start

```bash
# 1. Create development environment
task dev-create

# 2. Deploy auror admission controller
task auror-deploy

# 3. Verify deployment
kubectl get pods -n firebolt-auror
```

### Configuration

#### Environment Setup
```bash
# Configure AWS credentials
aws configure export-credentials

# Test ECR access
aws ecr get-login-password --region us-east-1
```

#### Key Configuration Options
- `--mode`: Set to `deny` (block unsigned images) or `audit` (log only)
- `--registry`: Specify allowed ECR registries (comma-separated)
- `--public-key`: Path to Cosign public key for signature verification
- `--log-level`: Set logging level (`info` or `debug`)

### Testing

```bash
# Test admission controller
./cmd/officer/officer -job admission-test

# Test with specific resource type
./cmd/officer/officer -job cosign-review -kind deployment -image digest

# Warm up cache with images
./cmd/officer/officer -job warmup -images "your-registry/image:tag"
```

### Monitoring

```bash
# Check metrics
kubectl port-forward -n firebolt-auror service/auror 8080:8080
curl http://localhost:8080/metrics
```


### License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the full license text.