# Docker Build and Run Guide

This guide explains how to build and run the ClamdProxy Docker container with custom configuration.

## Building the Docker Image

You can build the ClamdProxy Docker image using the following command:

```bash
docker build -t clamdproxy \
  --build-arg LISTEN_ADDR=0.0.0.0:3315 \
  --build-arg BACKEND_ADDR=docker.for.mac.localhost:3310 \
  --build-arg LOG_LEVEL=debug \
  --build-arg METRICS_ADDR=0.0.0.0:2112 \
  -f docker/Dockerfile .
```

### Build Arguments

The Dockerfile supports the following build arguments:

| Argument | Description | Default Value |
|----------|-------------|---------------|
| `LISTEN_ADDR` | Address and port for ClamdProxy to listen on | `0.0.0.0:3315` |
| `BACKEND_ADDR` | Address and port of the clamd backend | `clamav:3310` |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `debug` |
| `METRICS_ADDR` | Address and port for exposing Prometheus metrics | `0.0.0.0:2112` |

## Running the Container

After building the image, you can run the container with:

```bash
docker run -p 3315:3315 -p 2112:2112 \
  -e LISTEN_ADDR=0.0.0.0:3315 \
  -e BACKEND_ADDR=docker.for.mac.localhost:3310 \
  -e LOG_LEVEL=debug \
  -e METRICS_ADDR=0.0.0.0:2112 \
  clamdproxy
```

### Environment Variables

The container uses the following environment variables:

| Variable | Description | Default Value |
|----------|-------------|---------------|
| `LISTEN_ADDR` | Address and port for ClamdProxy to listen on | Value from build arg |
| `BACKEND_ADDR` | Address and port of the clamd backend | Value from build arg |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | Value from build arg |
| `METRICS_ADDR` | Address and port for exposing Prometheus metrics | Value from build arg |

## Notes for macOS Users

When running Docker on macOS, use `docker.for.mac.localhost` to connect to clamD services running on your host machine. This is why the example uses `docker.for.mac.localhost:3310` as the backend address.

## Ports

- The proxy service listens on port 3315 (or as configured)
- Metrics are exposed on port 2112 (or as configured)

Make sure to map these ports correctly when running the container.