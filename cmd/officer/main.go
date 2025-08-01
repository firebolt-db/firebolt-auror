package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func main() {
	err := run()
	if err != nil {
		fmt.Println("error on execution", err)
	}
}

func run() error {
	job := flag.String("job", "cosign-review", "job to run: [cosign-review, warmup]")
	caFile := flag.String("ca-file", "./tls.crt", "File containing the x509 Certificate for HTTPS.")
	skip := flag.Bool("skip", true, "Skip certificate verification for testing purposes.")
	protocol := flag.String("protocol", "https", "Protocol to use: [http, https]")
	service := flag.String("service", "auror.firebolt-auror.svc", " Service to connect to")
	port := flag.Int("port", 443, "Port to connect to (localhost test used 8443)")
	resourceKind := flag.String("kind", "pod", "[cosign-review flag] Resource kind to test: [pod, deployment, replicaset, daemonset, statefulset, job, cronjob]")
	imageFormat := flag.String("image", "digest", "[cosign-review flag] Image format to use: [default, digest, unsigned]")
	images := flag.String("images", "", "Comma-separated list of images to warm up the cache")

	flag.Parse()
	c := Client{
		Web: &http.Client{},
	}
	// check officer environment variable
	envJob := os.Getenv("OFFICER_JOB")
	if envJob != "" {
		job = &envJob
	}
	envService := os.Getenv("OFFICER_SERVICE")
	if envService != "" {
		service = &envService
	}
	envRresourceKind := os.Getenv("OFFICER_RESOURCE_KIND")
	if envRresourceKind != "" {
		resourceKind = &envRresourceKind
	}
	envPort := os.Getenv("OFFICER_PORT")
	if envPort != "" {
		portInt, err := strconv.Atoi(envPort)
		if err == nil {
			port = &portInt
		}
	}

	switch *job {
	case "cosign-review":
		if *skip {
			c.Web.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			*caFile = ""
		}
		if *caFile != "" {
			certPool, err := genCertPool(*caFile)
			if err != nil {
				return err
			}
			c.Web.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool, // Replace with appropriate value for RootCAs
				},
			}
		}
		c.CosignReview(*protocol, *service, *port, *resourceKind, *imageFormat)
	case "warmup":
		if *skip {
			c.Web.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			*caFile = ""
		}
		if *caFile != "" {
			certPool, err := genCertPool(*caFile)
			if err != nil {
				return err
			}
			c.Web.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: certPool,
				},
			}
		}
		c.WarmUp(*protocol, *service, *port, *images)
	default:
		fmt.Println("Usage: ./officer -job cosign-review -service localhost -port 8443")
	}
	return nil
}

type Client struct {
	Web *http.Client
}

func (c Client) Request(serverURL, method string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, serverURL, body)
	if err != nil {
		return []byte{}, err
	}
	res, err := c.Web.Do(req)
	if err != nil {
		return []byte{}, err
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return []byte{}, err
	}
	defer func() {
		err := res.Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()
	if res.StatusCode == http.StatusOK {
		return b, nil
	}
	return []byte{}, fmt.Errorf("status code: %d, raw body: %s", res.StatusCode, string(b))
}

type ResourceConfig struct {
	kind     string
	group    string
	resource string
	name     string
	manifest string
}

func (c Client) WarmUp(protocol, service string, port int, images string) {
	if images == "" {
		fmt.Println("No images provided. Please provide images using -images flag")
		return
	}

	imageList := strings.Split(images, ",")
	if len(imageList) == 0 {
		fmt.Println("No valid images provided")
		return
	}

	serverURL := fmt.Sprintf("%s://%s:%d/validate", protocol, service, port)

	for i, image := range imageList {

		image = strings.TrimSpace(image)
		if image == "" {
			continue
		}

		podManifest := fmt.Sprintf(`{
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": {
                "name": "warmup-pod-%d",
                "namespace": "default"
            },
            "spec": {
                "containers": [
                    {
                        "name": "warmup-container",
                        "image": "%s",
                        "command": [
                            "/bin/sh",
                            "-c", 
                            "sleep infinity"
                        ]
                    }
                ]
            }
        }`, i, image)

		admissionReview := admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "AdmissionReview",
				APIVersion: "admission.k8s.io/v1",
			},
			Request: &admissionv1.AdmissionRequest{
				UID: types.UID(fmt.Sprintf("warmup-cache-%d", i)),
				Kind: metav1.GroupVersionKind{
					Kind:    "Pod",
					Version: "v1",
					Group:   "",
				},
				Resource: metav1.GroupVersionResource{
					Group:    "",
					Version:  "v1",
					Resource: "pods",
				},
				Name:      fmt.Sprintf("warmup-pod-%d", i),
				Namespace: "default",
				Operation: admissionv1.Create,
				UserInfo: authenticationv1.UserInfo{
					Username: "kubernetes-admin",
				},
				Object: runtime.RawExtension{
					Raw: []byte(podManifest),
				},
			},
		}

		data, err := json.Marshal(admissionReview)
		if err != nil {
			fmt.Printf("Error marshaling admissionReview for image %s: %v\n", image, err)
			continue
		}

		b, err := c.Request(serverURL, http.MethodPost, bytes.NewReader(data))
		if err != nil {
			fmt.Printf("Error warming up image %s: %v\n", image, err)
			continue
		}

		fmt.Printf("Successfully warmed up image %s\n", image)
		fmt.Printf("Response: %s\n", string(b))
	}
}

func (c Client) CosignReview(protocol, service string, port int, resourceKind, imageFormat string) {

	resourceConfig := generateResourceConfig(resourceKind, imageFormat)

	admissionReview := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			Kind:       "AdmissionReview",
			APIVersion: "admission.k8s.io/v1",
		},
		Request: &admissionv1.AdmissionRequest{
			UID: "e385a4e0-752d-4897-9be7-371e6332f3ec",
			Kind: metav1.GroupVersionKind{
				Kind:    resourceConfig.kind,
				Version: "v1",
				Group:   resourceConfig.group,
			},
			Resource: metav1.GroupVersionResource{
				Group:    resourceConfig.group,
				Version:  "v1",
				Resource: resourceConfig.resource,
			},
			RequestKind: &metav1.GroupVersionKind{
				Kind:    resourceConfig.kind,
				Version: "v1",
				Group:   resourceConfig.group,
			},
			RequestResource: &metav1.GroupVersionResource{
				Group:    resourceConfig.group,
				Version:  "v1",
				Resource: resourceConfig.resource,
			},
			Name:      resourceConfig.name,
			Namespace: "default",
			Operation: admissionv1.Create,
			UserInfo: authenticationv1.UserInfo{
				Username: "kubernetes-admin",
			},
			Object: runtime.RawExtension{
				Raw: []byte(resourceConfig.manifest),
			},
		},
	}

	data, err := json.Marshal(admissionReview)
	if err != nil {
		fmt.Println("Error marshaling admissionReview:", err)
		return
	}

	serverURL := fmt.Sprintf("%s://%s:%d/validate", protocol, service, port)
	b, err := c.Request(serverURL, http.MethodPost, bytes.NewReader(data))
	if err != nil {
		fmt.Println(err)
		return
	}
	resp := string(b)
	if resp != "" {
		fmt.Printf("Service %s answered OK\n", serverURL)
		fmt.Println(resp)
	}
}

// creates the appropriate resource configuration based on the kind and image format
func generateResourceConfig(resourceKind, imageFormat string) ResourceConfig {

	var nginxImage, busyboxImage string

	// Replace with your ECR registry address and images
	switch imageFormat {
	case "digest":
		nginxImage = "123456789123.dkr.ecr.us-east-1.amazonaws.com/nginx:1.27.2-alpine@sha256:1234567890"
		busyboxImage = "123456789123.dkr.ecr.us-east-1.amazonaws.com/busybox:1.36.1@sha256:1234567890"
	case "unsigned":
		nginxImage = "123456789123.dkr.ecr.us-east-1.amazonaws.com/nginx:1.27.0-alpine-amd"
		busyboxImage = "123456789123.dkr.ecr.us-east-1.amazonaws.com/busybox:1.35.0-test-dont-use"
	default:
		nginxImage = "123456789123.dkr.ecr.us-east-1.amazonaws.com/nginx:1.27.2-alpine"
		busyboxImage = "123456789123.dkr.ecr.us-east-1.amazonaws.com/busybox:1.36.1"
	}

	config := ResourceConfig{
		kind:     "Pod",
		group:    "",
		resource: "pods",
		name:     "test-pod",
	}

	// Customize based on resource kind
	switch resourceKind {
	case "pod":
		config.kind = "Pod"
		config.group = ""
		config.resource = "pods"
		config.name = "test-app"
		config.manifest = fmt.Sprintf(`{
            "kind": "Pod",
            "apiVersion": "v1",
            "metadata": {
                "name": "test-app",
                "namespace": "default"
            },
            "spec": {
                "containers": [
                    {
                        "name": "test-app",
                        "image": "%s",
                        "command": [
                            "/bin/sh",
                            "-c", 
                            "sleep infinity"
                        ]
                    }
                ],
                "initContainers": [
                    {
                        "name": "init-myservice",
                        "image": "%s",
                        "command": [
                            "sh",
                            "-c",
                            "echo Hello, World!"
                        ]
                    }
                ]
            }
        }`, busyboxImage, busyboxImage)
	case "deployment":
		config.kind = "Deployment"
		config.group = "apps"
		config.resource = "deployments"
		config.name = "nginx-deployment"
		config.manifest = fmt.Sprintf(`{
            "kind": "Deployment",
            "apiVersion": "apps/v1",
            "metadata": {
                "name": "nginx-deployment",
                "namespace": "default",
                "labels": {
                    "app": "nginx"
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": "nginx"
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "nginx"
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx-one",
                                "image": "%s",
                                "ports": [
                                    {
                                        "containerPort": 8080
                                    }
                                ]
                            }
                        ],
                        "initContainers": [
                            {
                                "name": "init-myservice",
                                "image": "%s",
                                "command": [
                                    "sh",
                                    "-c",
                                    "echo Hello, World!"
                                ]
                            }
                        ]
                    }
                }
            }
        }`, nginxImage, busyboxImage)
	case "replicaset":
		config.kind = "ReplicaSet"
		config.group = "apps"
		config.resource = "replicasets"
		config.name = "nginx-replicaset"
		config.manifest = fmt.Sprintf(`{
            "kind": "ReplicaSet",
            "apiVersion": "apps/v1",
            "metadata": {
                "name": "nginx-replicaset",
                "namespace": "default",
                "labels": {
                    "app": "nginx-replicaset"
                }
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": "nginx-replicaset"
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "nginx-replicaset"
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx-replicaset",
                                "image": "%s"
                            }
                        ],
                        "initContainers": [
                            {
                                "name": "init-myservice",
                                "image": "%s",
                                "command": [
                                    "sh",
                                    "-c",
                                    "echo Hello, World!"
                                ]
                            }
                        ]
                    }
                }
            }
        }`, nginxImage, busyboxImage)
	case "daemonset":
		config.kind = "DaemonSet"
		config.group = "apps"
		config.resource = "daemonsets"
		config.name = "nginx-daemon"
		config.manifest = fmt.Sprintf(`{
            "kind": "DaemonSet",
            "apiVersion": "apps/v1",
            "metadata": {
                "name": "nginx-daemon",
                "namespace": "default",
                "labels": {
                    "k8s-app": "nginx-daemon"
                }
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "name": "nginx-daemon"
                    }
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "name": "nginx-daemon"
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx-daemon",
                                "image": "%s"
                            }
                        ],
                        "initContainers": [
                            {
                                "name": "init-myservice",
                                "image": "%s",
                                "command": [
                                    "sh",
                                    "-c",
                                    "echo Hello, World!"
                                ]
                            }
                        ]
                    }
                }
            }
        }`, nginxImage, busyboxImage)
	case "statefulset":
		config.kind = "StatefulSet"
		config.group = "apps"
		config.resource = "statefulsets"
		config.name = "web"
		config.manifest = fmt.Sprintf(`{
            "kind": "StatefulSet",
            "apiVersion": "apps/v1",
            "metadata": {
                "name": "web",
                "namespace": "default"
            },
            "spec": {
                "replicas": 1,
                "selector": {
                    "matchLabels": {
                        "app": "nginx"
                    }
                },
                "serviceName": "nginx",
                "template": {
                    "metadata": {
                        "labels": {
                            "app": "nginx"
                        }
                    },
                    "spec": {
                        "containers": [
                            {
                                "name": "nginx",
                                "image": "%s",
                                "ports": [
                                    {
                                        "name": "web",
                                        "containerPort": 8080
                                    }
                                ]
                            }
                        ],
                        "initContainers": [
                            {
                                "name": "init-myservice",
                                "image": "%s",
                                "command": [
                                    "sh",
                                    "-c",
                                    "echo Hello, World!"
                                ]
                            }
                        ]
                    }
                }
            }
        }`, nginxImage, busyboxImage)
	case "job":
		config.kind = "Job"
		config.group = "batch"
		config.resource = "jobs"
		config.name = "pi"
		config.manifest = fmt.Sprintf(`{
            "kind": "Job",
            "apiVersion": "batch/v1",
            "metadata": {
                "name": "pi",
                "namespace": "default"
            },
            "spec": {
                "backoffLimit": 4,
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "pi",
                                "image": "%s",
                                "command": [
                                    "sh",
                                    "-c",
                                    "echo 3.14"
                                ]
                            }
                        ],
                        "initContainers": [
                            {
                                "name": "init-myservice",
                                "image": "%s",
                                "command": [
                                    "sh",
                                    "-c",
                                    "echo Hello, World!"
                                ]
                            }
                        ],
                        "restartPolicy": "Never"
                    }
                }
            }
        }`, busyboxImage, busyboxImage)
	case "cronjob":
		config.kind = "CronJob"
		config.group = "batch"
		config.resource = "cronjobs"
		config.name = "hello"
		config.manifest = fmt.Sprintf(`{
            "kind": "CronJob",
            "apiVersion": "batch/v1",
            "metadata": {
                "name": "hello",
                "namespace": "default"
            },
            "spec": {
                "schedule": "* * * * *",
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {
                                        "name": "hello",
                                        "image": "%s",
                                        "command": [
                                            "/bin/sh",
                                            "-c",
                                            "date; echo Hello from the Kubernetes cluster"
                                        ]
                                    }
                                ],
                                "initContainers": [
                                    {
                                        "name": "init-myservice",
                                        "image": "%s",
                                        "command": [
                                            "sh",
                                            "-c",
                                            "echo Hello, World!"
                                        ]
                                    }
                                ],
                                "restartPolicy": "OnFailure"
                            }
                        }
                    }
                }
            }
        }`, busyboxImage, busyboxImage)
	}

	return config
}

func genCertPool(f string) (*x509.CertPool, error) {
	caFile, err := os.ReadFile(f)
	if err != nil {
		fmt.Println("Error reading ca file", err)
		return nil, err
	}
	certPool, err := x509.SystemCertPool()
	if err != nil {
		fmt.Println("Error reading system cert pool", err)
		return nil, err
	}
	if ok := certPool.AppendCertsFromPEM(caFile); !ok {
		fmt.Println("Error appending certs from pem", err)
		return nil, err
	}
	return certPool, nil
}
