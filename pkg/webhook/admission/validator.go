package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/firebolt-db/firebolt-auror/pkg/webhook/cache"
	"github.com/firebolt-db/firebolt-auror/pkg/webhook/cosign"
	"github.com/firebolt-db/firebolt-auror/pkg/webhook/metrics"

	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewValidator(verifier *cosign.Verifier, mode string, registries []string, cacheConfig CacheConfig, useTagCache bool, logger *slog.Logger) *Validator {
	return &Validator{
		verifier:    verifier,
		ownerCache:  cache.CacheFactory(cacheConfig.OwnerSize, cacheConfig.OwnerTTL, "owner", logger),
		cache:       cache.CacheFactory(cacheConfig.DigestSize, cacheConfig.DigestTTL, "digest", logger),
		tagCache:    cache.CacheFactory(cacheConfig.TagSize, cacheConfig.TagTTL, "tag", logger),
		mode:        mode,
		registries:  registries,
		useTagCache: useTagCache,
		logger:      logger,
	}
}

func (v *Validator) ValidateAdmission(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		v.logger.Debug("Admission validation took", "duration", time.Since(start).Seconds())
	}()
	v.logger.Debug("Starting admission validation")

	admissionReview := admissionv1.AdmissionReview{}
	if err := json.NewDecoder(r.Body).Decode(&admissionReview); err != nil {
		v.logger.Error("Failed to parse admission review", "error", err)
		http.Error(w, "Failed to parse admission review", http.StatusBadRequest)
		return
	}
	v.logger.Debug("Successfully parsed admission review")
	v.logger.Debug("Processing admission request", "uid", admissionReview.Request.UID, "namespace", admissionReview.Request.Namespace, "name", admissionReview.Request.Name, "kind", admissionReview.Request.Kind.Kind)

	if admissionReview.Request.Namespace == "firebolt-auror" && admissionReview.Request.Name == "webhook" {
		v.logger.Debug("Skipping signature verification for webhook's own pod")
		v.sendResponse(w, &admissionReview, true, "Skipping signature verification for webhook's own pod")
		return
	}

	// To stop the verification if the context is cancelled
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	internalImages, externalImages, objectMetadata, err := v.extractImagesFromAdmissionReview(admissionReview.Request.Object.Raw, admissionReview.Request.Kind.Kind)
	if err != nil {
		v.logger.Error("Failed to extract images", "error", err)
		v.sendResponse(w, &admissionReview, false, fmt.Sprintf("Failed to extract images: %v", err))
		return
	}

	if len(internalImages) == 0 && len(externalImages) == 0 {
		v.logger.Debug("No images found in resource")
		v.sendResponse(w, &admissionReview, false, "No images found in resource")
		return
	}

	if len(externalImages) > 0 {
		// We only create metrics for high level resources
		if kind := admissionReview.Request.Kind.Kind; kind == "Deployment" || kind == "StatefulSet" || kind == "DaemonSet" || kind == "CronJob" {
			metrics.RecordExternalImage(ctx,
				admissionReview.Request.Namespace,
				admissionReview.Request.Kind.Kind,
				admissionReview.Request.Name)
		}
		v.logger.Error("Found external images that will not be validated",
			"images", externalImages, "namespace", admissionReview.Request.Namespace, "name", admissionReview.Request.Name, "kind", admissionReview.Request.Kind.Kind)
		v.handleFailedVerification(w, &admissionReview, fmt.Sprintf("%v", externalImages), fmt.Errorf("found external images that will not be validated"))
		return
	}

	if v.checkOwnership(ctx, admissionReview.Request.Kind.Kind, admissionReview.Request.Namespace, objectMetadata.OwnerReferences) {
		v.logger.Debug("Owner resource found in cache", "namespace", admissionReview.Request.Namespace, "name", admissionReview.Request.Name, "kind", admissionReview.Request.Kind.Kind)
		v.sendResponse(w, &admissionReview, true, "Owner resource found in cache")
		return
	}

	v.logger.Debug("Found unique images to verify", "count", len(internalImages))
	var wg sync.WaitGroup

	resultCh := make(chan VerificationResult, len(internalImages))

	// verify only unique images
	for _, image := range internalImages {
		wg.Add(1)
		go func(image string) {
			defer wg.Done()
			v.verifyImage(ctx, image, admissionReview.Request.Namespace, resultCh)
		}(image)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	allValid := true
	var firstFailure VerificationResult

	for result := range resultCh {
		if !result.Valid {
			allValid = false
			firstFailure = result
			//cancel()
			break
		}
	}

	if allValid {
		v.logger.Debug("All image signatures verified successfully")
		if v.addOwnerCacheEntry(ctx, admissionReview.Request.Kind.Kind, objectMetadata.Namespace, objectMetadata.Name, string(objectMetadata.UID)) {
			v.logger.Debug("Adding owner cache entry", "namespace", admissionReview.Request.Namespace, "name", admissionReview.Request.Name, "kind", admissionReview.Request.Kind.Kind, "cache size", v.ownerCache.Len())
		}

		v.sendResponse(w, &admissionReview, true, "All image signatures verified successfully")
	} else {
		v.logger.Error("Signature verification failed", "image", firstFailure, "namespace", admissionReview.Request.Namespace, "name", admissionReview.Request.Name, "kind", admissionReview.Request.Kind.Kind)
		v.handleFailedVerification(w, &admissionReview, firstFailure.Image, firstFailure.Error)
	}

}

func (v *Validator) isAllowedRegistry(image string) bool {
	for _, registry := range v.registries {
		if strings.HasPrefix(image, registry) {
			return true
		}
	}
	return false
}

// TODO fix unused digest
func (v *Validator) handleFailedVerification(w http.ResponseWriter, review *admissionv1.AdmissionReview, image string, err error) {

	message := "Failed to verify signature for image: " + image
	if err != nil {
		message = "Invalid signature: " + err.Error() + " for image: " + image
	}

	// If audit mode
	if v.mode == "audit" {
		warningMessage := "WARNING: Allowing " + review.Request.Kind.Kind + " creation in audit mode: " + message
		v.logger.Info(warningMessage)
		v.sendResponse(w, review, true, warningMessage)
		return
	}

	// If deny mode
	v.logger.Info(message)
	v.sendResponse(w, review, false, message)
}

func (v *Validator) extractImagesFromAdmissionReview(raw []byte, kind string) (internalImages []string, externalImages []string, metadata metav1.ObjectMeta, err error) {
	uniqueInternalImages := make(map[string]struct{})
	uniqueExternalImages := make(map[string]struct{})

	var resource Resource
	err = json.NewDecoder(bytes.NewReader(raw)).Decode(&resource)
	if err != nil {
		return nil, nil, metav1.ObjectMeta{}, fmt.Errorf("failed to decode %s: %w", kind, err)
	}

	categorizeImage := func(image string) {
		if image == "" {
			return
		}
		if v.isAllowedRegistry(image) {
			uniqueInternalImages[image] = struct{}{}
		} else {
			uniqueExternalImages[image] = struct{}{}
		}
	}

	switch kind {
	case "Pod":
		for _, container := range resource.Spec.Containers {
			categorizeImage(container.Image)
		}
		for _, container := range resource.Spec.InitContainers {
			categorizeImage(container.Image)
		}
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		for _, container := range resource.Spec.Template.Spec.Containers {
			categorizeImage(container.Image)
		}
		for _, container := range resource.Spec.Template.Spec.InitContainers {
			categorizeImage(container.Image)
		}
	case "CronJob":
		for _, container := range resource.Spec.JobTemplate.Spec.Template.Spec.Containers {
			categorizeImage(container.Image)
		}
		for _, container := range resource.Spec.JobTemplate.Spec.Template.Spec.InitContainers {
			categorizeImage(container.Image)
		}
	}

	internalImages = make([]string, 0, len(uniqueInternalImages))
	for image := range uniqueInternalImages {
		internalImages = append(internalImages, image)
	}

	externalImages = make([]string, 0, len(uniqueExternalImages))
	for image := range uniqueExternalImages {
		externalImages = append(externalImages, image)
	}
	v.logger.Debug("resource metadata owner references", "owner references", resource.Metadata.OwnerReferences)
	return internalImages, externalImages, resource.Metadata, nil
}

func (v *Validator) verifyImage(ctx context.Context, image string, namespace string, resultCh chan<- VerificationResult) {

	result := VerificationResult{Image: image, Valid: false}

	select {
	case <-ctx.Done():
		return
	default:
	}

	v.logger.Debug("Checking if we have the digest in cache")

	var imageDigest string
	idx := strings.Index(image, "@sha256:")
	if idx != -1 {
		imageDigest = image[idx+1:] // Skip the @ symbol
		// Check cache
		if entry, ok := v.cache.Get(ctx, imageDigest); ok {
			if entry.Valid {
				v.logger.Debug("Found cached successful verification for image", "image", image)
				result.Valid = true
				result.Digest = imageDigest
				sendResult(ctx, resultCh, result)
				return
			}
		}
		v.logger.Debug("Proceeding with verification for image", "image", image)
	} else if v.useTagCache {
		namespacedKey := fmt.Sprintf("%s:%s", namespace, image)
		if _, ok := v.tagCache.Get(ctx, namespacedKey); ok {
			v.logger.Debug("Found tag cache hit for image", "image", image)
			result.Valid = true
			result.Digest = imageDigest
			sendResult(ctx, resultCh, result)
			return
		}
	}

	select {
	case <-ctx.Done():
		return
	default:

	}

	// Verify signature if not in cache
	valid, digest, err := v.verifier.VerifySignature(image)
	result.Valid = valid
	result.Digest = digest
	result.Error = err
	if err != nil {
		v.logger.Error("Failed to verify signature", "error", err, "image", image)
		sendResult(ctx, resultCh, result)
		return
	}

	if !valid {
		v.logger.Error("Invalid signature", "digest", digest, "image", image)
		sendResult(ctx, resultCh, result)
		return
	}

	if idx != -1 && digest != "" {
		v.cache.Add(ctx, digest, cache.CacheEntry{
			Valid:     true,
			Timestamp: time.Now(),
		})
		v.logger.Debug("Cached successful verification for image", "image", image, "digest", digest, "cache size", v.cache.Len())
	} else if v.useTagCache { // Cache by tag only if it's a tag-based image and useTagCache is true
		namespacedKey := fmt.Sprintf("%s:%s", namespace, image)
		v.tagCache.Add(ctx, namespacedKey, cache.CacheEntry{
			Valid:     true,
			Timestamp: time.Now(),
		})
		v.logger.Debug("Cached successful verification for tagCache for image", "image", image, "namespace", namespace, "cache size", v.tagCache.Len())
	}

	v.logger.Debug("Valid signature for image", "image", image)
	sendResult(ctx, resultCh, result)

}

func sendResult(ctx context.Context, ch chan<- VerificationResult, result VerificationResult) {
	select {
	case <-ctx.Done():
		return
	default:
		ch <- result
	}
}

func (v *Validator) sendResponse(w http.ResponseWriter, review *admissionv1.AdmissionReview, allowed bool, message string) {
	review.Response = &admissionv1.AdmissionResponse{
		UID:     review.Request.UID,
		Allowed: allowed,
		Result: &metav1.Status{
			Message: message,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(review); err != nil {
		v.logger.Error("Failed to encode response", "error", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (v *Validator) addOwnerCacheEntry(ctx context.Context, kind, namespace, name, uid string) bool {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
		owner := fmt.Sprintf("%s-%s-%s", namespace, name, uid)
		v.ownerCache.Add(ctx, owner, cache.CacheEntry{
			Valid:     true,
			Timestamp: time.Now(),
		})
		return true

	default:
		return false
	}
}

func (v *Validator) checkOwnership(ctx context.Context, kind, namespace string, ownerReferences []metav1.OwnerReference) bool {
	switch kind {
	case "Pod", "Job", "ReplicaSet":
		for _, ownerReference := range ownerReferences {
			owner := fmt.Sprintf("%s-%s-%s", namespace, ownerReference.Name, ownerReference.UID)
			if entry, ok := v.ownerCache.Get(ctx, owner); ok {
				if entry.Valid {
					return true
				}
			}
		}
		return false
	default:
		return false
	}
}
