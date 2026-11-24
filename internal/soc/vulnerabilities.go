package soc

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const maxVulnerabilityDocuments = 10000

type vulnerableSoftware struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Priority     string `json:"priority"`
	Detections   int    `json:"detections"`
	priorityRank int
	score        float64
}

type vulnerabilityInventory struct {
	AgentID         string               `json:"agent_id"`
	AgentName       string               `json:"agent_name,omitempty"`
	TotalDetections int                  `json:"total_detections"`
	Truncated       bool                 `json:"truncated"`
	Software        []vulnerableSoftware `json:"software"`
}

func (b *Backend) vulnerabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	if agentID == "" || len(agentID) > 128 {
		writeError(w, http.StatusBadRequest, "agent_id est obligatoire et ne doit pas dépasser 128 caractères")
		return
	}

	tenantID := tenantFromContext(r.Context())
	var source *WazuhSource
	for _, configured := range b.wazuhSources() {
		if configured.TenantID == tenantID {
			configured := configured
			source = &configured
			break
		}
	}
	if source == nil {
		writeError(w, http.StatusServiceUnavailable, "aucune source Wazuh n’est configurée pour ce client")
		return
	}
	if source.VulnerabilitiesIndex == "" {
		source.VulnerabilitiesIndex = defaultVulnerabilitiesIndex
	}

	inventory, err := b.fetchVulnerabilityInventory(r.Context(), *source, agentID)
	if err != nil {
		var responseError *wazuhHTTPError
		if errors.As(err, &responseError) {
			message := fmt.Sprintf("Wazuh Indexer a répondu HTTP %d lors de la lecture de l’inventaire.", responseError.statusCode)
			switch responseError.statusCode {
			case http.StatusUnauthorized:
				message = "Wazuh Indexer a refusé l’authentification (HTTP 401)."
			case http.StatusForbidden:
				message = "Wazuh Indexer a refusé l’accès à l’index des vulnérabilités (HTTP 403)."
			case http.StatusNotFound:
				message = "Index des vulnérabilités introuvable ; vérifiez son nom et l’activation du module Wazuh."
			}
			writeError(w, http.StatusBadGateway, message)
			return
		}
		log.Printf("lecture de l’inventaire des vulnérabilités pour l’agent %q: %v", agentID, err)
		writeError(w, http.StatusBadGateway, "impossible de lire l’inventaire des vulnérabilités dans Wazuh Indexer")
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (b *Backend) fetchVulnerabilityInventory(ctx context.Context, source WazuhSource, agentID string) (vulnerabilityInventory, error) {
	index := source.VulnerabilitiesIndex
	if index == "" {
		index = defaultVulnerabilitiesIndex
	}
	base, err := url.Parse(strings.TrimRight(source.URL, "/"))
	if err != nil {
		return vulnerabilityInventory{}, fmt.Errorf("analyser l’URL de l’Indexer: %w", err)
	}
	indexPath := strings.ReplaceAll(url.PathEscape(index), "%2A", "*")
	base.Path = strings.TrimRight(base.Path, "/") + "/" + indexPath + "/_search"
	query, err := json.Marshal(map[string]any{
		"size":             maxVulnerabilityDocuments,
		"track_total_hits": true,
		"_source":          []string{"agent.id", "agent.name", "package.name", "package.version", "vulnerability.severity", "vulnerability.score.base"},
		"sort":             []any{map[string]any{"vulnerability.score.base": map[string]string{"order": "desc", "missing": "_last"}}},
		"query": map[string]any{
			"term": map[string]string{"agent.id": agentID},
		},
	})
	if err != nil {
		return vulnerabilityInventory{}, fmt.Errorf("encoder la requête de vulnérabilités: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(query))
	if err != nil {
		return vulnerabilityInventory{}, fmt.Errorf("créer la requête de vulnérabilités: %w", err)
	}
	request.SetBasicAuth(source.Username, source.Password)
	request.Header.Set("Content-Type", "application/json")

	client := b.httpClient
	if source.VerifyTLS != nil && !*source.VerifyTLS {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client = &http.Client{Timeout: b.httpClient.Timeout, Transport: transport}
	}
	response, err := client.Do(request)
	if err != nil {
		return vulnerabilityInventory{}, fmt.Errorf("contacter Wazuh Indexer: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return vulnerabilityInventory{}, &wazuhHTTPError{statusCode: response.StatusCode}
	}

	var result struct {
		Hits struct {
			Total json.RawMessage `json:"total"`
			Hits  []struct {
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxRequestBytes*10))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return vulnerabilityInventory{}, fmt.Errorf("décoder l’inventaire des vulnérabilités: %w", err)
	}

	total := len(result.Hits.Hits)
	truncated := false
	if len(result.Hits.Total) > 0 {
		var totalValue struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		}
		if err := json.Unmarshal(result.Hits.Total, &totalValue); err == nil {
			total = totalValue.Value
			truncated = totalValue.Relation == "gte"
		} else {
			var numericTotal int
			if err := json.Unmarshal(result.Hits.Total, &numericTotal); err == nil {
				total = numericTotal
			}
		}
	}

	inventory := vulnerabilityInventory{
		AgentID:         agentID,
		TotalDetections: total,
		Truncated:       truncated || total > len(result.Hits.Hits),
		Software:        []vulnerableSoftware{},
	}
	softwareByKey := make(map[string]*vulnerableSoftware)
	for _, hit := range result.Hits.Hits {
		agentName := nestedString(hit.Source, "agent", "name")
		if inventory.AgentName == "" && agentName != "" {
			inventory.AgentName = agentName
		}
		name := nestedString(hit.Source, "package", "name")
		version := nestedString(hit.Source, "package", "version")
		if name == "" || version == "" {
			continue
		}
		key := strings.Join([]string{name, version}, "\x00")
		software := softwareByKey[key]
		if software == nil {
			software = &vulnerableSoftware{
				Name:     name,
				Version:  version,
				Priority: "unknown",
			}
			softwareByKey[key] = software
		}
		software.Detections++
		priority, rank, score := vulnerabilityPriority(
			nestedString(hit.Source, "vulnerability", "severity"),
			nestedFloat(hit.Source, "vulnerability", "score", "base"),
		)
		if rank > software.priorityRank || (rank == software.priorityRank && score > software.score) {
			software.Priority = priority
			software.priorityRank = rank
			software.score = score
		}
	}

	for _, software := range softwareByKey {
		inventory.Software = append(inventory.Software, *software)
	}
	sort.Slice(inventory.Software, func(i, j int) bool {
		left, right := inventory.Software[i], inventory.Software[j]
		if left.priorityRank != right.priorityRank {
			return left.priorityRank > right.priorityRank
		}
		if left.score != right.score {
			return left.score > right.score
		}
		if left.Detections != right.Detections {
			return left.Detections > right.Detections
		}
		if left.Name != right.Name {
			return strings.ToLower(left.Name) < strings.ToLower(right.Name)
		}
		return left.Version < right.Version
	})
	return inventory, nil
}

func nestedString(value map[string]any, keys ...string) string {
	current := any(value)
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[key]
	}
	text, _ := current.(string)
	return strings.TrimSpace(text)
}

func nestedFloat(value map[string]any, keys ...string) float64 {
	current := any(value)
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return 0
		}
		current = object[key]
	}
	var score float64
	switch typed := current.(type) {
	case json.Number:
		score, _ = typed.Float64()
	case float64:
		score = typed
	case string:
		score, _ = strconv.ParseFloat(typed, 64)
	}
	if score < 0 || score > 10 {
		return 0
	}
	return score
}

func vulnerabilityPriority(severity string, score float64) (string, int, float64) {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical", 4, score
	case "high":
		return "high", 3, score
	case "medium", "moderate":
		return "medium", 2, score
	case "low":
		return "low", 1, score
	}
	switch {
	case score >= 9:
		return "critical", 4, score
	case score >= 7:
		return "high", 3, score
	case score >= 4:
		return "medium", 2, score
	case score > 0:
		return "low", 1, score
	default:
		return "unknown", 0, 0
	}
}
