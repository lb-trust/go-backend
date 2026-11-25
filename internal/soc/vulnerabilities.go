package soc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const maxVulnerabilityDocuments = 10000
const vulnerabilityAgentPageSize = 1000

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
	AgentIP         string               `json:"agent_ip,omitempty"`
	OSName          string               `json:"os_name,omitempty"`
	OSPlatform      string               `json:"os_platform,omitempty"`
	OSVersion       string               `json:"os_version,omitempty"`
	Search          string               `json:"search"`
	TotalDetections int                  `json:"total_detections"`
	Truncated       bool                 `json:"truncated"`
	Software        []vulnerableSoftware `json:"software"`
}

var errAmbiguousAgentSearch = errors.New("plusieurs agents correspondent à cette recherche")

func (b *Backend) vulnerabilitiesHandler(w http.ResponseWriter, r *http.Request) {
	searchTerm := strings.TrimSpace(r.URL.Query().Get("search"))
	if searchTerm == "" {
		searchTerm = strings.TrimSpace(r.URL.Query().Get("agent_id"))
	}
	if searchTerm == "" || len(searchTerm) > 128 {
		writeError(w, http.StatusBadRequest, "la recherche est obligatoire et ne doit pas dépasser 128 caractères")
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

	inventory, err := b.fetchVulnerabilityInventory(r.Context(), *source, searchTerm)
	if err != nil {
		if errors.Is(err, errAmbiguousAgentSearch) {
			writeError(w, http.StatusConflict, "plusieurs agents correspondent ; utilisez l’ID ou l’adresse IP exacte")
			return
		}
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
		log.Printf("lecture de l’inventaire des vulnérabilités pour %q: %v", searchTerm, err)
		writeError(w, http.StatusBadGateway, "impossible de lire l’inventaire des vulnérabilités dans Wazuh Indexer")
		return
	}
	writeJSON(w, http.StatusOK, inventory)
}

func (b *Backend) fetchVulnerabilityInventory(ctx context.Context, source WazuhSource, searchTerm string) (vulnerabilityInventory, error) {
	index := source.VulnerabilitiesIndex
	if index == "" {
		index = defaultVulnerabilitiesIndex
	}
	vulnerabilityFields := []string{
		"agent.id", "agent.name", "agent.ip",
		"package.name", "package.version",
		"vulnerability.severity", "vulnerability.score.base",
		"host.name", "host.ip", "host.os.platform", "host.os.type",
		"host.os.name", "host.os.full", "host.os.version",
	}
	query := map[string]any{
		"size":             maxVulnerabilityDocuments,
		"track_total_hits": true,
		"_source":          vulnerabilityFields,
		"sort":             []any{map[string]any{"vulnerability.score.base": map[string]string{"order": "desc", "missing": "_last"}}},
		"query":            agentSearchQuery(searchTerm),
	}
	result, err := b.searchWazuhIndex(ctx, source, index, query)
	if err != nil {
		return vulnerabilityInventory{}, err
	}

	agents := vulnerabilityAgents(result.Hits.Hits)
	if len(agents) == 0 {
		alertsIndex := source.AlertsIndex
		if alertsIndex == "" {
			alertsIndex = "wazuh-alerts-*"
		}
		agentResult, err := b.searchWazuhIndex(ctx, source, alertsIndex, map[string]any{
			"size": 1000,
			"_source": []string{
				"agent.id", "agent.name", "agent.ip", "host.name", "host.ip",
			},
			"sort":  []any{map[string]any{"timestamp": map[string]string{"order": "desc"}}},
			"query": agentSearchQuery(searchTerm),
		})
		if err != nil {
			return vulnerabilityInventory{}, err
		}
		agents = vulnerabilityAgents(agentResult.Hits.Hits)
		if len(agents) == 1 {
			query["query"] = map[string]any{"term": map[string]string{"agent.id": agents[0].ID}}
			result, err = b.searchWazuhIndex(ctx, source, index, query)
			if err != nil {
				return vulnerabilityInventory{}, err
			}
		}
	}
	if len(agents) > 1 {
		return vulnerabilityInventory{}, errAmbiguousAgentSearch
	}
	if len(agents) == 0 {
		return vulnerabilityInventory{
			Search:   searchTerm,
			Software: []vulnerableSoftware{},
		}, nil
	}

	total, truncated := wazuhHitsTotal(result.Hits.Total, len(result.Hits.Hits))
	inventory := vulnerabilityInventory{
		AgentID:         searchTerm,
		Search:          searchTerm,
		TotalDetections: total,
		Truncated:       truncated || total > len(result.Hits.Hits),
		Software:        []vulnerableSoftware{},
	}
	if len(agents) == 1 {
		inventory.AgentID = agents[0].ID
		inventory.AgentName = agents[0].Name
		inventory.AgentIP = agents[0].IP
	}
	softwareByKey := make(map[string]*vulnerableSoftware)
	for _, hit := range result.Hits.Hits {
		if inventory.AgentIP == "" {
			inventory.AgentIP = firstString(
				nestedString(hit.Source, "agent", "ip"),
				nestedString(hit.Source, "host", "ip"),
			)
		}
		if inventory.OSName == "" {
			inventory.OSName = firstString(
				nestedString(hit.Source, "host", "os", "name"),
				nestedString(hit.Source, "host", "os", "full"),
			)
		}
		if inventory.OSPlatform == "" {
			inventory.OSPlatform = firstString(
				nestedString(hit.Source, "host", "os", "platform"),
				nestedString(hit.Source, "host", "os", "type"),
			)
		}
		if inventory.OSVersion == "" {
			inventory.OSVersion = nestedString(hit.Source, "host", "os", "version")
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

type wazuhSearchHit struct {
	Source map[string]any `json:"_source"`
}

type wazuhSearchResponse struct {
	Hits struct {
		Total json.RawMessage  `json:"total"`
		Hits  []wazuhSearchHit `json:"hits"`
	} `json:"hits"`
	Aggregations struct {
		Agents *wazuhAgentBuckets `json:"agents"`
	} `json:"aggregations"`
}

type wazuhAgentBuckets struct {
	Buckets []struct {
		Key struct {
			AgentID string `json:"agent_id"`
		} `json:"key"`
		Details struct {
			Hits struct {
				Hits []wazuhSearchHit `json:"hits"`
			} `json:"hits"`
		} `json:"details"`
	} `json:"buckets"`
	AfterKey struct {
		AgentID string `json:"agent_id"`
	} `json:"after_key"`
}

type vulnerabilityAgent struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Status string `json:"status,omitempty"`
}

func (b *Backend) vulnerabilityAgentsHandler(w http.ResponseWriter, r *http.Request) {
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

	agents, err := b.fetchVulnerabilityAgents(r.Context(), *source)
	if err != nil {
		log.Printf("lecture de la liste des agents Wazuh: %v", err)
		writeError(w, http.StatusBadGateway, "impossible de lire la liste des agents dans Wazuh Indexer")
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func (b *Backend) fetchVulnerabilityAgents(ctx context.Context, source WazuhSource) ([]vulnerabilityAgent, error) {
	agentsIndex := source.AgentsIndex
	if agentsIndex == "" {
		agentsIndex = defaultAgentsIndex
	}

	agentsByID := make(map[string]vulnerabilityAgent)
	afterKey := ""
	for {
		composite := map[string]any{
			"size": vulnerabilityAgentPageSize,
			"sources": []any{
				map[string]any{"agent_id": map[string]any{"terms": map[string]string{"field": "agent.id"}}},
			},
		}
		if afterKey != "" {
			composite["after"] = map[string]string{"agent_id": afterKey}
		}
		result, err := b.searchWazuhIndex(ctx, source, agentsIndex, map[string]any{
			"size":  0,
			"query": map[string]any{"match_all": map[string]any{}},
			"aggs": map[string]any{
				"agents": map[string]any{
					"composite": composite,
					"aggs": map[string]any{
						"details": map[string]any{
							"top_hits": map[string]any{
								"size": 1,
								"_source": []string{
									"agent.id", "agent.name", "agent.ip", "agent.status",
									"host.name", "host.ip",
								},
							},
						},
					},
				},
			},
		})
		if err != nil {
			return nil, err
		}
		if result.Aggregations.Agents == nil {
			return nil, fmt.Errorf("Wazuh Indexer n’a pas renvoyé l’agrégation des agents")
		}
		for _, bucket := range result.Aggregations.Agents.Buckets {
			agent := vulnerabilityAgent{ID: bucket.Key.AgentID}
			found := vulnerabilityAgents(bucket.Details.Hits.Hits)
			if len(found) > 0 {
				agent.Name = found[0].Name
				agent.IP = found[0].IP
				agent.Status = found[0].Status
				if agent.ID == "" {
					agent.ID = found[0].ID
				}
			}
			if agent.ID != "" {
				agentsByID[agent.ID] = agent
			}
		}
		nextAfterKey := result.Aggregations.Agents.AfterKey.AgentID
		if nextAfterKey == "" {
			break
		}
		if nextAfterKey == afterKey {
			return nil, fmt.Errorf("Wazuh Indexer n’a pas avancé dans la pagination des agents")
		}
		afterKey = nextAfterKey
	}

	agents := make([]vulnerabilityAgent, 0, len(agentsByID))
	for _, agent := range agentsByID {
		agents = append(agents, agent)
	}
	sort.Slice(agents, func(i, j int) bool {
		leftName, rightName := strings.ToLower(agents[i].Name), strings.ToLower(agents[j].Name)
		if leftName != rightName {
			return leftName < rightName
		}
		return agents[i].ID < agents[j].ID
	})
	return agents, nil
}

func (b *Backend) searchWazuhIndex(ctx context.Context, source WazuhSource, index string, query map[string]any) (wazuhSearchResponse, error) {
	endpoint, err := wazuhIndexSearchURL(source.URL, index)
	if err != nil {
		return wazuhSearchResponse{}, err
	}
	body, err := json.Marshal(query)
	if err != nil {
		return wazuhSearchResponse{}, fmt.Errorf("encoder la requête Wazuh: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return wazuhSearchResponse{}, fmt.Errorf("créer la requête Wazuh: %w", err)
	}
	request.SetBasicAuth(source.Username, source.Password)
	request.Header.Set("Content-Type", "application/json")

	response, err := b.wazuhHTTPClient(source).Do(request)
	if err != nil {
		return wazuhSearchResponse{}, fmt.Errorf("contacter Wazuh Indexer: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return wazuhSearchResponse{}, &wazuhHTTPError{statusCode: response.StatusCode}
	}

	var result wazuhSearchResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxRequestBytes*10))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		return wazuhSearchResponse{}, fmt.Errorf("décoder la réponse Wazuh: %w", err)
	}
	return result, nil
}

func (b *Backend) checkWazuhVulnerabilityIndex(ctx context.Context, source WazuhSource) error {
	index := source.VulnerabilitiesIndex
	if index == "" {
		index = defaultVulnerabilitiesIndex
	}
	_, err := b.searchWazuhIndex(ctx, source, index, map[string]any{
		"size":  0,
		"query": map[string]any{"match_all": map[string]any{}},
	})
	return err
}

func (b *Backend) checkWazuhAgentsIndex(ctx context.Context, source WazuhSource) error {
	index := source.AgentsIndex
	if index == "" {
		index = defaultAgentsIndex
	}
	_, err := b.searchWazuhIndex(ctx, source, index, map[string]any{
		"size":  0,
		"query": map[string]any{"match_all": map[string]any{}},
	})
	return err
}

func agentSearchQuery(searchTerm string) map[string]any {
	return map[string]any{
		"bool": map[string]any{
			"should": []any{
				map[string]any{"term": map[string]string{"agent.id": searchTerm}},
				map[string]any{"match_phrase": map[string]string{"agent.name": searchTerm}},
				map[string]any{"match_phrase": map[string]string{"host.name": searchTerm}},
				map[string]any{"term": map[string]string{"agent.ip": searchTerm}},
				map[string]any{"term": map[string]string{"host.ip": searchTerm}},
			},
			"minimum_should_match": 1,
		},
	}
}

func vulnerabilityAgents(hits []wazuhSearchHit) []vulnerabilityAgent {
	byID := make(map[string]vulnerabilityAgent)
	for _, hit := range hits {
		id := firstString(nestedString(hit.Source, "agent", "id"), nestedString(hit.Source, "id"))
		if id == "" {
			continue
		}
		agent := byID[id]
		agent.ID = id
		if agent.Name == "" {
			agent.Name = firstString(
				nestedString(hit.Source, "agent", "name"),
				nestedString(hit.Source, "host", "name"),
				nestedString(hit.Source, "name"),
			)
		}
		if agent.IP == "" {
			agent.IP = firstString(
				nestedString(hit.Source, "agent", "ip"),
				nestedString(hit.Source, "host", "ip"),
			)
		}
		if agent.Status == "" {
			agent.Status = firstString(
				nestedString(hit.Source, "agent", "status"),
				nestedString(hit.Source, "status"),
			)
		}
		byID[id] = agent
	}
	agents := make([]vulnerabilityAgent, 0, len(byID))
	for _, agent := range byID {
		agents = append(agents, agent)
	}
	return agents
}

func wazuhHitsTotal(raw json.RawMessage, hitCount int) (int, bool) {
	if len(raw) == 0 {
		return hitCount, false
	}
	var result struct {
		Value    int    `json:"value"`
		Relation string `json:"relation"`
	}
	if err := json.Unmarshal(raw, &result); err == nil {
		return result.Value, result.Relation == "gte"
	}
	var total int
	if err := json.Unmarshal(raw, &total); err == nil {
		return total, false
	}
	return hitCount, false
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
