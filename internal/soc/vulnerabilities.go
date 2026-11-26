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
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
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
	if source.ManagerAPIURL == "" {
		writeError(w, http.StatusServiceUnavailable,
			"configurez l’API du manager Wazuh pour afficher les agents actuels")
		return
	}
	if err := validateWazuhManagerAPI(*source); err != nil {
		writeError(w, http.StatusServiceUnavailable,
			"configurez l’API du manager Wazuh pour afficher les agents actuels")
		return
	}

	agents, err := b.fetchCurrentWazuhAgents(r.Context(), *source)
	if err != nil {
		log.Printf("lecture des agents en ligne via l’API Wazuh: %v", err)
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusBadGateway,
				"l’API du manager Wazuh ne répond pas depuis le serveur SOC avant le délai maximal ; vérifiez l’URL, le port 55000 et l’accès réseau depuis ce serveur")
			return
		}
		writeError(w, http.StatusBadGateway, "impossible de lire les agents en ligne via l’API du manager Wazuh")
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func (b *Backend) fetchCurrentWazuhAgents(ctx context.Context, source WazuhSource) ([]vulnerabilityAgent, error) {
	apiURL := strings.TrimRight(source.ManagerAPIURL, "/")
	client := b.wazuhManagerAPIHTTPClient(source)
	authRequest, err := http.NewRequestWithContext(ctx, http.MethodPost,
		apiURL+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return nil, fmt.Errorf("créer la requête d’authentification à l’API Wazuh: %w", err)
	}
	authRequest.SetBasicAuth(source.ManagerAPIUsername, source.ManagerAPIPassword)
	authResponse, err := client.Do(authRequest)
	if err != nil {
		return nil, fmt.Errorf("contacter l’API du manager Wazuh: %w", err)
	}
	if authResponse.StatusCode < http.StatusOK || authResponse.StatusCode >= http.StatusMultipleChoices {
		authResponse.Body.Close()
		return nil, fmt.Errorf("l’API du manager Wazuh a refusé l’authentification (HTTP %d)", authResponse.StatusCode)
	}
	authBody, decodeErr := io.ReadAll(io.LimitReader(authResponse.Body, 1<<20))
	authResponse.Body.Close()
	if decodeErr != nil {
		return nil, fmt.Errorf("décoder la réponse d’authentification de l’API Wazuh: %w", decodeErr)
	}
	token := ""
	var authResult struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(authBody, &authResult); err == nil {
		token = authResult.Data.Token
	} else {
		var rawToken string
		if json.Unmarshal(authBody, &rawToken) == nil && rawToken != "" {
			token = rawToken
		} else {
			token = strings.TrimSpace(string(authBody))
		}
	}
	if token == "" {
		return nil, errors.New("l’API du manager Wazuh n’a pas renvoyé de jeton")
	}

	agentsByID := make(map[string]vulnerabilityAgent)
	const pageSize = 500
	for offset := 0; ; {
		query := url.Values{
			"status": {"active"},
			"limit":  {strconv.Itoa(pageSize)},
			"offset": {strconv.Itoa(offset)},
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet,
			apiURL+"/agents?"+query.Encode(), nil)
		if err != nil {
			return nil, fmt.Errorf("créer la requête des agents en ligne: %w", err)
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("lire les agents en ligne dans l’API Wazuh: %w", err)
		}
		if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
			response.Body.Close()
			return nil, fmt.Errorf("l’API du manager Wazuh a refusé la lecture des agents (HTTP %d)", response.StatusCode)
		}
		var result struct {
			Data struct {
				Agents []struct {
					ID     string `json:"id"`
					Name   string `json:"name"`
					IP     string `json:"ip"`
					Status string `json:"status"`
				} `json:"affected_items"`
				Total int `json:"total_affected_items"`
			} `json:"data"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 16<<20)).Decode(&result)
		response.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("décoder la liste des agents Wazuh: %w", decodeErr)
		}
		if result.Data.Total < 0 {
			return nil, errors.New("l’API du manager Wazuh a renvoyé un total d’agents invalide")
		}
		for _, agent := range result.Data.Agents {
			if agent.ID == "" || !strings.EqualFold(agent.Status, "active") {
				continue
			}
			agentsByID[agent.ID] = vulnerabilityAgent{ID: agent.ID, Name: agent.Name, IP: agent.IP}
		}
		offset += len(result.Data.Agents)
		if offset >= result.Data.Total {
			break
		}
		if len(result.Data.Agents) == 0 {
			return nil, errors.New("l’API du manager Wazuh a renvoyé une page vide avant la fin de la liste")
		}
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
		id := nestedString(hit.Source, "agent", "id")
		if id == "" {
			continue
		}
		agent := byID[id]
		agent.ID = id
		if agent.Name == "" {
			agent.Name = firstString(
				nestedString(hit.Source, "agent", "name"),
				nestedString(hit.Source, "host", "name"),
			)
		}
		if agent.IP == "" {
			agent.IP = firstString(
				nestedString(hit.Source, "agent", "ip"),
				nestedString(hit.Source, "host", "ip"),
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
