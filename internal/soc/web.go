package soc

import (
	"embed"
	"log"
	"net/http"
	"strings"
)

//go:embed web/home.html web/home.js web/index.html web/dashboard.css web/dashboard.js web/maintenance.html web/maintenance.js web/accounts.html web/settings.html web/admin.js web/vulnerabilities.html web/vulnerabilities.js web/account-menu.js
var dashboardFiles embed.FS

func dashboardHandler() http.Handler {
	files := http.FileServer(http.FS(dashboardFiles))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/" {
			index, err := dashboardFiles.ReadFile("web/home.html")
			if err != nil {
				log.Printf("lire la page d’accueil embarquée: %v", err)
				http.Error(w, "erreur interne", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(index); err != nil {
				log.Printf("envoyer la page d’accueil: %v", err)
			}
			return
		} else if r.URL.Path == "/events" {
			page, err := dashboardFiles.ReadFile("web/index.html")
			if err != nil {
				log.Printf("lire la page des événements embarquée: %v", err)
				http.Error(w, "erreur interne", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(page); err != nil {
				log.Printf("envoyer la page des événements: %v", err)
			}
			return
		} else if r.URL.Path == "/maintenance" {
			page, err := dashboardFiles.ReadFile("web/maintenance.html")
			if err != nil {
				log.Printf("lire la page de maintenance embarquée: %v", err)
				http.Error(w, "erreur interne", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(page); err != nil {
				log.Printf("envoyer la page de maintenance: %v", err)
			}
			return
		} else if r.URL.Path == "/vulnerabilities" {
			page, err := dashboardFiles.ReadFile("web/vulnerabilities.html")
			if err != nil {
				log.Printf("lire la page des vulnérabilités embarquée: %v", err)
				http.Error(w, "erreur interne", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(page); err != nil {
				log.Printf("envoyer la page des vulnérabilités: %v", err)
			}
			return
		} else if r.URL.Path == "/accounts" || r.URL.Path == "/settings" {
			pageName := "web/accounts.html"
			if r.URL.Path == "/settings" {
				pageName = "web/settings.html"
			}
			page, err := dashboardFiles.ReadFile(pageName)
			if err != nil {
				log.Printf("lire la page d’administration embarquée: %v", err)
				http.Error(w, "erreur interne", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(page); err != nil {
				log.Printf("envoyer la page d’administration: %v", err)
			}
			return
		} else if strings.HasPrefix(r.URL.Path, "/assets/") {
			r.URL.Path = "/web/" + strings.TrimPrefix(r.URL.Path, "/assets/")
		} else {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}
