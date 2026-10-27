package soc

import (
	"embed"
	"log"
	"net/http"
	"strings"
)

//go:embed web/index.html web/dashboard.css web/dashboard.js
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
			index, err := dashboardFiles.ReadFile("web/index.html")
			if err != nil {
				log.Printf("lire le tableau de bord embarqué: %v", err)
				http.Error(w, "erreur interne", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(index); err != nil {
				log.Printf("envoyer le tableau de bord: %v", err)
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
