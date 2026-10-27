package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/lb-trust/go-backend/internal/soc"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	config, err := soc.LoadConfig()
	if err != nil {
		return err
	}
	if config.GeneratedToken != "" {
		log.Printf("Jeton API du client client-a : %s (conservé dans %s)",
			config.GeneratedToken, config.TokenFilePath)
	}
	backend, err := soc.NewBackend(config)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		stop()
		backend.WaitBackground()
		if err := backend.Close(); err != nil {
			log.Printf("fermer la base SQLite: %v", err)
		}
	}()
	backend.StartCollectors(ctx)
	backend.StartAIWorker(ctx)

	server := &http.Server{
		Addr:              net.JoinHostPort(config.Host, fmt.Sprint(config.Port)),
		Handler:           backend.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serverDone := make(chan error, 1)
	go func() {
		log.Printf("Backend SOC à l'écoute sur %s", server.Addr)
		if config.Host == "0.0.0.0" || config.Host == "::" {
			logAccessURLs(config.Port)
		} else {
			log.Printf("Tableau de bord : http://%s/", server.Addr)
		}
		serverDone <- server.ListenAndServe()
	}()

	select {
	case err := <-serverDone:
		if !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serveur HTTP: %w", err)
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("arrêter le serveur HTTP: %w", err)
		}
	}
	return nil
}

func logAccessURLs(port int) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("impossible de détecter les adresses réseau : %v", err)
		return
	}

	found := false
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ip == nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		log.Printf("Tableau de bord (réseau) : http://%s:%d/", ip.String(), port)
		found = true
	}
	if !found {
		log.Printf("aucune adresse IPv4 réseau détectée ; vérifiez la configuration réseau")
	}
}
