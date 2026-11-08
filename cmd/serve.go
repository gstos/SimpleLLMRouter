package cmd

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/gstos/SimpleLLMRouter/internal/health"
	"github.com/gstos/SimpleLLMRouter/internal/router"
	"github.com/gstos/SimpleLLMRouter/internal/server"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the router (requires the master key)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadDecryptedConfig()
		if err != nil {
			return err
		}
		log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

		rt := router.New(cfg)
		checker := health.New(cfg.Providers, cfg.Server.HealthTimeout, func(r health.Result) {
			rt.SetProviderHealthy(r.Provider, r.Healthy)
			if !r.Healthy {
				log.Warn("provider unhealthy", "provider", r.Provider, "status", r.Status, "err", r.Error)
			}
		})

		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if cfg.Server.HealthInterval > 0 {
			go checker.Run(ctx, cfg.Server.HealthInterval)
		}

		srv := &http.Server{
			Addr:              cfg.Server.Listen,
			Handler:           server.New(cfg, rt, checker, log).Handler(),
			ReadHeaderTimeout: 10 * time.Second,
		}
		errc := make(chan error, 1)
		go func() { errc <- srv.ListenAndServe() }()
		log.Info("listening", "addr", cfg.Server.Listen, "providers", len(cfg.Providers), "models", len(cfg.Models))

		select {
		case err := <-errc:
			return err
		case <-ctx.Done():
		}
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	},
}
