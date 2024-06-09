package main

import (
	"os"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func initLogger() {
	// Configure zerolog to write to both the console and a file

	// Open a file for logging
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open log file")
	}

	// Create a multi-writer to write to both console and file
	multi := zerolog.MultiLevelWriter(zerolog.ConsoleWriter{Out: os.Stderr}, logFile)

	// Configure the global logger
	log.Logger = zerolog.New(multi).With().Timestamp().Logger()
}
