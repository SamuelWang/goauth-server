package main

import (
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// load .env in dev (ignored if missing)
	err := godotenv.Load()
	if err != nil {
		// handle error if needed, for now just print it
		println("Error loading .env file")
	}

	// get port from environment variable or default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// allow GIN_MODE to control mode (debug/release/test)
	if m := os.Getenv("GIN_MODE"); m != "" {
		gin.SetMode(m)
	}

	// Create a Gin router with default middleware (logger and recovery)
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		// If the client is 192.168.1.2, use the X-Forwarded-For
		// header to deduce the original client IP from the trust-
		// worthy parts of that header.
		// Otherwise, simply return the direct client IP
		fmt.Printf("ClientIP: %s\n", c.ClientIP())
	})

	// Start server on port 8080 (default)
	// Server will listen on 0.0.0.0:8080 (localhost:8080 on Windows)
	r.Run(":" + port)
}
