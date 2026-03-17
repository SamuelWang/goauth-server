package handler_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SamuelWang/goauth-server/internal/transport/http/ops/handler"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestHealthCheck_Returns200(t *testing.T) {
	router := gin.New()
	router.GET("/ops/health", handler.HealthCheck)

	req := httptest.NewRequest(http.MethodGet, "/ops/health", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
