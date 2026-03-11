package api

import (
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/SamuelWang/goauth-server/docs-swagger" // swag-generated docs
	"github.com/gin-gonic/gin"
)

// registerDocsRoutes mounts the Swagger UI at /api/docs.
// Only call this in non-production environments.
//
//   - GET /api/docs/*any → Swagger UI
func registerDocsRoutes(r *gin.RouterGroup) {
	// gin-swagger registers its own sub-paths via /*any, so we register it
	// at the group level with the full prefix stripped.
	// Override the global `default-src 'none'` CSP set by SecurityHeadersMiddleware.
	// Swagger UI requires scripts and styles from unpkg.com, data: URI images,
	// and blob: workers. The spec itself is fetched from 'self'.
	r.GET("/docs/*any", func(c *gin.Context) {
		c.Header("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' unpkg.com; "+
				"style-src 'self' 'unsafe-inline' unpkg.com; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"worker-src blob:; "+
				"frame-ancestors 'none'")
		ginSwagger.WrapHandler(swaggerFiles.Handler)(c)
	})
}
