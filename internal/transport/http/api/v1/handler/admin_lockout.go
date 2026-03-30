package handler

import (
	"errors"
	"log"
	"net/http"

	"github.com/SamuelWang/goauth-server/internal/service/audit"
	"github.com/SamuelWang/goauth-server/internal/service/user"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// UnlockUser handles DELETE /api/v1/admin/users/:id/lockout — clears the lockout
// on a user account. Admin only.
//
// @Summary     Unlock a locked user account
// @Description Clears the locked_until field for the specified user. Admin only.
// @Tags        Users
// @Produce     json
// @Param       id   path      string  true  "User UUID"
// @Success     204
// @Failure     403  {object}  handler.ErrorResponse
// @Failure     404  {object}  handler.ErrorResponse
// @Failure     500  {object}  handler.ErrorResponse
// @Security    BearerAuth
// @Router      /api/v1/admin/users/{id}/lockout [delete]
func (h *ApiV1Handler) UnlockUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if err := h.userService.UnlockUserAccount(c.Request.Context(), id); err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			return
		}
		log.Printf("UnlockUser: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
		return
	}

	// Write audit entry for the admin action.
	if h.auditSvc != nil {
		var actorID *uuid.UUID
		if actorIDStr, ok := getUserID(c); ok {
			if parsed, err := uuid.Parse(actorIDStr); err == nil {
				actorID = &parsed
			}
		}
		_ = h.auditSvc.LogEvent(c.Request.Context(), audit.AuditEntry{
			EventType: audit.EventAccountUnlocked,
			UserID:    &id,
			ActorID:   actorID,
			Metadata:  map[string]any{"reason": "admin_unlock"},
		})
	}

	c.Status(http.StatusNoContent)
}
