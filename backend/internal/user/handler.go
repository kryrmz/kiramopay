package user

import (
	"errors"
	"encoding/json"
	"net/http"

	"github.com/kiramopay/backend/internal/middleware"
	"github.com/kiramopay/backend/pkg/response"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "user not authenticated")
		return
	}

	profile, err := h.service.GetProfile(r.Context(), userID)
	if err != nil {
		response.Error(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	response.JSON(w, http.StatusOK, profile)
}

func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID := middleware.GetUserID(r.Context())
	if userID == "" {
		response.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "user not authenticated")
		return
	}

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Error(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}

	profile, err := h.service.UpdateProfile(r.Context(), userID, &req)
	if err != nil {
		if errors.Is(err, ErrCuentaDeDemostracion) {
			response.Error(w, http.StatusForbidden, "DEMO_ACCOUNT",
				"una cuenta de demostracion no puede cambiar sus datos")
			return
		}
		if errors.Is(err, ErrContrasenaRequerida) {
			response.Error(w, http.StatusForbidden, "PASSWORD_REQUIRED",
				"se requiere la contrasena vigente para cambiar el correo")
			return
		}
		response.Error(w, http.StatusInternalServerError, "UPDATE_FAILED", err.Error())
		return
	}

	response.JSON(w, http.StatusOK, profile)
}
