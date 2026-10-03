package h2cproxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"imuslab.com/zoraxy/mod/utils"
)

// Management handlers must be mounted on Zoraxy's authenticated, CSRF-protected
// admin router. Mutation endpoints accept POST only, never URL query parameters.
func (m *Manager) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.List())
}

func decodeMutation(w http.ResponseWriter, r *http.Request, value any) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		sendError(w, "Invalid request: "+err.Error())
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		sendError(w, "Expected one JSON object")
		return false
	}
	return true
}

func (m *Manager) HandleSave(w http.ResponseWriter, r *http.Request) {
	var config Config
	if !decodeMutation(w, r, &config) {
		return
	}
	saved, err := m.Save(config)
	if err != nil {
		sendError(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(saved)
}

func (m *Manager) HandleEnabled(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID      string
		Enabled *bool
	}
	if !decodeMutation(w, r, &request) {
		return
	}
	if request.Enabled == nil {
		sendError(w, "Enabled is required")
		return
	}
	if err := m.SetEnabled(request.ID, *request.Enabled); err != nil {
		sendError(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func (m *Manager) HandleDelete(w http.ResponseWriter, r *http.Request) {
	var request struct{ ID string }
	if !decodeMutation(w, r, &request) {
		return
	}
	if err := m.Delete(request.ID); err != nil {
		sendError(w, err.Error())
		return
	}
	utils.SendOK(w)
}

func sendError(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
