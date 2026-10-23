package api

import (
	"net/http"
	"testing"
	"time"

	"scanning/internal/flow"
)

type searchEnvelope struct {
	Data  flowSearchPayload `json:"data"`
	Error *apiError         `json:"error"`
}

func TestSearchFlowsByBodyKeyword(t *testing.T) {
	ts, st := newTestServer(t, true)

	searchFlow := &flow.Flow{
		Scheme:     "https",
		Host:       "interfacepc.music.163.com",
		Port:       443,
		Method:     "POST",
		Path:       "/eapi/cloudsearch/pc",
		StatusCode: 200,
		Mime:       "application/json",
		State:      flow.StateCompleted,
		Mode:       flow.ModeProxy,
		Request: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Body:        &flow.Body{Size: 40, CapturedSize: 40, Mime: "application/json", Text: true, Preview: `{"s":"Taylor Swift"}`},
		},
		Response: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Body:        &flow.Body{Size: 60, CapturedSize: 60, Mime: "application/json", Text: true, Preview: `{"name":"Taylor Swift","id":1}`},
		},
		StartedAt: time.Now(),
	}
	added := st.Add(searchFlow)

	var out searchEnvelope
	status := getJSON(t, ts.URL+"/api/v1/flows/search?q=Taylor%20Swift", &out, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, error = %+v", status, out.Error)
	}
	if out.Data.Query != "Taylor Swift" {
		t.Fatalf("query = %q", out.Data.Query)
	}
	found := false
	for _, id := range out.Data.IDs {
		if id == added.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("未命中正文关键字: %+v", out.Data)
	}

	var none searchEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/search?q=nobody%20here", &none, nil); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if none.Data.Count != 0 {
		t.Fatalf("不期望的命中: %+v", none.Data)
	}
}

func TestSearchFlowsRejectsEmptyQuery(t *testing.T) {
	ts, _ := newTestServer(t, true)

	var out searchEnvelope
	status := getJSON(t, ts.URL+"/api/v1/flows/search?q=%20%20", &out, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d", status)
	}
}
