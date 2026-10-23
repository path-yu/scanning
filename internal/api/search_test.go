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

func TestSearchFlowsScope(t *testing.T) {
	ts, st := newTestServer(t, true)

	bodyFlow := &flow.Flow{
		Scheme:     "https",
		Host:       "api.example.com",
		Port:       443,
		Method:     "POST",
		Path:       "/body-only",
		StatusCode: 200,
		Mime:       "application/json",
		State:      flow.StateCompleted,
		Mode:       flow.ModeProxy,
		Request: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Body:        &flow.Body{Size: 24, CapturedSize: 24, Mime: "application/json", Text: true, Preview: `{"want":"request-only"}`},
		},
		Response: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Body:        &flow.Body{Size: 20, CapturedSize: 20, Mime: "application/json", Text: true, Preview: `{"kind":"player"}`},
		},
		StartedAt: time.Now(),
	}
	urlFlow := &flow.Flow{
		Scheme:     "https",
		Host:       "player.example.com",
		Port:       443,
		Method:     "GET",
		Path:       "/api/player",
		StatusCode: 200,
		Mime:       "application/json",
		State:      flow.StateCompleted,
		Mode:       flow.ModeProxy,
		StartedAt:  time.Now(),
	}
	addedBody := st.Add(bodyFlow)
	addedURL := st.Add(urlFlow)

	contains := func(ids []string, target string) bool {
		for _, id := range ids {
			if id == target {
				return true
			}
		}
		return false
	}

	var urlOut searchEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/search?q=player&scope=url", &urlOut, nil); status != http.StatusOK {
		t.Fatalf("url scope status=%d", status)
	}
	if !contains(urlOut.Data.IDs, addedURL.ID) || contains(urlOut.Data.IDs, addedBody.ID) {
		t.Fatalf("url scope = %+v", urlOut.Data.IDs)
	}

	var bodyOut searchEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/search?q=player&scope=body", &bodyOut, nil); status != http.StatusOK {
		t.Fatalf("body scope status=%d", status)
	}
	if !contains(bodyOut.Data.IDs, addedBody.ID) || contains(bodyOut.Data.IDs, addedURL.ID) {
		t.Fatalf("body scope = %+v", bodyOut.Data.IDs)
	}

	var responseOut searchEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/search?q=player&scope=response", &responseOut, nil); status != http.StatusOK {
		t.Fatalf("response scope status=%d", status)
	}
	if !contains(responseOut.Data.IDs, addedBody.ID) || contains(responseOut.Data.IDs, addedURL.ID) {
		t.Fatalf("response scope = %+v", responseOut.Data.IDs)
	}

	var requestOut searchEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/search?q=request-only&scope=request", &requestOut, nil); status != http.StatusOK {
		t.Fatalf("request scope status=%d", status)
	}
	if !contains(requestOut.Data.IDs, addedBody.ID) {
		t.Fatalf("request scope = %+v", requestOut.Data.IDs)
	}

	var requestMiss searchEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/search?q=request-only&scope=response", &requestMiss, nil); status != http.StatusOK {
		t.Fatalf("response scope status=%d", status)
	}
	if contains(requestMiss.Data.IDs, addedBody.ID) {
		t.Fatalf("response scope matched request-only body: %+v", requestMiss.Data.IDs)
	}

	var allOut searchEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/search?q=player&scope=all", &allOut, nil); status != http.StatusOK {
		t.Fatalf("all scope status=%d", status)
	}
	if !contains(allOut.Data.IDs, addedBody.ID) || !contains(allOut.Data.IDs, addedURL.ID) {
		t.Fatalf("all scope = %+v", allOut.Data.IDs)
	}

	var bad searchEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/search?q=player&scope=bad", &bad, nil); status != http.StatusBadRequest {
		t.Fatalf("invalid scope status=%d", status)
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
