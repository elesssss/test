package sub

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSubscriptionFormatAndVaryForGetAndHead(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, test := range []struct {
			query, agent, vary, want string
			valid, negotiated        bool
		}{
			{"", "Happ/1.0", "Accept-Encoding", "happ", true, true},
			{"", "SFA/1.0", "Accept-Encoding, User-Agent", "json", true, true},
			{"", "mihomo/1.0", "*", "clash", true, true},
			{"", "HiddifyNext/1.0 like Clash", "", "", true, true},
			{"?format=json", "Happ/1.0", "Accept-Encoding", "json", true, false},
			{"?format=happ", "mihomo/1.0", "", "happ", true, false},
			{"?format=clash", "SFA/1.0", "", "clash", true, false},
			{"?format=unknown", "SFA/1.0", "", "unknown", false, false},
			{"?format=", "Happ/1.0", "", "", false, false},
		} {
			response := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(response)
			c.Request = httptest.NewRequest(method, "/sub/test"+test.query, nil)
			c.Request.Header.Set("User-Agent", test.agent)
			if test.vary != "" {
				c.Writer.Header().Set("Vary", test.vary)
			}
			got, valid := subscriptionFormat(c)
			if got != test.want || valid != test.valid {
				t.Fatalf("%s %s %s: (%q,%v), want (%q,%v)", method, test.query, test.agent, got, valid, test.want, test.valid)
			}
			vary := strings.Join(response.Header().Values("Vary"), ",")
			if test.negotiated && !strings.Contains(vary, "User-Agent") && vary != "*" {
				t.Fatalf("missing negotiated Vary: %s", vary)
			}
			if !test.negotiated && vary != test.vary {
				t.Fatalf("explicit format changed Vary: %s", vary)
			}
			if strings.Contains(test.vary, "Accept-Encoding") && !strings.Contains(vary, "Accept-Encoding") {
				t.Fatal("lost existing Vary header")
			}
		}
	}
}

func TestInvalidFormatStatusMatchesGetAndHead(t *testing.T) {
	router := gin.New()
	NewSubHandler(router.Group("/sub"))
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, query := range []string{"?format=", "?format=unsupported"} {
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(method, "/sub/test"+query, nil))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("%s %s: status %d", method, query, recorder.Code)
			}
			if method == http.MethodHead && recorder.Body.Len() != 0 {
				t.Fatal("HEAD wrote a body")
			}
		}
	}
}
