package sub

import (
	"fmt"
	"strings"

	"github.com/alireza0/s-ui/logger"
	"github.com/alireza0/s-ui/service"

	"github.com/gin-gonic/gin"
)

type SubHandler struct {
	service.SettingService
	SubService
	JsonService
	ClashService
}

func NewSubHandler(g *gin.RouterGroup) {
	a := &SubHandler{}
	a.initRouter(g)
}

func (s *SubHandler) initRouter(g *gin.RouterGroup) {
	g.GET("/:subid", s.subs)
	g.HEAD("/:subid", s.subHeaders)
}

func (s *SubHandler) subs(c *gin.Context) {
	var headers []string
	var result *string
	var err error
	subId := c.Param("subid")
	format, valid := subscriptionFormat(c)
	if !valid {
		c.String(400, "Error!")
		return
	}
	switch {
	case format == "json":
		result, headers, err = s.JsonService.GetJson(subId, format)
	case format == "clash":
		result, headers, err = s.ClashService.GetClash(subId)
	case format == "happ":
		result, headers, err = s.SubService.getSubs(subId, happLinks)
	case format == "":
		result, headers, err = s.SubService.GetSubs(subId)
	}
	if err != nil || result == nil {
		logger.Error(err)
		c.String(400, "Error!")
		return
	}

	s.addHeaders(c, headers)

	c.String(200, *result)
}

// subscriptionFormat is shared by GET and HEAD. An explicit format never
// depends on the User-Agent, including when the explicit value is invalid.
func subscriptionFormat(c *gin.Context) (string, bool) {
	query := c.Request.URL.Query()
	if query.Has("format") {
		format := query.Get("format")
		return format, format == "json" || format == "clash" || format == "happ"
	}
	for _, vary := range c.Writer.Header().Values("Vary") {
		for _, field := range strings.Split(vary, ",") {
			if strings.EqualFold(strings.TrimSpace(field), "User-Agent") || strings.TrimSpace(field) == "*" {
				return formatForUserAgent(c.Request.UserAgent()), true
			}
		}
	}
	c.Writer.Header().Add("Vary", "User-Agent")
	return formatForUserAgent(c.Request.UserAgent()), true
}

func (s *SubHandler) subHeaders(c *gin.Context) {
	if _, valid := subscriptionFormat(c); !valid {
		c.Status(400)
		return
	}
	subId := c.Param("subid")
	client, err := s.SubService.getClientBySubId(subId)
	if err != nil {
		logger.Error(err)
		c.Status(400)
		return
	}

	headers := s.SubService.getClientHeaders(client)
	s.addHeaders(c, headers)

	c.Status(200)
}

func (s *SubHandler) addHeaders(c *gin.Context, headers []string) {
	c.Writer.Header().Set("Subscription-Userinfo", headers[0])
	c.Writer.Header().Set("Profile-Update-Interval", headers[1])
	c.Writer.Header().Set("Profile-Title", headers[2])
	c.Writer.Header().Set("Content-Disposition", contentDispositionHeader(headers[2]))
}

func contentDispositionHeader(name string) string {
	filename := strings.TrimSpace(name)
	if filename == "" {
		filename = "subscription"
	}

	return fmt.Sprintf("attachment; filename=\"%s\"; filename*=UTF-8''%s", asciiSafeFilename(filename), rfc5987Encode(filename))
}

func asciiSafeFilename(filename string) string {
	var builder strings.Builder
	for _, r := range filename {
		switch {
		case r == '"' || r == '\\':
			builder.WriteByte('_')
		case r >= 0x20 && r <= 0x7e:
			builder.WriteRune(r)
		}
	}

	fallback := strings.TrimSpace(builder.String())
	if fallback == "" {
		return "subscription"
	}

	return fallback
}

func rfc5987Encode(filename string) string {
	const hex = "0123456789ABCDEF"

	var builder strings.Builder
	for _, b := range []byte(filename) {
		if isRFC5987AttrChar(b) {
			builder.WriteByte(b)
			continue
		}

		builder.WriteByte('%')
		builder.WriteByte(hex[b>>4])
		builder.WriteByte(hex[b&0x0f])
	}

	return builder.String()
}

func isRFC5987AttrChar(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z':
		return true
	case b >= 'A' && b <= 'Z':
		return true
	case b >= '0' && b <= '9':
		return true
	}

	switch b {
	case '!', '#', '$', '&', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}
