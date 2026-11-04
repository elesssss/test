package service

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/alireza0/s-ui/database"
	"github.com/alireza0/s-ui/database/model"
	"github.com/alireza0/s-ui/util"
	"github.com/alireza0/s-ui/util/common"

	"gorm.io/gorm"
)

type InboundService struct {
	ClientService
}

func (s *InboundService) Get(ids string) (*[]map[string]interface{}, error) {
	if ids == "" {
		return s.GetAll()
	}
	return s.getById(ids)
}

func (s *InboundService) getById(ids string) (*[]map[string]interface{}, error) {
	var inbound []model.Inbound
	var result []map[string]interface{}
	db := database.GetDB()
	err := db.Model(model.Inbound{}).Where("id in ?", strings.Split(ids, ",")).Scan(&inbound).Error
	if err != nil {
		return nil, err
	}
	for _, inb := range inbound {
		inbData, err := inb.MarshalFull()
		if err != nil {
			return nil, err
		}
		result = append(result, *inbData)
	}
	return &result, nil
}

func (s *InboundService) GetAll() (*[]map[string]interface{}, error) {
	db := database.GetDB()
	inbounds := []model.Inbound{}
	err := db.Model(model.Inbound{}).Scan(&inbounds).Error
	if err != nil {
		return nil, err
	}
	var data []map[string]interface{}
	for _, inbound := range inbounds {
		enabled, err := inbound.IsEnabled()
		if err != nil {
			return nil, err
		}
		var shadowtls_version uint
		ss_managed := false
		inbData := map[string]interface{}{
			"id":     inbound.Id,
			"type":   inbound.Type,
			"tag":    inbound.Tag,
			"tls_id": inbound.TlsId,
			"enable": enabled,
		}
		if inbound.Options != nil {
			var restFields map[string]json.RawMessage
			if err := json.Unmarshal(inbound.Options, &restFields); err != nil {
				return nil, err
			}
			inbData["listen"] = restFields["listen"]
			inbData["listen_port"] = restFields["listen_port"]
			if inbound.Type == "shadowtls" {
				json.Unmarshal(restFields["version"], &shadowtls_version)
			}
			if inbound.Type == "shadowsocks" {
				json.Unmarshal(restFields["managed"], &ss_managed)
			}
		}
		if s.hasUser(inbound.Type) &&
			!(inbound.Type == "shadowtls" && shadowtls_version < 3) &&
			!(inbound.Type == "shadowsocks" && ss_managed) {
			users := []string{}
			err = db.Raw("SELECT clients.name FROM clients, json_each(clients.inbounds) as je WHERE je.value = ?", inbound.Id).Scan(&users).Error
			if err != nil {
				return nil, err
			}
			inbData["users"] = users
		}

		data = append(data, inbData)
	}
	return &data, nil
}

func (s *InboundService) FromIds(ids []uint) ([]*model.Inbound, error) {
	db := database.GetDB()
	inbounds := []*model.Inbound{}
	err := db.Model(model.Inbound{}).Where("id in ?", ids).Scan(&inbounds).Error
	if err != nil {
		return nil, err
	}
	return inbounds, nil
}

// Save writes the database portion. ConfigService coordinates the runtime
// change and restores the previous listener if the transaction cannot commit.
func (s *InboundService) Save(tx *gorm.DB, act string, data json.RawMessage, initUserIds string, hostname string) error {
	var err error

	switch act {
	case "new", "edit":
		var inbound model.Inbound
		err = inbound.UnmarshalJSON(data)
		if err != nil {
			return err
		}
		if inbound.TlsId > 0 {
			err = tx.Model(model.Tls{}).Where("id = ?", inbound.TlsId).Find(&inbound.Tls).Error
			if err != nil {
				return err
			}
		}
		var oldTag string
		if act == "edit" {
			err = tx.Model(model.Inbound{}).Select("tag").Where("id = ?", inbound.Id).Find(&oldTag).Error
			if err != nil {
				return err
			}
		}

		err = util.FillOutJson(&inbound, hostname)
		if err != nil {
			return err
		}

		err = tx.Save(&inbound).Error
		if err != nil {
			return err
		}
		switch act {
		case "new":
			err = s.ClientService.UpdateClientsOnInboundAdd(tx, initUserIds, inbound.Id, hostname)
		case "edit":
			err = s.ClientService.UpdateLinksByInboundChange(tx, &[]model.Inbound{inbound}, hostname, oldTag)
		}
		if err != nil {
			return err
		}
	case "toggle":
		var toggle struct {
			Id     uint  `json:"id"`
			Enable *bool `json:"enable"`
		}
		if err = json.Unmarshal(data, &toggle); err != nil {
			return err
		}
		if toggle.Id == 0 || toggle.Enable == nil {
			return common.NewError("inbound id and boolean enable are required")
		}
		var inbound model.Inbound
		if err = tx.First(&inbound, toggle.Id).Error; err != nil {
			return err
		}
		if err = inbound.SetEnabled(*toggle.Enable); err != nil {
			return err
		}
		return tx.Model(&inbound).Update("options", inbound.Options).Error
	case "del":
		var tag string
		err = json.Unmarshal(data, &tag)
		if err != nil {
			return err
		}
		var id uint
		err = tx.Model(model.Inbound{}).Select("id").Where("tag = ?", tag).Scan(&id).Error
		if err != nil {
			return err
		}
		err = s.ClientService.UpdateClientsOnInboundDelete(tx, id, tag)
		if err != nil {
			return err
		}
		err = tx.Where("tag = ?", tag).Delete(model.Inbound{}).Error
		if err != nil {
			return err
		}
	default:
		return common.NewErrorf("unknown action: %s", act)
	}
	return nil
}

func (s *InboundService) UpdateOutJsons(tx *gorm.DB, inboundIds []uint, hostname string) error {
	var inbounds []model.Inbound
	err := tx.Model(model.Inbound{}).Preload("Tls").Where("id in ?", inboundIds).Find(&inbounds).Error
	if err != nil {
		return err
	}
	for _, inbound := range inbounds {
		err = util.FillOutJson(&inbound, hostname)
		if err != nil {
			return err
		}
		err = tx.Model(model.Inbound{}).Where("tag = ?", inbound.Tag).Update("out_json", inbound.OutJson).Error
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *InboundService) GetAllConfig(db *gorm.DB) ([]json.RawMessage, error) {
	var inboundsJson []json.RawMessage
	inbounds, err := s.enabledInbounds(db, nil)
	if err != nil {
		return nil, err
	}
	for _, inbound := range inbounds {
		inboundJson, err := inbound.MarshalJSON()
		if err != nil {
			return nil, err
		}
		inboundJson, err = s.addUsers(db, inboundJson, inbound.Id, inbound.Type)
		if err != nil {
			return nil, err
		}
		inboundsJson = append(inboundsJson, inboundJson)
	}
	return inboundsJson, nil
}

// All paths that start or update listeners use this selection, so a user or
// TLS change cannot bring a disabled inbound back online. Nil selects all;
// an empty, non-nil ID list selects none.
func (s *InboundService) enabledInbounds(db *gorm.DB, ids []uint) ([]*model.Inbound, error) {
	var inbounds []*model.Inbound
	query := db.Model(model.Inbound{}).Preload("Tls")
	if ids != nil {
		query = query.Where("id in ?", ids)
	}
	if err := query.Find(&inbounds).Error; err != nil {
		return nil, err
	}
	active := make([]*model.Inbound, 0, len(inbounds))
	for _, inbound := range inbounds {
		enabled, err := inbound.IsEnabled()
		if err != nil {
			return nil, err
		}
		if enabled {
			active = append(active, inbound)
		}
	}
	return active, nil
}

func (s *InboundService) hasUser(inboundType string) bool {
	switch inboundType {
	case "l2tp", "mixed", "socks", "http", "shadowsocks", "vmess", "trojan", "naive", "hysteria", "shadowtls", "tuic", "hysteria2", "vless", "anytls", "snell":
		return true
	}
	return false
}

func (s *InboundService) fetchUsers(db *gorm.DB, inboundType string, condition string, args []any, inbound map[string]interface{}) ([]json.RawMessage, error) {
	if inboundType == "shadowtls" {
		version, _ := inbound["version"].(float64)
		if int(version) < 3 {
			return nil, nil
		}
	}
	if inboundType == "shadowsocks" {
		method, _ := inbound["method"].(string)
		inboundType = util.ShadowsocksClientConfigKey(method)
	}

	var users []string

	err := db.Raw(
		fmt.Sprintf(`SELECT json_extract(clients.config, "$.%s")
		FROM clients WHERE enable = true AND %s`,
			inboundType, condition), args...).Scan(&users).Error
	if err != nil {
		return nil, err
	}
	stripVision := false
	if inboundType == "vless" {
		transportType := ""
		if tr, ok := inbound["transport"].(map[string]interface{}); ok {
			transportType, _ = tr["type"].(string)
		}
		stripVision = inbound["tls"] == nil || transportType != ""
	}

	var usersJson []json.RawMessage
	for _, user := range users {
		if stripVision {
			user = strings.ReplaceAll(user, "xtls-rprx-vision", "")
		}
		usersJson = append(usersJson, json.RawMessage(user))
	}
	return usersJson, nil
}

func (s *InboundService) addUsers(db *gorm.DB, inboundJson []byte, inboundId uint, inboundType string) ([]byte, error) {
	if !s.hasUser(inboundType) {
		return inboundJson, nil
	}

	var inbound map[string]interface{}
	err := json.Unmarshal(inboundJson, &inbound)
	if err != nil {
		return nil, err
	}

	condition := fmt.Sprintf("%d IN (SELECT json_each.value FROM json_each(clients.inbounds))", inboundId)
	inbound["users"], err = s.fetchUsers(db, inboundType, condition, nil, inbound)
	if err != nil {
		return nil, err
	}

	return json.Marshal(inbound)
}

func (s *InboundService) initUsers(db *gorm.DB, inboundJson []byte, clientIds string, inboundType string) ([]byte, error) {
	if strings.TrimSpace(clientIds) == "" {
		return inboundJson, nil
	}

	if !s.hasUser(inboundType) {
		return inboundJson, nil
	}

	var inbound map[string]interface{}
	err := json.Unmarshal(inboundJson, &inbound)
	if err != nil {
		return nil, err
	}

	// The ids arrive as a form value, so they are attacker-shaped text, not
	// numbers: splicing them into the SQL condition (id IN (%s)) let a value
	// like "0) OR (1=1" select every enabled client, the same injection
	// class fixed for /api/changes in #1131. Parse each id and pass the
	// numbers as arguments instead, so nothing in the value can change
	// the shape of the query.
	parts := strings.Split(clientIds, ",")
	ids := make([]any, 0, len(parts))
	marks := make([]string, 0, len(parts))
	for _, part := range parts {
		id, err := strconv.ParseUint(strings.TrimSpace(part), 10, 64)
		if err != nil {
			return nil, common.NewError("invalid client id: ", part)
		}
		ids = append(ids, id)
		marks = append(marks, "?")
	}

	condition := "id IN (" + strings.Join(marks, ",") + ")"
	inbound["users"], err = s.fetchUsers(db, inboundType, condition, ids, inbound)
	if err != nil {
		return nil, err
	}

	return json.Marshal(inbound)
}

func (s *InboundService) enabledClientNames(tx *gorm.DB, inboundId uint) (map[string]struct{}, error) {
	var names []string
	err := tx.Raw(
		"SELECT clients.name FROM clients, json_each(clients.inbounds) AS je WHERE je.value = ? AND clients.enable = true",
		inboundId).Scan(&names).Error
	if err != nil {
		return nil, err
	}
	keep := make(map[string]struct{}, len(names))
	for _, name := range names {
		keep[name] = struct{}{}
	}
	return keep, nil
}
