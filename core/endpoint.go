package core

import (
	"errors"
	"net"
	"os"
	"slices"

	"github.com/alireza0/s-ui/logger"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

// Each method below takes the live box once via running() and then works from
// that single reference. The managers come off the box rather than from
// package-level vars, so an add cannot be applied to a manager belonging to a
// box that has since been replaced by a restart.

func (c *Core) AddInbound(config []byte) error {
	box, err := c.running()
	if err != nil {
		return err
	}
	var inbound_config option.Inbound
	if err = inbound_config.UnmarshalJSONContext(box.scope.Context(), config); err != nil {
		return err
	}

	ctx, err := box.accessContext()
	if err != nil {
		return err
	}
	err = box.inbound.Create(
		ctx,
		box.policy,
		box.logFactory.NewLogger("inbound/"+inbound_config.Type+"["+inbound_config.Tag+"]"),
		inbound_config.Tag,
		inbound_config.Type,
		inbound_config.Options)
	if err == nil {
		box.policy.mu.Lock()
		box.applied.Inbounds = append(slices.Clone(box.applied.Inbounds), inbound_config)
		box.policy.mu.Unlock()
	}
	return err
}

func (c *Core) RemoveInbound(tag string) error {
	box, err := c.running()
	if err != nil {
		return err
	}
	logger.Info("remove inbound: ", tag)
	err = box.inbound.Remove(tag)
	if err == nil || errors.Is(err, os.ErrInvalid) {
		box.policy.mu.Lock()
		box.applied.Inbounds = slices.DeleteFunc(slices.Clone(box.applied.Inbounds), func(inbound option.Inbound) bool { return inbound.Tag == tag })
		box.policy.mu.Unlock()
	}
	// Listener shutdown alone does not close already routed connections.
	// A missing listener can still have sessions left from an earlier edit.
	if box.sessionTracker != nil {
		box.sessionTracker.CloseByInbound(tag)
	}
	return err
}

func (c *Core) AddOutbound(config []byte) error {
	box, err := c.running()
	if err != nil {
		return err
	}
	var outbound_config option.Outbound
	if err = outbound_config.UnmarshalJSONContext(box.scope.Context(), config); err != nil {
		return err
	}

	generation := box.policy.acquire()
	if generation == nil {
		return net.ErrClosed
	}
	defer generation.release()
	outboundCtx := adapter.WithContext(generation.runtime.ctx, &adapter.InboundContext{
		Outbound: outbound_config.Tag,
	})

	err = generation.runtime.outbound.Create(
		outboundCtx,
		generation.runtime.router,
		box.logFactory.NewLogger("outbound/"+outbound_config.Type+"["+outbound_config.Tag+"]"),
		outbound_config.Tag,
		outbound_config.Type,
		outbound_config.Options)
	if err == nil {
		box.policy.mu.Lock()
		box.applied.Outbounds = append(slices.Clone(box.applied.Outbounds), outbound_config)
		box.policy.mu.Unlock()
	}
	return err
}

func (c *Core) RemoveOutbound(tag string) error {
	box, err := c.running()
	if err != nil {
		return err
	}
	logger.Info("remove outbound: ", tag)
	generation := box.policy.acquire()
	if generation == nil {
		return net.ErrClosed
	}
	defer generation.release()
	err = generation.runtime.outbound.Remove(tag)
	if err == nil {
		box.policy.mu.Lock()
		box.applied.Outbounds = slices.DeleteFunc(slices.Clone(box.applied.Outbounds), func(outbound option.Outbound) bool { return outbound.Tag == tag })
		box.policy.mu.Unlock()
	}
	return err
}

func (c *Core) AddEndpoint(config []byte) error {
	box, err := c.running()
	if err != nil {
		return err
	}
	var endpoint_config option.Endpoint
	if err = endpoint_config.UnmarshalJSONContext(box.scope.Context(), config); err != nil {
		return err
	}

	ctx, err := box.accessContext()
	if err != nil {
		return err
	}
	return box.endpoint.Create(
		ctx,
		box.policy,
		box.logFactory.NewLogger("endpoint/"+endpoint_config.Type+"["+endpoint_config.Tag+"]"),
		endpoint_config.Tag,
		endpoint_config.Type,
		endpoint_config.Options)
}

func (c *Core) RemoveEndpoint(tag string) error {
	box, err := c.running()
	if err != nil {
		return err
	}
	logger.Info("remove endpoint: ", tag)
	return box.endpoint.Remove(tag)
}

func (c *Core) AddService(config []byte) error {
	box, err := c.running()
	if err != nil {
		return err
	}
	var srv_config option.Service
	if err = srv_config.UnmarshalJSONContext(box.scope.Context(), config); err != nil {
		return err
	}

	ctx, err := box.accessContext()
	if err != nil {
		return err
	}
	return box.service.Create(
		ctx,
		box.logFactory.NewLogger("service/"+srv_config.Type+"["+srv_config.Tag+"]"),
		srv_config.Tag,
		srv_config.Type,
		srv_config.Options)
}

func (c *Core) RemoveService(tag string) error {
	box, err := c.running()
	if err != nil {
		return err
	}
	logger.Info("remove service: ", tag)
	return box.service.Remove(tag)
}
