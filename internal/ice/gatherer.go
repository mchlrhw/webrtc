// +build !js

package ice

import (
	"errors"
	"sync"
	"time"

	"github.com/pion/ice"
	"github.com/pion/logging"
)

// Gatherer gathers local host, server reflexive and relay
// candidates, as well as enabling the retrieval of local Interactive
// Connectivity Establishment (ICE) parameters which can be
// exchanged in signaling.
type Gatherer struct {
	lock  sync.RWMutex
	state GathererState

	validatedServers []*ice.URL

	agent *ice.Agent

	portMin           uint16
	portMax           uint16
	candidateTypes    []ice.CandidateType
	connectionTimeout *time.Duration
	keepaliveInterval *time.Duration
	loggerFactory     logging.LoggerFactory
	networkTypes      []NetworkType
}

// NewGatherer creates a new NewGatherer.
func NewGatherer(
	portMin uint16,
	portMax uint16,
	connectionTimeout *time.Duration,
	keepaliveInterval *time.Duration,
	loggerFactory logging.LoggerFactory,
	networkTypes []NetworkType,
	opts GatherOptions,
) (*Gatherer, error) {
	var validatedServers []*ice.URL
	if len(opts.ICEServers) > 0 {
		for _, server := range opts.ICEServers {
			url, err := server.urls()
			if err != nil {
				return nil, err
			}
			validatedServers = append(validatedServers, url...)
		}
	}

	candidateTypes := []ice.CandidateType{}
	if opts.ICEGatherPolicy == TransportPolicyRelay {
		candidateTypes = append(candidateTypes, ice.CandidateTypeRelay)
	}

	return &Gatherer{
		state:             GathererStateNew,
		validatedServers:  validatedServers,
		portMin:           portMin,
		portMax:           portMax,
		connectionTimeout: connectionTimeout,
		keepaliveInterval: keepaliveInterval,
		loggerFactory:     loggerFactory,
		networkTypes:      networkTypes,
		candidateTypes:    candidateTypes,
	}, nil
}

// State indicates the current state of the ICE gatherer.
func (g *Gatherer) State() GathererState {
	g.lock.RLock()
	defer g.lock.RUnlock()
	return g.state
}

// Gather ICE candidates.
func (g *Gatherer) Gather() error {
	g.lock.Lock()
	defer g.lock.Unlock()

	config := &ice.AgentConfig{
		Urls:              g.validatedServers,
		PortMin:           g.portMin,
		PortMax:           g.portMax,
		ConnectionTimeout: g.connectionTimeout,
		KeepaliveInterval: g.keepaliveInterval,
		LoggerFactory:     g.loggerFactory,
		CandidateTypes:    g.candidateTypes,
	}

	requestedNetworkTypes := g.networkTypes
	if len(requestedNetworkTypes) == 0 {
		requestedNetworkTypes = supportedNetworkTypes
	}

	for _, typ := range requestedNetworkTypes {
		config.NetworkTypes = append(config.NetworkTypes, ice.NetworkType(typ))
	}

	agent, err := ice.NewAgent(config)
	if err != nil {
		return err
	}

	g.agent = agent
	g.state = GathererStateComplete

	return nil
}

// Close prunes all local candidates, and closes the ports.
func (g *Gatherer) Close() error {
	g.lock.Lock()
	defer g.lock.Unlock()

	if g.agent == nil {
		return nil
	}

	err := g.agent.Close()
	if err != nil {
		return err
	}
	g.agent = nil

	return nil
}

// GetLocalParameters returns the ICE parameters of the Gatherer.
func (g *Gatherer) GetLocalParameters() (Parameters, error) {
	g.lock.RLock()
	defer g.lock.RUnlock()
	if g.agent == nil {
		return Parameters{}, errors.New("gatherer not started")
	}

	frag, pwd := g.agent.GetLocalUserCredentials()

	return Parameters{
		UsernameFragment: frag,
		Password:         pwd,
		ICELite:          false,
	}, nil
}

// GetLocalCandidates returns the sequence of valid local candidates associated with the Gatherer.
func (g *Gatherer) GetLocalCandidates() ([]Candidate, error) {
	g.lock.RLock()
	defer g.lock.RUnlock()

	if g.agent == nil {
		return nil, errors.New("gatherer not started")
	}

	candidates, err := g.agent.GetLocalCandidates()
	if err != nil {
		return nil, err
	}

	return newCandidatesFromICE(candidates)
}
