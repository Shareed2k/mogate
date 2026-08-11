//go:build !linux

package kube

import "errors"

type Redirector struct{}

func NewRedirector(config RedirectConfig) (*Redirector, error) {
	if config.TableName == "" {
		config.TableName = DefaultTableName
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	return &Redirector{}, nil
}

func (r *Redirector) Install() error {
	return errors.New("nftables redirection is supported only on linux")
}

func (r *Redirector) Cleanup() error {
	return nil
}
