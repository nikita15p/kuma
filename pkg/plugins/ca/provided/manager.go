package provided

import (
	"context"
	"strings"

	"github.com/pkg/errors"

	mesh_proto "github.com/kumahq/kuma/api/mesh/v1alpha1"
	"github.com/kumahq/kuma/pkg/core/ca"
	ca_issuer "github.com/kumahq/kuma/pkg/core/ca/issuer"
	"github.com/kumahq/kuma/pkg/core/datasource"
	mesh_helper "github.com/kumahq/kuma/pkg/core/resources/apis/mesh"
	"github.com/kumahq/kuma/pkg/core/validators"
	"github.com/kumahq/kuma/pkg/plugins/ca/provided/config"
	util_proto "github.com/kumahq/kuma/pkg/util/proto"
)

type providedCaManager struct {
	dataSourceLoader datasource.Loader
}

var _ ca.Manager = &providedCaManager{}

func NewProvidedCaManager(dataSourceLoader datasource.Loader) ca.Manager {
	return &providedCaManager{
		dataSourceLoader: dataSourceLoader,
	}
}

func (p *providedCaManager) ValidateBackend(ctx context.Context, mesh string, backend *mesh_proto.CertificateAuthorityBackend) error {
	verr := validators.ValidationError{}

	cfg := &config.ProvidedCertificateAuthorityConfig{}
	if err := util_proto.ToTyped(backend.Conf, cfg); err != nil {
		verr.AddViolation("", "could not convert backend config: "+err.Error())
		return verr.OrNil()
	}

	if cfg.GetCert() == nil {
		verr.AddViolation("cert", "has to be defined")
	} else {
		verr.AddError("cert", datasource.Validate(cfg.GetCert()))
	}
	if cfg.GetKey() == nil {
		verr.AddViolation("key", "has to be defined")
	} else {
		verr.AddError("key", datasource.Validate(cfg.GetKey()))
	}

	if cfg.GetChainCert() != nil && cfg.GetRootCert() == nil{
		verr.AddViolation("root cert", "has to be defined")
	}

	if !verr.HasViolations() {
		pair, err := p.getCa(ctx, mesh, backend)
		if err != nil {
			verr.AddViolation("cert", err.Error())
			verr.AddViolation("key", err.Error())
		} else {
			verr.AddError("", validateCaCert(pair))
		}
	}
	return verr.OrNil()
}

func (p *providedCaManager) getCa(ctx context.Context, mesh string, backend *mesh_proto.CertificateAuthorityBackend) (ca.KeyPair, error) {
	cfg := &config.ProvidedCertificateAuthorityConfig{}
	if err := util_proto.ToTyped(backend.Conf, cfg); err != nil {
		return ca.KeyPair{}, errors.Wrap(err, "could not convert backend config to ProvidedCertificateAuthorityConfig")
	}
	key, err := p.dataSourceLoader.Load(ctx, mesh, cfg.Key)
	if err != nil {
		return ca.KeyPair{}, err
	}
	cert, err := p.dataSourceLoader.Load(ctx, mesh, cfg.Cert)
	if err != nil {
		return ca.KeyPair{}, err
	}
	pair := ca.KeyPair{
		CertPEM: cert,
		KeyPEM:  key,
	}
	return pair, nil
}

func (p *providedCaManager) getRootCert(ctx context.Context, mesh string, backend *mesh_proto.CertificateAuthorityBackend) (ca.Cert, error){
	cfg := &config.ProvidedCertificateAuthorityConfig{}
	if err := util_proto.ToTyped(backend.Conf, cfg); err != nil{
		return ca.Cert{}, errors.Wrap(err, "could not convert backend config to ProvidedCertificateAuthorityConfig")
	}
	if cfg.GetRootCert() != nil{
		rootCert, err := p.dataSourceLoader.Load(ctx, mesh, cfg.GetRootCert())
		if err != nil{
			return ca.Cert{}, err
		}
		return rootCert, nil
	}

	meshCa, err := p.getCa(ctx, mesh, backend)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load CA key pair")
	}

	return meshCa.CertPEM, nil
}

func (p *providedCaManager) getChainCert(ctx context.Context, mesh string, backend *mesh_proto.CertificateAuthorityBackend) (ca.Cert, error){
	cfg := &config.ProvidedCertificateAuthorityConfig{}
	if err := util_proto.ToTyped(backend.Conf, cfg); err != nil{
		return ca.Cert{}, errors.Wrap(err, "could not convert backend config to ProvidedCertificateAuthorityConfig")
	}
	if cfg.GetChainCert() != nil {
		chainCert, err := p.dataSourceLoader.Load(ctx, mesh, cfg.ChainCert)
		if err != nil {
			return ca.Cert{}, err
		}
		return chainCert, nil
	}
	return nil, nil
}

func (p *providedCaManager) Ensure(ctx context.Context, mesh string, backend *mesh_proto.CertificateAuthorityBackend) error {
	return nil // Cert and Key are created by user and pointed in the configuration which is validated first
}

func (p *providedCaManager) UsedSecrets(mesh string, backend *mesh_proto.CertificateAuthorityBackend) ([]string, error) {
	cfg := &config.ProvidedCertificateAuthorityConfig{}
	if err := util_proto.ToTyped(backend.Conf, cfg); err != nil {
		return nil, errors.Wrap(err, "could not convert backend config to ProvidedCertificateAuthorityConfig")
	}
	var secrets []string
	if cfg.GetCert().GetSecret() != "" {
		secrets = append(secrets, cfg.GetCert().GetSecret())
	}
	if cfg.GetKey().GetSecret() != "" {
		secrets = append(secrets, cfg.GetKey().GetSecret())
	}
	if cfg.GetRootCert().GetSecret() != "" {
		secrets = append(secrets, cfg.GetRootCert().GetSecret())
	}
	if cfg.GetChainCert().GetSecret() != "" {
		secrets = append(secrets, cfg.GetChainCert().GetSecret())
	}
	return secrets, nil
}

//AppendCertByte: Append x.509 rootCert in bytes to existing certificate chain (in bytes)
func AppendCertByte(pemCert []byte, rootCert []byte) []byte{
	rootCerts := []byte{}
	if len(pemCert) > 0{
		//Copy the input certificate
		rootCerts = []byte(strings.TrimSuffix(string(pemCert), "\n") + "\n")
	}
	rootCerts = append(rootCerts, rootCert...)
	return rootCerts
}

func (p *providedCaManager) GetRootCert(ctx context.Context, mesh string, backend *mesh_proto.CertificateAuthorityBackend) ([]ca.Cert,  error) {
	rootCa, err := p.getRootCert(ctx, mesh, backend)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load root cert for Mesh %q and backend %q", mesh, backend.Name)
	}
	return []ca.Cert{[]byte(rootCa)}, nil
}

func (p *providedCaManager) GenerateDataplaneCert(ctx context.Context, mesh string, backend *mesh_proto.CertificateAuthorityBackend, tags mesh_proto.MultiValueTagSet) (ca.KeyPair, ca.Cert, error) {
	meshCa, err := p.getCa(ctx, mesh, backend)
	if err != nil {
		return ca.KeyPair{}, ca.Cert{}, errors.Wrapf(err, "failed to load CA key pair for Mesh %q and backend %q", mesh, backend.Name)
	}
	rootCert , err := p.getRootCert(ctx, mesh, backend)
	if err != nil{
		return ca.KeyPair{}, ca.Cert{}, errors.Wrapf(err, "failed to load root cert for Mesh %q and backend %q", mesh, backend.Name)

	}
	chainCert, err := p.getChainCert(ctx, mesh, backend)
	if err != nil{
		return ca.KeyPair{}, ca.Cert{}, errors.Wrapf(err, "failed to load chain cert for Mesh %q and backend %q", mesh, backend.Name)
	}
	chain := AppendCertByte(chainCert, rootCert)

	var opts []ca_issuer.CertOptsFn
	if backend.GetDpCert().GetRotation().GetExpiration() != "" {
		duration, err := mesh_helper.ParseDuration(backend.GetDpCert().GetRotation().Expiration)
		if err != nil {
			return ca.KeyPair{}, ca.Cert{}, err
		}
		opts = append(opts, ca_issuer.WithExpirationTime(duration))
	}
	keyPair, err := ca_issuer.NewWorkloadCert(meshCa, mesh, tags, opts...)
	if err != nil {
		return ca.KeyPair{}, ca.Cert{}, errors.Wrapf(err, "failed to generate a Workload Identity cert for tags %q in Mesh %q using backend %q", tags.String(), mesh, backend.Name)
	}

	return *keyPair, chain, nil
}
