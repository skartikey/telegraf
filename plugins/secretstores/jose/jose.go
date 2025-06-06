//go:generate ../../../tools/readme_config_includer/generator
package jose

import (
	_ "embed"
	"errors"
	"fmt"

	"github.com/99designs/keyring"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/plugins/secretstores"
)

//go:embed sample.conf
var sampleConfig string

type Jose struct {
	ID       string        `toml:"id"`
	Path     string        `toml:"path"`
	Password config.Secret `toml:"password"`

	ring keyring.Keyring
}

func (*Jose) SampleConfig() string {
	return sampleConfig
}

func (j *Jose) Init() error {
	defer j.Password.Destroy()

	if j.ID == "" {
		return errors.New("id missing")
	}

	if j.Path == "" {
		return errors.New("path missing")
	}

	// Create the prompt-function in case we need it
	promptFunc := keyring.TerminalPrompt
	if !j.Password.Empty() {
		passwd, err := j.Password.Get()
		if err != nil {
			return fmt.Errorf("getting password failed: %w", err)
		}
		defer passwd.Destroy()
		promptFunc = keyring.FixedStringPrompt(passwd.String())
	} else if !config.Password.Empty() {
		passwd, err := config.Password.Get()
		if err != nil {
			return fmt.Errorf("getting global password failed: %w", err)
		}
		defer passwd.Destroy()
		promptFunc = keyring.FixedStringPrompt(passwd.String())
	}

	// Setup the actual keyring
	cfg := keyring.Config{
		AllowedBackends:  []keyring.BackendType{keyring.FileBackend},
		FileDir:          j.Path,
		FilePasswordFunc: promptFunc,
	}
	kr, err := keyring.Open(cfg)
	if err != nil {
		return fmt.Errorf("opening keyring failed: %w", err)
	}
	j.ring = kr

	return nil
}

func (j *Jose) Get(key string) ([]byte, error) {
	item, err := j.ring.Get(key)
	if err != nil {
		return nil, err
	}

	return item.Data, nil
}

func (j *Jose) Set(key, value string) error {
	item := keyring.Item{
		Key:  key,
		Data: []byte(value),
	}

	return j.ring.Set(item)
}

func (j *Jose) List() ([]string, error) {
	return j.ring.Keys()
}

func (j *Jose) GetResolver(key string) (telegraf.ResolveFunc, error) {
	resolver := func() ([]byte, bool, error) {
		s, err := j.Get(key)
		return s, false, err
	}
	return resolver, nil
}

func init() {
	secretstores.Add("jose", func(id string) telegraf.SecretStore {
		return &Jose{ID: id}
	})
}
