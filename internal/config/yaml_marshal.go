package config

import "gopkg.in/yaml.v3"

func marshalYAML(v any) ([]byte, error) {
	return yaml.Marshal(v)
}
