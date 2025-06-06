package csv

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/influxdata/toml"
	"github.com/stretchr/testify/require"

	"github.com/influxdata/telegraf/plugins/parsers/influx"
	"github.com/influxdata/telegraf/plugins/serializers"
	"github.com/influxdata/telegraf/testutil"
)

func TestInvalidTimestampFormat(t *testing.T) {
	s := Serializer{
		TimestampFormat: "garbage",
	}
	require.EqualError(t, s.Init(), `invalid timestamp format "garbage"`)
}

func TestInvalidSeparator(t *testing.T) {
	s := Serializer{
		Separator: "garbage",
	}
	require.EqualError(t, s.Init(), `invalid separator "garbage"`)

	s = Serializer{
		Separator: "\n",
	}
	require.NoError(t, s.Init())

	_, err := s.Serialize(testutil.TestMetric(42.3, "test"))
	require.EqualError(t, err, "writing data failed: csv: invalid field or comment delimiter")
}

func TestSerializeTransformationNonBatch(t *testing.T) {
	var tests = []struct {
		name     string
		filename string
	}{
		{
			name:     "basic",
			filename: "testcases/basic.conf",
		},
		{
			name:     "unix nanoseconds timestamp",
			filename: "testcases/nanoseconds.conf",
		},
		{
			name:     "header",
			filename: "testcases/header.conf",
		},
		{
			name:     "header with prefix",
			filename: "testcases/prefix.conf",
		},
		{
			name:     "header and RFC3339 timestamp",
			filename: "testcases/rfc3339.conf",
		},
		{
			name:     "header and semicolon",
			filename: "testcases/semicolon.conf",
		},
		{
			name:     "ordered without header",
			filename: "testcases/ordered.conf",
		},
		{
			name:     "ordered with header",
			filename: "testcases/ordered_with_header.conf",
		},
		{
			name:     "ordered with header and prefix",
			filename: "testcases/ordered_with_header_prefix.conf",
		},
		{
			name:     "ordered non-existing fields and tags",
			filename: "testcases/ordered_not_exist.conf",
		},
	}
	parser := &influx.Parser{}
	require.NoError(t, parser.Init())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := filepath.FromSlash(tt.filename)
			cfg, header, err := loadTestConfiguration(filename)
			require.NoError(t, err)

			// Get the input metrics
			metrics, err := testutil.ParseMetricsFrom(header, "Input:", parser)
			require.NoError(t, err)

			// Get the expectations
			expectedFn, err := testutil.ParseRawLinesFrom(header, "Output File:")
			require.NoError(t, err)
			require.Len(t, expectedFn, 1, "only a single output file is supported")
			expected, err := loadCSV(expectedFn[0])
			require.NoError(t, err)

			// Serialize
			serializer := Serializer{
				TimestampFormat: cfg.TimestampFormat,
				Separator:       cfg.Separator,
				Header:          cfg.Header,
				Prefix:          cfg.Prefix,
				Columns:         cfg.Columns,
			}
			require.NoError(t, serializer.Init())
			// expected results use LF endings
			serializer.writer.UseCRLF = false
			var actual bytes.Buffer
			for _, m := range metrics {
				buf, err := serializer.Serialize(m)
				require.NoError(t, err)
				_, err = actual.ReadFrom(bytes.NewReader(buf))
				require.NoError(t, err)
			}
			// Compare
			require.EqualValues(t, string(expected), actual.String())
		})
	}
}

func TestSerializeTransformationBatch(t *testing.T) {
	var tests = []struct {
		name     string
		filename string
	}{
		{
			name:     "basic",
			filename: "testcases/basic.conf",
		},
		{
			name:     "unix nanoseconds timestamp",
			filename: "testcases/nanoseconds.conf",
		},
		{
			name:     "header",
			filename: "testcases/header.conf",
		},
		{
			name:     "header with prefix",
			filename: "testcases/prefix.conf",
		},
		{
			name:     "header and RFC3339 timestamp",
			filename: "testcases/rfc3339.conf",
		},
		{
			name:     "header and semicolon",
			filename: "testcases/semicolon.conf",
		},
		{
			name:     "ordered without header",
			filename: "testcases/ordered.conf",
		},
		{
			name:     "ordered with header",
			filename: "testcases/ordered_with_header.conf",
		},
		{
			name:     "ordered with header and prefix",
			filename: "testcases/ordered_with_header_prefix.conf",
		},
		{
			name:     "ordered non-existing fields and tags",
			filename: "testcases/ordered_not_exist.conf",
		},
	}
	parser := &influx.Parser{}
	require.NoError(t, parser.Init())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filename := filepath.FromSlash(tt.filename)
			cfg, header, err := loadTestConfiguration(filename)
			require.NoError(t, err)

			// Get the input metrics
			metrics, err := testutil.ParseMetricsFrom(header, "Input:", parser)
			require.NoError(t, err)

			// Get the expectations
			expectedFn, err := testutil.ParseRawLinesFrom(header, "Output File:")
			require.NoError(t, err)
			require.Len(t, expectedFn, 1, "only a single output file is supported")
			expected, err := loadCSV(expectedFn[0])
			require.NoError(t, err)

			// Serialize
			serializer := Serializer{
				TimestampFormat: cfg.TimestampFormat,
				Separator:       cfg.Separator,
				Header:          cfg.Header,
				Prefix:          cfg.Prefix,
				Columns:         cfg.Columns,
			}
			require.NoError(t, serializer.Init())
			// expected results use LF endings
			serializer.writer.UseCRLF = false
			actual, err := serializer.SerializeBatch(metrics)
			require.NoError(t, err)

			// Compare
			require.EqualValues(t, string(expected), string(actual))
		})
	}
}

func loadTestConfiguration(filename string) (*Serializer, []string, error) {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, err
	}

	header := make([]string, 0)
	for _, line := range strings.Split(string(buf), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			header = append(header, line)
		}
	}
	var cfg Serializer
	err = toml.Unmarshal(buf, &cfg)
	return &cfg, header, err
}

func loadCSV(filename string) ([]byte, error) {
	return os.ReadFile(filename)
}

func BenchmarkSerialize(b *testing.B) {
	s := &Serializer{}
	require.NoError(b, s.Init())
	metrics := serializers.BenchmarkMetrics(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.Serialize(metrics[i%len(metrics)])
		require.NoError(b, err)
	}
}

func BenchmarkSerializeBatch(b *testing.B) {
	s := &Serializer{}
	require.NoError(b, s.Init())
	m := serializers.BenchmarkMetrics(b)
	metrics := m[:]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.SerializeBatch(metrics)
		require.NoError(b, err)
	}
}
