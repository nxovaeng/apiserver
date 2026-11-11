package geodata

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// GeoDataParser parses geosite.dat and geoip.dat protobuf files.
type GeoDataParser struct {
	assetsPath string
}

// NewGeoDataParser creates a new GeoDataParser.
func NewGeoDataParser(assetsPath string) *GeoDataParser {
	return &GeoDataParser{assetsPath: assetsPath}
}

// GeoDataInfo contains information about available geo data.
type GeoDataInfo struct {
	GeoSiteAvailable bool     `json:"geosite_available"`
	GeoIPAvailable   bool     `json:"geoip_available"`
	GeoSiteTags      []string `json:"geosite_tags"`
	GeoIPCodes       []string `json:"geoip_codes"`
}

// GetGeoSiteTags returns all available geosite tags.
func (p *GeoDataParser) GetGeoSiteTags() ([]string, error) {
	return p.parseGeoFile(filepath.Join(p.assetsPath, "geosite.dat"))
}

// GetGeoIPCodes returns all available geoip country codes.
func (p *GeoDataParser) GetGeoIPCodes() ([]string, error) {
	return p.parseGeoFile(filepath.Join(p.assetsPath, "geoip.dat"))
}

// GetGeoDataInfo returns information about available geo data.
func (p *GeoDataParser) GetGeoDataInfo() GeoDataInfo {
	info := GeoDataInfo{
		GeoSiteTags: []string{},
		GeoIPCodes:  []string{},
	}

	geositePath := filepath.Join(p.assetsPath, "geosite.dat")
	if _, err := os.Stat(geositePath); err == nil {
		info.GeoSiteAvailable = true
		if tags, err := p.GetGeoSiteTags(); err == nil {
			info.GeoSiteTags = tags
		}
	}

	geoipPath := filepath.Join(p.assetsPath, "geoip.dat")
	if _, err := os.Stat(geoipPath); err == nil {
		info.GeoIPAvailable = true
		if codes, err := p.GetGeoIPCodes(); err == nil {
			info.GeoIPCodes = codes
		}
	}

	return info
}

func (p *GeoDataParser) parseGeoFile(filePath string) ([]string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	reader := bytes.NewReader(data)
	codes := make([]string, 0)

	for reader.Len() > 0 {
		tag, err := readVarint(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if fieldNumber == 1 && wireType == 2 {
			entryData, err := readLengthDelimited(reader)
			if err != nil {
				return nil, err
			}
			code, err := extractCountryCode(entryData)
			if err == nil && code != "" {
				codes = append(codes, strings.ToLower(code))
			}
		} else {
			if err := skipField(reader, wireType); err != nil {
				return nil, err
			}
		}
	}

	codes = uniqueStrings(codes)
	sort.Strings(codes)
	return codes, nil
}

func extractCountryCode(data []byte) (string, error) {
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		tag, err := readVarint(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		fieldNumber := tag >> 3
		wireType := tag & 0x7

		if fieldNumber == 1 && wireType == 2 {
			codeData, err := readLengthDelimited(reader)
			if err != nil {
				return "", err
			}
			return string(codeData), nil
		}
		if err := skipField(reader, wireType); err != nil {
			return "", err
		}
	}

	return "", nil
}

func readVarint(r io.ByteReader) (uint64, error) {
	var result uint64
	var shift uint
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
		if shift >= 64 {
			return 0, errors.New("varint too long")
		}
	}
	return result, nil
}

func readLengthDelimited(r io.Reader) ([]byte, error) {
	br, ok := r.(io.ByteReader)
	if !ok {
		return nil, errors.New("reader does not support ByteReader")
	}

	length, err := readVarint(br)
	if err != nil {
		return nil, err
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	return data, nil
}

func skipField(r *bytes.Reader, wireType uint64) error {
	switch wireType {
	case 0:
		_, err := readVarint(r)
		return err
	case 1:
		_, err := r.Seek(8, io.SeekCurrent)
		return err
	case 2:
		length, err := readVarint(r)
		if err != nil {
			return err
		}
		_, err = r.Seek(int64(length), io.SeekCurrent)
		return err
	case 5:
		_, err := r.Seek(4, io.SeekCurrent)
		return err
	default:
		return errors.New("unknown wire type")
	}
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(s))
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
