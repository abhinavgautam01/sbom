package sbom

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

const cdxXMLNamespacePrefix = "http://cyclonedx.org/schema/bom/"

type cdxDependencyXML struct {
	Ref       string             `xml:"ref,attr"`
	DependsOn []cdxDependencyXML `xml:"dependency"`
}

// The dependency targets are ref attributes, unlike the JSON string array.
type cdxInputXML struct {
	XMLName      xml.Name           `xml:"bom"`
	Version      int                `xml:"version,attr"`
	SerialNumber string             `xml:"serialNumber,attr"`
	Metadata     *cdxMetadataXML    `xml:"metadata"`
	Components   *cdxComponentsXML  `xml:"components"`
	Dependencies []cdxDependencyXML `xml:"dependencies>dependency"`
}

func detectCycloneDXXML(data []byte) detectedFormat {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return detectedFormat{}
		}
		if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local == "bom" && (start.Name.Space == "" || cycloneDXXMLVersion(start.Name.Space) != "") {
				return detectedFormat{typ: TypeCycloneDX, xml: true}
			}
			return detectedFormat{}
		}
	}
}

func cycloneDXXMLVersion(namespace string) string {
	version, ok := strings.CutPrefix(namespace, cdxXMLNamespacePrefix)
	if !ok {
		return ""
	}
	return version
}

func parseCycloneDXXML(data []byte) (*SBOM, error) {
	var input cdxInputXML
	decoder := xml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&input); err != nil {
		return nil, wrapErr("cyclonedx xml", err)
	}
	if err := checkXMLEnd(decoder); err != nil {
		return nil, wrapErr("cyclonedx xml", err)
	}
	bom := cdxBOM{
		BOMFormat: cdxBOMFormat, SpecVersion: cycloneDXXMLVersion(input.XMLName.Space),
		BOMVersion: input.Version, SerialNumber: input.SerialNumber,
		Components: componentsFromXML(input.Components),
	}
	if input.Metadata != nil {
		m := input.Metadata
		bom.Metadata = &cdxMetadata{Timestamp: m.Timestamp, Supplier: m.Supplier}
		if m.Component != nil {
			component := componentFromXML(m.Component)
			bom.Metadata.Component = &component
		}
	}
	for _, dependency := range input.Dependencies {
		d := cdxDependency{Ref: dependency.Ref}
		for _, target := range dependency.DependsOn {
			d.DependsOn = append(d.DependsOn, target.Ref)
		}
		bom.Dependencies = append(bom.Dependencies, d)
	}
	return normalizeCycloneDX(&bom), nil
}

func checkXMLEnd(decoder *xml.Decoder) error {
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case xml.Comment, xml.ProcInst:
			continue
		case xml.CharData:
			if len(bytes.TrimSpace(token)) == 0 {
				continue
			}
		}
		return fmt.Errorf("unexpected content after bom element")
	}
}

func componentsFromXML(input *cdxComponentsXML) []cdxComponent {
	if input == nil || len(input.Components) == 0 {
		return nil
	}
	components := make([]cdxComponent, len(input.Components))
	for i := range input.Components {
		components[i] = componentFromXML(&input.Components[i])
	}
	return components
}

func componentFromXML(input *cdxComponentXML) cdxComponent {
	c := cdxComponent{
		BOMRef: input.BOMRef, Type: input.Type, Name: input.Name, Version: input.Version,
		Description: input.Description, Copyright: input.Copyright, Author: input.Author,
		PURL: input.PURL, Supplier: input.Supplier, Components: componentsFromXML(input.Components),
	}
	if input.Hashes != nil {
		c.Hashes = input.Hashes.Hashes
	}
	if input.ExternalReferences != nil {
		c.ExternalReferences = input.ExternalReferences.References
	}
	if input.Properties != nil {
		c.Properties = input.Properties.Properties
	}
	if input.Licenses != nil {
		for _, license := range input.Licenses.Licenses {
			c.Licenses = append(c.Licenses, cdxLicense{License: &cdxLicenseID{ID: license.ID, Name: license.Name}})
		}
		if input.Licenses.Expression != "" {
			c.Licenses = append(c.Licenses, cdxLicense{Expression: input.Licenses.Expression})
		}
	}
	return c
}
