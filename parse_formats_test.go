package sbom

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestParseCycloneDXXML(t *testing.T) {
	data := readFixture(t, "cyclonedx/packages.cdx.xml")
	if got := Detect(data); got != TypeCycloneDX {
		t.Fatalf("Detect = %q", got)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Type != TypeCycloneDX || doc.SpecVersion != "1.5" || doc.Document.Name != "example" || doc.Document.Supplier != "Acme" || doc.Document.Created != "2026-01-01T00:00:00Z" {
		t.Fatalf("document = %+v", doc.Document)
	}
	if len(doc.Packages) != 3 {
		t.Fatalf("packages = %+v", doc.Packages)
	}
	want := Package{
		ID: "alpha", Name: "shared", Version: "1.0.0", Type: "LIBRARY",
		Description: "Shared & useful", Copyright: "Copyright Acme",
		Supplier: "Acme", SupplierType: SupplierOrganization,
		Originator: "Jane Doe", OriginatorType: SupplierPerson,
		LicenseConcluded: "MIT", LicenseDeclared: "MIT",
		Checksums: []Checksum{{Algorithm: "SHA256", Value: "abc"}},
		ExternalRefs: []ExternalRef{
			{Category: "PACKAGE_MANAGER", Type: "purl", Locator: "pkg:npm/%40alpha/shared@1.0.0"},
			{Category: "website", Type: "website", Locator: "https://example.com"},
		},
		Properties: []Property{{Name: "scope", Value: "runtime"}},
	}
	if !reflect.DeepEqual(doc.Packages[0], want) {
		t.Errorf("package = %#v, want %#v", doc.Packages[0], want)
	}
	if doc.Packages[2].PURL() != "pkg:npm/%40beta/shared@1.0.0" || doc.Packages[2].LicenseDeclared != "MIT OR Apache-2.0" {
		t.Errorf("second scoped package = %+v", doc.Packages[2])
	}
	wantRelationships := []Relationship{
		{SourceID: "alpha", TargetID: "child", Type: RelDependsOn},
		{SourceID: "alpha", TargetID: "beta", Type: RelDependsOn},
	}
	if !reflect.DeepEqual(doc.Relationships, wantRelationships) {
		t.Errorf("relationships = %+v", doc.Relationships)
	}
}

func TestParseSPDXTagValue(t *testing.T) {
	data := readFixture(t, "spdx/packages.spdx")
	if got := Detect(data); got != TypeSPDX {
		t.Fatalf("Detect = %q", got)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	wantDocument := Document{
		Name: "example", ID: "SPDXRef-DOCUMENT", Type: TypeSPDX, SpecVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0", Namespace: "https://example.com/sbom/example",
		Created: "2026-01-01T00:00:00Z", Supplier: "Acme",
		Creators: []Creator{{Type: "Tool", Name: "example-generator"}},
	}
	if !reflect.DeepEqual(doc.Document, wantDocument) {
		t.Errorf("document = %#v", doc.Document)
	}
	if len(doc.Packages) != 2 {
		t.Fatalf("packages = %+v", doc.Packages)
	}
	want := Package{
		ID: "SPDXRef-alpha", Name: "shared", Version: "1.0.0", Type: "LIBRARY",
		Filename: "alpha.tgz", DownloadLocation: "https://example.com/alpha.tgz", Homepage: "https://example.com",
		Description: "Shared & useful\n# This is part of the description.\n  Indented text.", Copyright: "Copyright Acme",
		Supplier: "Acme", SupplierType: SupplierOrganization, Originator: "Jane Doe", OriginatorType: SupplierPerson,
		LicenseDeclared: "MIT", LicenseConcluded: "MIT",
		Checksums: []Checksum{{Algorithm: "SHA256", Value: "abc"}},
		ExternalRefs: []ExternalRef{
			{Category: "PACKAGE-MANAGER", Type: "purl", Locator: "pkg:npm/%40alpha/shared@1.0.0"},
			{Category: "PACKAGE-MANAGER", Type: "purl", Locator: "pkg:generic/alpha@1.0.0"},
			{Category: "SECURITY", Type: "cpe23Type", Locator: "cpe:2.3:a:acme:shared:1.0.0"},
		},
	}
	if !reflect.DeepEqual(doc.Packages[0], want) {
		t.Errorf("package = %#v, want %#v", doc.Packages[0], want)
	}
	if doc.Packages[1].PURL() != "pkg:npm/%40beta/shared@1.0.0" {
		t.Errorf("second scoped package = %+v", doc.Packages[1])
	}
	wantRelationships := []Relationship{
		{SourceID: "SPDXRef-DOCUMENT", Source: "example", TargetID: "SPDXRef-alpha", Target: "shared", Type: RelDescribes},
		{SourceID: "SPDXRef-alpha", Source: "shared", TargetID: "SPDXRef-beta", Target: "shared", Type: RelDependsOn},
	}
	if !reflect.DeepEqual(doc.Relationships, wantRelationships) {
		t.Errorf("relationships = %+v", doc.Relationships)
	}
}

func TestParsePreservesPackageIdentities(t *testing.T) {
	for name, data := range map[string]string{
		"cyclonedx without marker": `{"components":[
			{"name":"shared","version":"1","purl":"pkg:npm/%40alpha/shared@1"},
			{"name":"shared","version":"1","purl":"pkg:npm/%40beta/shared@1"}]}`,
		"XML without namespace": `<bom><components><component><name>shared</name><version>1</version><purl>pkg:npm/%40alpha/shared@1</purl></component><component><name>shared</name><version>1</version><purl>pkg:npm/%40beta/shared@1</purl></component></components></bom>`,
		"cyclonedx": `{"bomFormat":"CycloneDX","components":[
			{"name":"shared","version":"1","purl":"pkg:npm/%40alpha/shared@1"},
			{"name":"shared","version":"1","purl":"pkg:npm/%40beta/shared@1"}]}`,
		"spdx": `{"spdxVersion":"SPDX-2.3","packages":[
			{"name":"shared","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/%40alpha/shared@1"}]},
			{"name":"shared","versionInfo":"1","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/%40beta/shared@1"}]}]}`,
		"different IDs": `{"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"shared","version":"1"},{"bom-ref":"b","name":"shared","version":"1"}],"dependencies":[{"ref":"a","dependsOn":["b"]}]}`,
		"multiple PURLs": `{"spdxVersion":"SPDX-2.3","packages":[
			{"name":"shared","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:generic/shared"},{"referenceType":"purl","referenceLocator":"pkg:npm/%40alpha/shared"}]},
			{"name":"shared","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:generic/shared"},{"referenceType":"purl","referenceLocator":"pkg:npm/%40beta/shared"}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			doc, err := Parse([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Packages) != 2 {
				t.Fatalf("packages = %+v; want both identities", doc.Packages)
			}
		})
	}
}

func TestParseAdditionalFormatErrors(t *testing.T) {
	for name, data := range map[string]string{
		"truncated XML":        `<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><components>`,
		"extra XML root":       `<bom xmlns="http://cyclonedx.org/schema/bom/1.5"/><bom/>`,
		"trailing XML text":    `<bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>oops`,
		"unclosed text":        "SPDXVersion: SPDX-2.3\nPackageName: a\nPackageDescription: <text>unfinished",
		"text suffix":          "SPDXVersion: SPDX-2.3\nPackageName: a\nPackageDescription: <text>text</text>oops",
		"missing colon":        "SPDXVersion: SPDX-2.3\nPackageName a",
		"invalid reference":    "SPDXVersion: SPDX-2.3\nPackageName: a\nExternalRef: PACKAGE-MANAGER purl",
		"invalid relationship": "SPDXVersion: SPDX-2.3\nRelationship: SPDXRef-a DEPENDS_ON",
		"invalid checksum":     "SPDXVersion: SPDX-2.3\nPackageName: a\nPackageChecksum: SHA256",
	} {
		t.Run(name, func(t *testing.T) {
			if doc, err := Parse([]byte(data)); err == nil {
				t.Fatalf("Parse accepted invalid input: %+v", doc)
			}
		})
	}
	for _, data := range []string{`<document/>`, `<bom xmlns="https://example.com/bom/1.5"/>`, "PackageName: a", "DocumentComment: <text>\nSPDXVersion: SPDX-2.3\n</text>"} {
		if got := Detect([]byte(data)); got != TypeUnknown {
			t.Errorf("Detect(%q) = %q", data, got)
		}
		if _, err := Parse([]byte(data)); !errors.Is(err, ErrUnrecognized) {
			t.Errorf("Parse(%q) = %v", data, err)
		}
	}
}

func TestParseSPDXHeaderOrder(t *testing.T) {
	data := []byte("DataLicense: CC0-1.0\nDocumentComment: <text>Generated inventory</text>\nSPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT\nPackageName: shared\nSPDXID: SPDXRef-shared\nExternalRef: PACKAGE-MANAGER purl pkg:generic/shared@1")
	if got := Detect(data); got != TypeSPDX {
		t.Fatalf("Detect = %q", got)
	}
	doc, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Document.DataLicense != "CC0-1.0" || len(doc.Packages) != 1 || doc.Packages[0].PURL() != "pkg:generic/shared@1" {
		t.Fatalf("document = %+v", doc)
	}
}

func TestParseAdditionalFormatWhitespace(t *testing.T) {
	for _, fixture := range []string{"cyclonedx/packages.cdx.xml", "spdx/packages.spdx"} {
		data := readFixture(t, fixture)
		want, err := Parse(data)
		if err != nil {
			t.Fatal(err)
		}
		data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
		data = append([]byte("\xef\xbb\xbf \r\n"), data...)
		got, err := Parse(data)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("Parse %s with BOM and CRLF = %+v, %v", fixture, got, err)
		}
	}
}

func TestParseSPDXLongText(t *testing.T) {
	text := strings.Repeat("x", 100_000)
	doc, err := Parse([]byte("SPDXVersion: SPDX-2.3\nPackageName: a\nPackageDescription: <text>" + text + "</text>"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Packages) != 1 || doc.Packages[0].Description != text {
		t.Fatal("long description was not preserved")
	}
}

func TestParseSPDXTextWhitespace(t *testing.T) {
	text := "  first line  \n\n second line \n"
	doc, err := Parse([]byte("SPDXVersion: SPDX-2.3\nPackageName: a\nPackageDescription: <text>" + text + "</text>"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Packages) != 1 || doc.Packages[0].Description != text {
		t.Fatalf("multiline whitespace was not preserved: %+v", doc.Packages)
	}
}

func TestAddPackagePURLSet(t *testing.T) {
	s := New(TypeSPDX)
	alpha := ExternalRef{Type: "purl", Locator: "pkg:npm/%40alpha/shared@1"}
	generic := ExternalRef{Type: "purl", Locator: "pkg:generic/shared@1"}
	s.AddPackage(Package{Name: "shared", Version: "1", ExternalRefs: []ExternalRef{alpha, generic}})
	s.AddPackage(Package{Name: "shared", Version: "1", Description: "updated", ExternalRefs: []ExternalRef{generic, alpha, alpha}})
	if len(s.Packages) != 1 || s.Packages[0].Description != "updated" {
		t.Fatalf("reordered PURLs should replace the same identity: %+v", s.Packages)
	}
	s.AddPackage(Package{Name: "shared", Version: "1"})
	if len(s.Packages) != 2 {
		t.Fatalf("an entry without PURLs must not replace a declared identity: %+v", s.Packages)
	}
}

func TestParseEmptyAdditionalFormats(t *testing.T) {
	for _, data := range []string{`<bom/>`, `<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5"/>`, "SPDXVersion: SPDX-2.3\nSPDXID: SPDXRef-DOCUMENT"} {
		doc, err := Parse([]byte(data))
		if err != nil {
			t.Fatal(err)
		}
		if doc.Packages != nil || doc.Relationships != nil {
			t.Errorf("empty document = %+v", doc)
		}
	}
}

func TestParsePrefixedCycloneDXXML(t *testing.T) {
	data := `<?xml version="1.0"?><!-- inventory --><cdx:bom xmlns:cdx="http://cyclonedx.org/schema/bom/1.5"><cdx:components><cdx:component type="library"><cdx:name>shared</cdx:name><cdx:purl>pkg:generic/shared@1</cdx:purl><cdx:licenses><cdx:license><cdx:name>Custom license</cdx:name></cdx:license></cdx:licenses></cdx:component></cdx:components></cdx:bom><!-- end -->`
	doc, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if doc.SpecVersion != "1.5" || len(doc.Packages) != 1 || doc.Packages[0].PURL() != "pkg:generic/shared@1" || doc.Packages[0].LicenseDeclared != "Custom license" {
		t.Fatalf("prefixed document = %+v", doc)
	}
}

func TestParseCycloneDXXMLManufacture(t *testing.T) {
	data := `<bom xmlns="http://cyclonedx.org/schema/bom/1.5"><metadata><manufacture><name>Acme</name></manufacture></metadata></bom>`
	doc, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Document.Supplier != "Acme" {
		t.Fatalf("supplier = %q, want manufacture name", doc.Document.Supplier)
	}
}
