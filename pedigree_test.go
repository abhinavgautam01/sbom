package sbom

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const pedigreeJSON = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "bom-ref": "pkg:npm/%40plotly/d3@3.8.2",
      "type": "library",
      "name": "@plotly/d3",
      "version": "3.8.2",
      "purl": "pkg:npm/%40plotly/d3@3.8.2",
      "pedigree": {
        "ancestors": [
          {"type": "library", "name": "d3/d3", "purl": "pkg:github/d3/d3"},
          {"type": "library", "name": "d3", "version": "3.5.17", "purl": "pkg:npm/d3@3.5.17"}
        ]
      },
      "components": [
        {"bom-ref": "child", "type": "library", "name": "child", "version": "1.0.0"}
      ]
    },
    {"bom-ref": "pkg:npm/lodash@4.17.21", "type": "library", "name": "lodash", "version": "4.17.21"}
  ],
  "dependencies": [
    {"ref": "pkg:npm/%40plotly/d3@3.8.2", "dependsOn": ["pkg:npm/lodash@4.17.21"]}
  ]
}`

const pedigreeXML = `<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">
  <components>
    <component type="library" bom-ref="pkg:npm/%40plotly/d3@3.8.2">
      <name>@plotly/d3</name>
      <version>3.8.2</version>
      <purl>pkg:npm/%40plotly/d3@3.8.2</purl>
      <pedigree>
        <ancestors>
          <component type="library">
            <name>d3/d3</name>
            <purl>pkg:github/d3/d3</purl>
          </component>
          <component type="library">
            <name>d3</name>
            <version>3.5.17</version>
            <purl>pkg:npm/d3@3.5.17</purl>
          </component>
        </ancestors>
      </pedigree>
      <components>
        <component type="library" bom-ref="child">
          <name>child</name>
          <version>1.0.0</version>
        </component>
      </components>
    </component>
    <component type="library" bom-ref="pkg:npm/lodash@4.17.21">
      <name>lodash</name>
      <version>4.17.21</version>
    </component>
  </components>
  <dependencies>
    <dependency ref="pkg:npm/%40plotly/d3@3.8.2">
      <dependency ref="pkg:npm/lodash@4.17.21"/>
    </dependency>
  </dependencies>
</bom>`

var wantPedigreeAncestors = []Ancestor{
	{Type: "LIBRARY", Name: "d3/d3", PURL: "pkg:github/d3/d3"},
	{Type: "LIBRARY", Name: "d3", Version: "3.5.17", PURL: "pkg:npm/d3@3.5.17"},
}

func TestParseCycloneDXPedigreeAncestors(t *testing.T) {
	for name, input := range map[string]string{"json": pedigreeJSON, "xml": pedigreeXML} {
		t.Run(name, func(t *testing.T) {
			doc, err := Parse([]byte(input))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			assertPedigreeDocument(t, doc)
		})
	}
}

func TestCycloneDXPedigreeAncestorsRoundTrip(t *testing.T) {
	for name, input := range map[string]string{"json": pedigreeJSON, "xml": pedigreeXML} {
		for _, format := range []Format{FormatCycloneDXJSON, FormatCycloneDXXML} {
			t.Run(name+"-to-"+formatName(format), func(t *testing.T) {
				doc, err := Parse([]byte(input))
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				var buf bytes.Buffer
				if err := Encode(&buf, doc, format); err != nil {
					t.Fatalf("Encode: %v", err)
				}
				out, err := Parse(buf.Bytes())
				if err != nil {
					t.Fatalf("Parse encoded: %v\n%s", err, buf.String())
				}
				d3 := findPackage(t, out, "@plotly/d3")
				if !reflect.DeepEqual(d3.Ancestors, wantPedigreeAncestors) {
					t.Errorf("Ancestors = %#v, want %#v\n%s", d3.Ancestors, wantPedigreeAncestors, buf.String())
				}
				for _, p := range out.Packages {
					if p.Name == "d3/d3" || p.Name == "d3" {
						t.Errorf("ancestor %q became a package:\n%s", p.Name, buf.String())
					}
				}
			})
		}
	}
}

func TestEncodeCycloneDXJSONUnversionedAncestor(t *testing.T) {
	s := New(TypeCycloneDX)
	s.AddPackage(Package{
		Name: "@plotly/d3", Version: "3.8.2",
		ExternalRefs: []ExternalRef{{Type: "purl", Locator: "pkg:npm/%40plotly/d3@3.8.2"}},
		Ancestors:    []Ancestor{{Name: "d3/d3", PURL: "pkg:github/d3/d3"}},
	})
	var buf bytes.Buffer
	if err := Encode(&buf, s, FormatCycloneDXJSON); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var bom struct {
		Components []struct {
			Pedigree json.RawMessage `json:"pedigree"`
		} `json:"components"`
		Dependencies []json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(bom.Components) != 1 || len(bom.Dependencies) != 0 {
		t.Fatalf("components = %d, dependencies = %d:\n%s", len(bom.Components), len(bom.Dependencies), buf.String())
	}
	var got, want any
	if err := json.Unmarshal(bom.Components[0].Pedigree, &got); err != nil {
		t.Fatalf("unmarshal pedigree: %v\n%s", err, buf.String())
	}
	// No version or bom-ref: only the identity the caller established.
	if err := json.Unmarshal([]byte(`{"ancestors":[{"type":"library","name":"d3/d3","purl":"pkg:github/d3/d3"}]}`), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pedigree = %s, want %v", bom.Components[0].Pedigree, want)
	}
}

func TestEncodeCycloneDXXMLPedigreeOrder(t *testing.T) {
	s := sampleSBOM()
	s.Packages[0].Ancestors = []Ancestor{{Name: "lodash/lodash", PURL: "pkg:github/lodash/lodash"}}
	var buf bytes.Buffer
	if err := Encode(&buf, s, FormatCycloneDXXML); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out := buf.String()
	// The CycloneDX XSD places pedigree after purl and before properties.
	purl := strings.Index(out, "<purl>pkg:npm/lodash@4.17.21</purl>")
	pedigree := strings.Index(out, "<pedigree>")
	properties := strings.Index(out, "<properties>")
	if purl < 0 || pedigree < 0 || properties < 0 || purl >= pedigree || pedigree >= properties {
		t.Errorf("purl at %d, pedigree at %d, properties at %d:\n%s", purl, pedigree, properties, out)
	}
	if !strings.Contains(out, `<component type="library">`) {
		t.Errorf("ancestor missing default type or carries a bom-ref:\n%s", out)
	}
}

func TestEncodeWithoutAncestorsOmitsPedigree(t *testing.T) {
	for _, format := range []Format{FormatCycloneDXJSON, FormatCycloneDXXML} {
		t.Run(formatName(format), func(t *testing.T) {
			var buf bytes.Buffer
			if err := Encode(&buf, sampleSBOM(), format); err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if strings.Contains(buf.String(), "pedigree") || strings.Contains(buf.String(), "ancestors") {
				t.Errorf("unexpected pedigree in:\n%s", buf.String())
			}
		})
	}
	doc, err := Parse([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"x"}]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Packages[0].Ancestors != nil {
		t.Errorf("Ancestors = %#v, want nil", doc.Packages[0].Ancestors)
	}
}

func TestEncodeSPDXIgnoresAncestors(t *testing.T) {
	s := sampleSBOM()
	s.Packages[0].Ancestors = []Ancestor{{Name: "lodash/lodash", PURL: "pkg:github/lodash/lodash"}}
	var buf bytes.Buffer
	if err := Encode(&buf, s, FormatSPDXJSON); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := Parse(buf.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// The synthetic root plus the two installed packages.
	if len(out.Packages) != len(s.Packages)+1 || strings.Contains(buf.String(), "lodash/lodash") {
		t.Errorf("ancestor leaked into SPDX output:\n%s", buf.String())
	}
}

func assertPedigreeDocument(t *testing.T, doc *SBOM) {
	t.Helper()
	if len(doc.Packages) != 3 {
		t.Fatalf("Packages = %d, want 3 (ancestors must not become packages): %#v", len(doc.Packages), doc.Packages)
	}
	d3 := findPackage(t, doc, "@plotly/d3")
	if !reflect.DeepEqual(d3.Ancestors, wantPedigreeAncestors) {
		t.Errorf("Ancestors = %#v, want %#v", d3.Ancestors, wantPedigreeAncestors)
	}
	if lodash := findPackage(t, doc, "lodash"); lodash.Ancestors != nil {
		t.Errorf("lodash Ancestors = %#v, want nil", lodash.Ancestors)
	}
	want := []Relationship{
		{SourceID: "pkg:npm/%40plotly/d3@3.8.2", TargetID: "child", Type: RelDependsOn},
		{SourceID: "pkg:npm/%40plotly/d3@3.8.2", TargetID: "pkg:npm/lodash@4.17.21", Type: RelDependsOn},
	}
	if !reflect.DeepEqual(doc.Relationships, want) {
		t.Errorf("Relationships = %#v, want %#v", doc.Relationships, want)
	}
}

func findPackage(t *testing.T, doc *SBOM, name string) *Package {
	t.Helper()
	for i := range doc.Packages {
		if doc.Packages[i].Name == name {
			return &doc.Packages[i]
		}
	}
	t.Fatalf("package %q not found in %#v", name, doc.Packages)
	return nil
}
