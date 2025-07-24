// This file was generated from JSON Schema using quicktype, do not modify it directly.
package threatdragon

import (
	"bytes"
	"encoding/json"
	"errors"
)

type Project struct {
	Version string  `json:"version"`
	Summary Summary `json:"summary"`
	Detail  Detail  `json:"detail"`
}

type Detail struct {
	Contributors []Contributor `json:"contributors"`
	Diagrams     []Diagram     `json:"diagrams"`
	DiagramTop   int64         `json:"diagramTop"`
	Reviewer     string        `json:"reviewer"`
	ThreatTop    int64         `json:"threatTop"`
}

type Contributor struct {
	Name string `json:"name"`
}

type Diagram struct {
	ID          int64   `json:"id"`
	Title       string  `json:"title"`
	DiagramType string  `json:"diagramType"`
	Placeholder *string `json:"placeholder,omitempty"`
	Thumbnail   string  `json:"thumbnail"`
	Version     string  `json:"version"`
	Cells       []Cell  `json:"cells"`
	Description *string `json:"description,omitempty"`
}

type Cell struct {
	Position  *VertexClass   `json:"position,omitempty"`
	Size      *Size          `json:"size,omitempty"`
	Attrs     *CellAttrs     `json:"attrs,omitempty"`
	Visible   *bool          `json:"visible,omitempty"`
	Shape     string         `json:"shape"`
	ZIndex    int64          `json:"zIndex"`
	ID        string         `json:"id"`
	Data      Data           `json:"data"`
	Ports     *Ports         `json:"ports,omitempty"`
	Width     *float64       `json:"width,omitempty"`
	Height    *float64       `json:"height,omitempty"`
	Connector *string        `json:"connector,omitempty"`
	Labels    []LabelElement `json:"labels,omitempty"`
	Source    *Source        `json:"source,omitempty"`
	Target    *Source        `json:"target,omitempty"`
	Vertices  *[]VertexClass `json:"vertices,omitempty"`
	Tools     *Tools         `json:"tools,omitempty"`
}

type CellAttrs struct {
	Text       *TextClass `json:"text,omitempty"`
	Label      *TextClass `json:"label,omitempty"`
	Body       *Body      `json:"body,omitempty"`
	Line       *Line      `json:"line,omitempty"`
	TopLine    *Body      `json:"topLine,omitempty"`
	BottomLine *Body      `json:"bottomLine,omitempty"`
}

type Body struct {
	Stroke          *string          `json:"stroke,omitempty"`
	StrokeWidth     float64          `json:"strokeWidth"`
	StrokeDasharray Nullable[string] `json:"strokeDasharray,omitzero"`
}

type TextClass struct {
	Text string `json:"text"`
}

type Line struct {
	Stroke          *string          `json:"stroke,omitempty"`
	TargetMarker    *Marker          `json:"targetMarker"`
	SourceMarker    *Marker          `json:"sourceMarker,omitempty"`
	StrokeDasharray Nullable[string] `json:"strokeDasharray,omitzero"`
	StrokeWidth     *float64         `json:"strokeWidth,omitempty"`
}

type Data struct {
	Type                   string           `json:"type"`
	Name                   *string          `json:"name,omitempty"`
	HasOpenThreats         bool             `json:"hasOpenThreats"`
	Description            *string          `json:"description,omitempty"`
	IsTrustBoundary        *bool            `json:"isTrustBoundary,omitempty"`
	OutOfScope             *bool            `json:"outOfScope,omitempty"`
	ReasonOutOfScope       *string          `json:"reasonOutOfScope,omitempty"`
	ProvidesAuthentication *bool            `json:"providesAuthentication,omitempty"`
	Threats                *[]Threat        `json:"threats,omitempty"`
	HandlesCardPayment     *bool            `json:"handlesCardPayment,omitempty"`
	HandlesGoodsOrServices *bool            `json:"handlesGoodsOrServices,omitempty"`
	IsWebApplication       *bool            `json:"isWebApplication,omitempty"`
	PrivilegeLevel         *string          `json:"privilegeLevel,omitempty"`
	IsBidirectional        *bool            `json:"isBidirectional,omitempty"`
	IsEncrypted            *bool            `json:"isEncrypted,omitempty"`
	IsPublicNetwork        *bool            `json:"isPublicNetwork,omitempty"`
	Protocol               *string          `json:"protocol,omitempty"`
	IsALog                 *bool            `json:"isALog,omitempty"`
	IsSigned               *bool            `json:"isSigned,omitempty"`
	StoresCredentials      *bool            `json:"storesCredentials,omitempty"`
	StoresInventory        *bool            `json:"storesInventory,omitempty"`
	ThreatFrequency        *ThreatFrequency `json:"threatFrequency,omitempty"`
}

type ThreatFrequency struct {
	Confidentiality       *int64 `json:"confidentiality,omitempty"`
	Integrity             *int64 `json:"integrity,omitempty"`
	Availability          *int64 `json:"availability,omitempty"`
	Spoofing              *int64 `json:"spoofing,omitempty"`
	Tampering             *int64 `json:"tampering,omitempty"`
	Repudiation           *int64 `json:"repudiation,omitempty"`
	InformationDisclosure *int64 `json:"informationDisclosure,omitempty"`
	DenialOfService       *int64 `json:"denialOfService,omitempty"`
	ElevationOfPrivilege  *int64 `json:"elevationOfPrivilege,omitempty"`
}

type Threat struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Status      string  `json:"status"`
	Severity    string  `json:"severity"`
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Mitigation  string  `json:"mitigation"`
	ModelType   string  `json:"modelType"`
	New         *bool   `json:"new,omitempty"`
	Number      *int64  `json:"number,omitempty"`
	Score       *string `json:"score,omitempty"`
}

type LabelElement struct {
	LabelLabel *LabelLabel
	String     *string
}

func (x *LabelElement) UnmarshalJSON(data []byte) error {
	x.LabelLabel = nil
	var c LabelLabel
	object, err := unmarshalUnion(data, nil, nil, nil, &x.String, false, nil, true, &c, false, nil, false, nil, false)
	if err != nil {
		return err
	}
	if object {
		x.LabelLabel = &c
	}
	return nil
}

func (x *LabelElement) MarshalJSON() ([]byte, error) {
	return marshalUnion(nil, nil, nil, x.String, false, nil, x.LabelLabel != nil, x.LabelLabel, false, nil, false, nil, false)
}

type LabelLabel struct {
	Attrs    LabelAttrs     `json:"attrs"`
	Markup   []Markup       `json:"markup"`
	Position *PositionUnion `json:"position"`
}

type LabelAttrs struct {
	Label     TextClass  `json:"label"`
	LabelText LabelText  `json:"labelText"`
	LabelBody LabelBody  `json:"labelBody"`
	Text      *TextClass `json:"text,omitempty"`
}

type LabelBody struct {
	Ref         string `json:"ref"`
	RefRx       string `json:"refRx"`
	RefRy       string `json:"refRy"`
	Fill        string `json:"fill"`
	StrokeWidth int64  `json:"strokeWidth"`
}

type LabelText struct {
	Text               string `json:"text"`
	TextAnchor         string `json:"textAnchor"`
	TextVerticalAnchor string `json:"textVerticalAnchor"`
}

type Markup struct {
	TagName  string `json:"tagName"`
	Selector string `json:"selector"`
}

type PositionPosition struct {
	Distance float64 `json:"distance"`
	Args     Args    `json:"args"`
}

type Args struct {
	KeepGradient     bool `json:"keepGradient"`
	EnsureLegibility bool `json:"ensureLegibility"`
}

type Ports struct {
	Groups PortGroups `json:"groups"`
	Items  []Port     `json:"items"`
}

type PortGroups struct {
	Top    PortGroup `json:"top"`
	Right  PortGroup `json:"right"`
	Bottom PortGroup `json:"bottom"`
	Left   PortGroup `json:"left"`
}

type PortGroup struct {
	Position string         `json:"position"`
	Attrs    PortGroupAttrs `json:"attrs"`
}

type PortGroupAttrs struct {
	Circle Circle `json:"circle"`
}

type Circle struct {
	R           float64 `json:"r"`
	Magnet      bool    `json:"magnet"`
	Stroke      string  `json:"stroke"`
	StrokeWidth float64 `json:"strokeWidth"`
	Fill        string  `json:"fill"`
	Style       Style   `json:"style"`
}

type Style struct {
	Visibility string `json:"visibility"`
}

type Port struct {
	Group string `json:"group"`
	ID    string `json:"id"`
}

type VertexClass struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type Size struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type Source struct {
	Cell *string `json:"cell,omitempty"`
	Port *string `json:"port,omitempty"`
	X    *int64  `json:"x,omitempty"`
	Y    *int64  `json:"y,omitempty"`
}

type Tools struct {
	Items []string         `json:"items"`
	Name  Nullable[string] `json:"name,omitzero"`
}

type Summary struct {
	Title       string `json:"title"`
	Owner       string `json:"owner"`
	Description string `json:"description"`
	ID          int64  `json:"id"`
}

type Marker struct {
	Contributor *Contributor
	String      *string
}

func (x *Marker) UnmarshalJSON(data []byte) error {
	x.Contributor = nil
	var c Contributor
	object, err := unmarshalUnion(data, nil, nil, nil, &x.String, false, nil, true, &c, false, nil, false, nil, false)
	if err != nil {
		return err
	}
	if object {
		x.Contributor = &c
	}
	return nil
}

func (x *Marker) MarshalJSON() ([]byte, error) {
	return marshalUnion(nil, nil, nil, x.String, false, nil, x.Contributor != nil, x.Contributor, false, nil, false, nil, false)
}

type PositionUnion struct {
	Double           *float64
	PositionPosition *PositionPosition
}

func (x *PositionUnion) UnmarshalJSON(data []byte) error {
	x.PositionPosition = nil
	var c PositionPosition
	object, err := unmarshalUnion(data, nil, &x.Double, nil, nil, false, nil, true, &c, false, nil, false, nil, false)
	if err != nil {
		return err
	}
	if object {
		x.PositionPosition = &c
	}
	return nil
}

func (x *PositionUnion) MarshalJSON() ([]byte, error) {
	return marshalUnion(nil, x.Double, nil, nil, false, nil, x.PositionPosition != nil, x.PositionPosition, false, nil, false, nil, false)
}

func unmarshalUnion(data []byte, pi **int64, pf **float64, pb **bool, ps **string, haveArray bool, pa interface{}, haveObject bool, pc interface{}, haveMap bool, pm interface{}, haveEnum bool, pe interface{}, nullable bool) (bool, error) {
	if pi != nil {
		*pi = nil
	}
	if pf != nil {
		*pf = nil
	}
	if pb != nil {
		*pb = nil
	}
	if ps != nil {
		*ps = nil
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}

	switch v := tok.(type) {
	case json.Number:
		if pi != nil {
			i, err := v.Int64()
			if err == nil {
				*pi = &i
				return false, nil
			}
		}
		if pf != nil {
			f, err := v.Float64()
			if err == nil {
				*pf = &f
				return false, nil
			}
			return false, errors.New("unparsable number")
		}
		return false, errors.New("union does not contain number")
	case float64:
		return false, errors.New("decoder should not return float64")
	case bool:
		if pb != nil {
			*pb = &v
			return false, nil
		}
		return false, errors.New("union does not contain bool")
	case string:
		if haveEnum {
			return false, json.Unmarshal(data, pe)
		}
		if ps != nil {
			*ps = &v
			return false, nil
		}
		return false, errors.New("union does not contain string")
	case nil:
		if nullable {
			return false, nil
		}
		return false, errors.New("union does not contain null")
	case json.Delim:
		if v == '{' {
			if haveObject {
				return true, json.Unmarshal(data, pc)
			}
			if haveMap {
				return false, json.Unmarshal(data, pm)
			}
			return false, errors.New("union does not contain object")
		}
		if v == '[' {
			if haveArray {
				return false, json.Unmarshal(data, pa)
			}
			return false, errors.New("union does not contain array")
		}
		return false, errors.New("cannot handle delimiter")
	}
	return false, errors.New("cannot unmarshal union")

}

func marshalUnion(pi *int64, pf *float64, pb *bool, ps *string, haveArray bool, pa interface{}, haveObject bool, pc interface{}, haveMap bool, pm interface{}, haveEnum bool, pe interface{}, nullable bool) ([]byte, error) {
	if pi != nil {
		return json.Marshal(*pi)
	}
	if pf != nil {
		return json.Marshal(*pf)
	}
	if pb != nil {
		return json.Marshal(*pb)
	}
	if ps != nil {
		return json.Marshal(*ps)
	}
	if haveArray {
		return json.Marshal(pa)
	}
	if haveObject {
		return json.Marshal(pc)
	}
	if haveMap {
		return json.Marshal(pm)
	}
	if haveEnum {
		return json.Marshal(pe)
	}
	if nullable {
		return json.Marshal(nil)
	}
	return nil, errors.New("union must not be null")
}

// Nullable is a generic type to track if a JSON key was missing, null, or had a value.
type Nullable[T any] struct {
	Value   T
	Set     bool // true if the key was present
	Present bool // true if value is not null
}

func (n *Nullable[T]) UnmarshalJSON(data []byte) error {
	n.Set = true
	if bytes.Equal(data, []byte("null")) {
		n.Present = false
		var zero T
		n.Value = zero
		return nil
	}
	n.Present = true
	return json.Unmarshal(data, &n.Value)
}

func (n Nullable[T]) MarshalJSON() ([]byte, error) {
	if !n.Present {
		return []byte("null"), nil
	}
	return json.Marshal(n.Value)
}

// Required to support omitempty when Set == false
func (n Nullable[T]) IsZero() bool {
	return !n.Set
}

// Used for creating optional bool values for the Threatdragon json model
func boolPtr(value bool) *bool {
	return &value
}

// Used for creating optional string values for the Threatdragon json model
func stringPtr(value string) *string {
	return &value
}

// Used for creating optional float64 values for the Threatdragon json model
func float64Ptr(value float64) *float64 {
	return &value
}
