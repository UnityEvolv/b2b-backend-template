// Package sheet reads a spreadsheet, CSV or XLSX, into rows of text for
// the bulk imports: users (UO-69) and offices (UO-115). No dependency: an
// XLSX is a zip of XML,
// and the little of it an import needs is read here.
package sheet

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	// MaxRows is the most rows one import takes, header included.
	MaxRows = 5001
	// MaxColumns is the most columns a row may have.
	MaxColumns = 50
)

var (
	ErrEmpty    = errors.New("sheet: no rows")
	ErrTooLarge = errors.New("sheet: too many rows or columns")
	ErrFormat   = errors.New("sheet: not a CSV or XLSX file")
)

// Table is a header row and the rows under it, every cell trimmed.
type Table struct {
	Header []string
	Rows   [][]string
}

// Read parses data as XLSX when it is a zip, CSV otherwise.
func Read(data []byte) (Table, error) {
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		return readXLSX(data)
	}
	return readCSV(data)
}

func finish(rows [][]string) (Table, error) {
	// Drop rows that are entirely blank; a trailing newline is not a person.
	kept := rows[:0]
	for _, r := range rows {
		blank := true
		for i := range r {
			r[i] = strings.TrimSpace(r[i])
			if r[i] != "" {
				blank = false
			}
		}
		if !blank {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		return Table{}, ErrEmpty
	}
	if len(kept) > MaxRows {
		return Table{}, ErrTooLarge
	}
	for _, r := range kept {
		if len(r) > MaxColumns {
			return Table{}, ErrTooLarge
		}
	}
	return Table{Header: kept[0], Rows: kept[1:]}, nil
}

func readCSV(data []byte) (Table, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	var rows [][]string
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Table{}, fmt.Errorf("%w: %v", ErrFormat, err)
		}
		rows = append(rows, rec)
		if len(rows) > MaxRows {
			return Table{}, ErrTooLarge
		}
	}
	return finish(rows)
}

// The parts of the XLSX XML an import reads.
type sst struct {
	Items []struct {
		Texts []string `xml:"t"`
		Runs  []struct {
			Text string `xml:"t"`
		} `xml:"r"`
	} `xml:"si"`
}

type worksheet struct {
	Rows []struct {
		R     string `xml:"r,attr"`
		Cells []struct {
			R      string `xml:"r,attr"`
			T      string `xml:"t,attr"`
			V      string `xml:"v"`
			Inline struct {
				T string `xml:"t"`
			} `xml:"is"`
		} `xml:"c"`
	} `xml:"sheetData>row"`
}

func readXLSX(data []byte) (Table, error) {
	z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return Table{}, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	files := map[string]*zip.File{}
	for _, f := range z.File {
		files[f.Name] = f
	}
	var strs []string
	if f, ok := files["xl/sharedStrings.xml"]; ok {
		var s sst
		if err := decodeXML(f, &s); err != nil {
			return Table{}, err
		}
		for _, item := range s.Items {
			var b strings.Builder
			for _, t := range item.Texts {
				b.WriteString(t)
			}
			for _, r := range item.Runs {
				b.WriteString(r.Text)
			}
			strs = append(strs, b.String())
		}
	}
	// The first sheet, whatever the workbook calls it.
	sheet, ok := files["xl/worksheets/sheet1.xml"]
	if !ok {
		for name, f := range files {
			if strings.HasPrefix(name, "xl/worksheets/sheet") && strings.HasSuffix(name, ".xml") {
				sheet = f
				break
			}
		}
	}
	if sheet == nil {
		return Table{}, fmt.Errorf("%w: no worksheet", ErrFormat)
	}
	var ws worksheet
	if err := decodeXML(sheet, &ws); err != nil {
		return Table{}, err
	}
	if len(ws.Rows) > MaxRows {
		return Table{}, ErrTooLarge
	}
	var rows [][]string
	for _, row := range ws.Rows {
		var cells []string
		for _, c := range row.Cells {
			col := columnIndex(c.R)
			if col < 0 || col >= MaxColumns {
				return Table{}, ErrTooLarge
			}
			for len(cells) <= col {
				cells = append(cells, "")
			}
			switch c.T {
			case "s":
				i, err := strconv.Atoi(c.V)
				if err == nil && i >= 0 && i < len(strs) {
					cells[col] = strs[i]
				}
			case "inlineStr":
				cells[col] = c.Inline.T
			default:
				cells[col] = c.V
			}
		}
		rows = append(rows, cells)
	}
	return finish(rows)
}

func decodeXML(f *zip.File, into any) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
	defer rc.Close()
	// A worksheet is text; a bomb is not welcome.
	dec := xml.NewDecoder(io.LimitReader(rc, 64<<20))
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("%w: %v", ErrFormat, err)
	}
	return nil
}

// columnIndex is the zero-based column of a cell reference such as C7.
func columnIndex(ref string) int {
	n := 0
	for _, ch := range ref {
		if ch < 'A' || ch > 'Z' {
			break
		}
		n = n*26 + int(ch-'A') + 1
	}
	return n - 1
}

// Column is the index of a header, matched without regard to case or
// surrounding space, or -1.
func (t Table) Column(name string) int {
	want := strings.ToLower(strings.TrimSpace(name))
	for i, h := range t.Header {
		if strings.ToLower(h) == want {
			return i
		}
	}
	return -1
}

// Cell is a row's value in a column, or "" past the row's end.
func Cell(row []string, col int) string {
	if col < 0 || col >= len(row) {
		return ""
	}
	return row[col]
}
