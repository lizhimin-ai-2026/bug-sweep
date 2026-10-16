package service

import (
	"strings"

	"example.com/smoke/internal/depa"
	"example.com/smoke/internal/depb"
)

const ModuleName = "service"

type Item struct {
	Region string
	Remark string
	Source string
	Weight int
}

type Note struct {
	Region      string
	Remark      string
	Source      string
	Weight      int
	Slug        string
	WeightKg    float64
	Priority    int
	Label       string
	Tag         string
	Fingerprint string
}

type Report struct {
	Counts map[string]int
	Digest string
	Source string
	Staged []Note
}

func RunBatch(items []Item) Report {
	staged := make([]Note, 0, len(items))
	for _, item := range items {
		region := strings.TrimSpace(item.Region)
		remark := strings.TrimSpace(item.Remark)
		source := strings.TrimSpace(item.Source)
		weight := item.Weight
		if weight < 0 {
			weight = 0
		}
		if weight > 1000 {
			weight = 1000
		}
		note := Note{
			Region:      depa.Normalize(region),
			Remark:      remark,
			Source:      source,
			Weight:      weight,
			Slug:        depb.Slugify(region),
			WeightKg:    float64(weight) / 1000.0,
			Priority:    1,
			Label:       "",
			Tag:         "",
			Fingerprint: "",
		}
		if weight > 500 {
			note.Priority = 0
		}
		note.Label = note.Slug + "-priority"
		note.Tag = note.Slug + "/" + note.Label
		note.Fingerprint = depb.ShortHash(note.Tag)
		if note.Region == "" {
			continue
		}
		if note.Remark == "" {
			continue
		}
		staged = append(staged, note)
	}
	counts := map[string]int{
		"total":  len(items),
		"staged": len(staged),
	}
	totalWeight := 0
	for _, note := range staged {
		totalWeight += note.Weight
	}
	digest := depb.ShortHash(depb.ModuleTag() + "|" + strings.Join(regionsOf(staged), ","))
	report := Report{
		Counts: counts,
		Digest: digest,
		Source: depb.ModuleTag(),
		Staged: staged,
	}
	return report
}

func regionsOf(notes []Note) []string {
	out := make([]string, 0, len(notes))
	for _, note := range notes {
		out = append(out, note.Region)
	}
	return out
}
