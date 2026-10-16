package main

import (
	"fmt"

	"example.com/smoke/internal/handler"
	"example.com/smoke/internal/service"
)

func main() {
	items := []service.Item{
		{Region: "norway", Remark: "logged", Source: "web", Weight: 10},
		{Region: "chile", Remark: "logged", Source: "web", Weight: 20},
	}
	report := service.RunBatch(items)
	fmt.Println("counts:", report.Counts)
	fmt.Println("source:", report.Source)
	if err := handler.Process("a1"); err != nil {
		fmt.Println("process failed:", err)
	}
	if err := handler.ProcessLogged("b2"); err != nil {
		fmt.Println("logged process failed:", err)
	}
}
