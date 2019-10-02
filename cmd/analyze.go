package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/influxdata/telegraf/internal/config"
	_ "github.com/influxdata/telegraf/plugins/inputs/all"
	_ "github.com/influxdata/telegraf/plugins/outputs/all"
)

func main() {
	files, err := ioutil.ReadDir("out")

	if err != nil {
		log.Fatal(err)
	}

	var counts map[string]int
	counts = make(map[string]int)
	counts["invalid"] = 0

	for _, f := range files {
		configuration := config.NewConfig()
		err := configuration.LoadConfig(fmt.Sprintf("./out/%v", f.Name()))

		counts[fmt.Sprintf("interval_%d", configuration.Agent.Interval)]++
		counts[fmt.Sprintf("round_interval_%d", configuration.Agent.RoundInterval)]++
		counts[fmt.Sprintf("jitter_%d", configuration.Agent.CollectionJitter)]++
		counts[fmt.Sprintf("omit_hostname_%d", configuration.Agent.OmitHostname)]++
		counts[fmt.Sprintf("metric_batch_size_%d", configuration.Agent.MetricBatchSize)]++
		counts[fmt.Sprintf("metric_buffer_limit_%d", configuration.Agent.MetricBufferLimit)]++

		if err != nil {
			fmt.Printf("Skipping %v: Invalid Config\n", f.Name())
			counts["invalid"]++
			continue
		}

		inputs := 0
		for _, input := range configuration.Inputs {
			inputs++
			counts[input.LogName()]++
		}

		counts[fmt.Sprintf("inputs_count_%d", inputs)]++

		outputs := 0
		for _, output := range configuration.Outputs {
			outputs++
			counts[output.LogName()]++
		}
		counts[fmt.Sprintf("outputs_count_%d", outputs)]++

		for _, aggregator := range configuration.Aggregators {
			fmt.Println("Found an aggregator")
			counts[aggregator.LogName()]++
		}
	}

	b, err := json.MarshalIndent(counts, "", "  ")
	fmt.Printf(string(b))
}

func die(err error) {
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
}
