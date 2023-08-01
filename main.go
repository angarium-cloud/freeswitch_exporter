package main

import (
	"net/http"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

func init() {
	prometheus.MustRegister(version.NewCollector("freeswitch_exporter"))
}

func main() {
	var (
		metricsPath = kingpin.Flag(
			"web.telemetry-path",
			"Path under which to expose metrics.",
		).Default("/metrics").String()
		scrapeURI = kingpin.Flag(
			"freeswitch.scrape-uri",
			`URI on which to scrape freeswitch. E.g. "tcp://localhost:8021"`,
		).Short('u').Default("tcp://localhost:8021").String()
		timeout = kingpin.Flag(
			"freeswitch.timeout",
			"Timeout for trying to get stats from freeswitch.",
		).Short('t').Default("5s").Duration()
		password = kingpin.Flag(
			"freeswitch.password",
			"Password for freeswitch event socket.",
		).Short('P').Default("ClueCon").String()
		toolkitFlags = webflag.AddFlags(kingpin.CommandLine, ":9282")
		rtpEnable    = kingpin.Flag("rtp.enable", "enable rtp info, default: fasle").Default("false").Bool()
	)
	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("freeswitch_exporter"))
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Info(logger).Log("msg", "Starting freeswitch_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())

	c, err := NewCollector(*scrapeURI, *timeout, *password, *rtpEnable)

	if err != nil {
		panic(err)
	}

	prometheus.MustRegister(c)

	http.Handle(*metricsPath, promhttp.Handler())
	if *metricsPath != "/" && *metricsPath != "" {
		landingConfig := web.LandingConfig{
			Name:        "FreeSWITCH Exporter",
			Description: "Prometheus Exporter for FreeSWITCH servers",
			Version:     version.Info(),
			Links: []web.LandingLinks{
				{
					Address: *metricsPath,
					Text:    "Metrics",
				},
			},
		}
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			level.Error(logger).Log("err", err)
			os.Exit(1)
		}
		http.Handle("/", landingPage)
	}
	server := &http.Server{}
	if err := web.ListenAndServe(server, toolkitFlags, logger); err != nil {
		level.Info(logger).Log("err", err)
		os.Exit(1)
	}
}
