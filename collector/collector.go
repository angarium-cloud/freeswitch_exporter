// MIT License
// Copyright 2023 Angarium Ltd
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package collector

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/html/charset"
)

// Collector implements prometheus.Collector (see below).
// it also contains the config of the exporter.
type Collector struct {
	URI       string
	Timeout   time.Duration
	Password  string
	rtpEnable bool

	conn    net.Conn
	input   *bufio.Reader
	address string
	scheme  string
	mutex   sync.Mutex

	logger        log.Logger
	up            prometheus.Gauge
	failedScrapes prometheus.Counter
	totalScrapes  prometheus.Counter
}

// Metric represents a prometheus metric. It is either fetched from an api command,
// or from "status" parsing (thus the RegexIndex)
type Metric struct {
	Name       string
	Help       string
	Type       prometheus.ValueType
	Command    string
	RegexIndex int
}

const (
	namespace = "freeswitch"
)

type Gateways struct {
	XMLName xml.Name  `xml:"gateways"`
	Gateway []Gateway `xml:"gateway"`
}

type Gateway struct {
	Name           string  `xml:"name"`
	Profile        string  `xml:"profile"`
	Scheme         string  `xml:"scheme"`
	Realm          string  `xml:"realm"`
	UserName       string  `xml:"username"`
	Password       string  `xml:"passowrd"`
	From           string  `xml:"from"`
	Contact        string  `xml:"contact"`
	Exten          string  `xml:"exten"`
	To             string  `xml:"to"`
	Proxy          string  `xml:"proxy"`
	Context        string  `xml:"context"`
	Expires        int     `xml:"expires"`
	FReq           int     `xml:"freq"`
	Ping           int     `xml:"ping"`
	PingFreq       int     `xml:"pingfreq"`
	PingMin        int     `xml:"pingmin"`
	PingCount      int     `xml:"pingcount"`
	PingMax        int     `xml:"pingmax"`
	PingTime       float64 `xml:"pingtime"`
	Pinging        int     `xml:"pinging"`
	State          string  `xml:"state"`
	Status         string  `xml:"status"`
	UptimeUsec     string  `xml:"uptime-usec"`
	CallsIn        int     `xml:"calls-in"`
	CallsOut       int     `xml:"calls-out"`
	FailedCallsIn  int     `xml:"failed-calls-in"`
	FailedCallsOut int     `xml:"failed-calls-out"`
}

type Configuration struct {
	XMLName     xml.Name `xml:"configuration"`
	Text        string   `xml:",chardata"`
	Name        string   `xml:"name,attr"`
	Description string   `xml:"description,attr"`
	Modules     struct {
		Text string `xml:",chardata"`
		Load []struct {
			Text   string `xml:",chardata"`
			Module string `xml:"module,attr"`
		} `xml:"load"`
	} `xml:"modules"`
}

type Result struct {
	XMLName  xml.Name `xml:"result"`
	Text     string   `xml:",chardata"`
	RowCount string   `xml:"row_count,attr"`
	Row      []struct {
		Text  string `xml:",chardata"`
		RowID string `xml:"row_id,attr"`
		Type  struct {
			Text string `xml:",chardata"`
		} `xml:"type"`
		Name struct {
			Text string `xml:",chardata"`
		} `xml:"name"`
		Ikey struct {
			Text string `xml:",chardata"`
		} `xml:"ikey"`
	} `xml:"row"`
}

type Verto struct {
	XMLName xml.Name `xml:"profiles"`
	Text    string   `xml:",chardata"`
	Profile []struct {
		Text string `xml:",chardata"`
		Name struct {
			Text string `xml:",chardata"`
		} `xml:"name"`
		Type struct {
			Text string `xml:",chardata"`
		} `xml:"type"`
		Data struct {
			Text string `xml:",chardata"`
		} `xml:"data"`
		State struct {
			Text string `xml:",chardata"`
		} `xml:"state"`
	} `xml:"profile"`
}

var (
	metricList = []Metric{
		{Name: "current_calls", Type: prometheus.GaugeValue, Help: "Number of calls active", Command: "api show calls count as json"},
		{Name: "detailed_bridged_calls", Type: prometheus.GaugeValue, Help: "Number of detailed_bridged_calls active", Command: "api show detailed_bridged_calls as json"},
		{Name: "detailed_calls", Type: prometheus.GaugeValue, Help: "Number of detailed_calls active", Command: "api show detailed_calls as json"},
		{Name: "bridged_calls", Type: prometheus.GaugeValue, Help: "Number of bridged_calls active", Command: "api show bridged_calls as json"},
		{Name: "registrations", Type: prometheus.GaugeValue, Help: "Number of registrations active", Command: "api show registrations as json"},
		{Name: "current_channels", Type: prometheus.GaugeValue, Help: "Number of channels active", Command: "api show channels count as json"},
		{Name: "time_synced", Type: prometheus.GaugeValue, Help: "Is FreeSWITCH time in sync with exporter host time", Command: "api strepoch"},
		{Name: "sessions_total", Type: prometheus.CounterValue, Help: "Number of sessions since startup", RegexIndex: 1},
		{Name: "current_sessions", Type: prometheus.GaugeValue, Help: "Number of sessions active", RegexIndex: 2},
		{Name: "current_sessions_peak", Type: prometheus.GaugeValue, Help: "Peak sessions since startup", RegexIndex: 3},
		{Name: "current_sessions_peak_last_5min", Type: prometheus.GaugeValue, Help: "Peak sessions for the last 5 minutes", RegexIndex: 4},
		{Name: "current_sps", Type: prometheus.GaugeValue, Help: "Number of sessions per second", RegexIndex: 5},
		{Name: "current_sps_peak", Type: prometheus.GaugeValue, Help: "Peak sessions per second since startup", RegexIndex: 7},
		{Name: "current_sps_peak_last_5min", Type: prometheus.GaugeValue, Help: "Peak sessions per second for the last 5 minutes", RegexIndex: 8},
		{Name: "max_sps", Type: prometheus.GaugeValue, Help: "Max sessions per second allowed", RegexIndex: 6},
		{Name: "max_sessions", Type: prometheus.GaugeValue, Help: "Max sessions allowed", RegexIndex: 9},
		{Name: "current_idle_cpu", Type: prometheus.GaugeValue, Help: "CPU idle", RegexIndex: 11},
		{Name: "min_idle_cpu", Type: prometheus.GaugeValue, Help: "Minimum CPU idle", RegexIndex: 10},
	}
	statusRegex   = regexp.MustCompile(`(\d+) session\(s\) since startup\s+(\d+) session\(s\) - peak (\d+), last 5min (\d+)\s+(\d+) session\(s\) per Sec out of max (\d+), peak (\d+), last 5min (\d+)\s+(\d+) session\(s\) max\s+min idle cpu (\d+\.\d+)\/(\d+\.\d+)`)
	uptimeSeconds = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "uptime_seconds"),
		"Uptime in seconds",
		[]string{"version"}, nil)
)

// New processes uri, timeout and methods and returns a new Collector.
func New(uri string, timeout time.Duration, password string, rtpEnable bool, logger log.Logger) (*Collector, error) {
	var c Collector

	c.URI = uri
	c.Timeout = timeout
	c.Password = password
	c.rtpEnable = rtpEnable
	c.logger = logger

	var url *url.URL
	var err error

	if url, err = url.Parse(c.URI); err != nil {
		return nil, fmt.Errorf("cannot parse URI: %w", err)
	}

	c.address = url.Host
	c.scheme = url.Scheme

	if c.scheme == "unix" {
		c.address = url.Path
	}

	c.up = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "up",
		Help:      "Was the last scrape successful.",
	})

	c.totalScrapes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_total_scrapes",
		Help:      "Current total freeswitch scrapes.",
	})

	c.failedScrapes = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "exporter_failed_scrapes",
		Help:      "Number of failed freeswitch scrapes.",
	})

	return &c, nil
}

// scrape will connect to the freeswitch instance and push metrics to the Prometheus channel.
func (c *Collector) scrape(ch chan<- prometheus.Metric) error {
	c.totalScrapes.Inc()

	var err error

	c.conn, err = net.DialTimeout(c.scheme, c.address, c.Timeout)

	if err != nil {
		return err
	}

	c.conn.SetDeadline(time.Now().Add(c.Timeout))
	defer c.conn.Close()

	c.input = bufio.NewReader(c.conn)

	if err = c.fsAuth(); err != nil {
		return err
	}

	if err = c.scapeUptime(ch); err != nil {
		return err
	}

	if err = c.scapeMetrics(ch); err != nil {
		return err
	}

	if err = c.scrapeStatus(ch); err != nil {
		return err
	}

	if err = c.sofiaStatusMetrics(ch); err != nil {
		return err
	}

	if err = c.loadModuleMetrics(ch); err != nil {
		return err
	}

	if err = c.endpointMetrics(ch); err != nil {
		return err
	}

	if err = c.codecMetrics(ch); err != nil {
		return err
	}

	if err = c.vertoMetrics(ch); err != nil {
		return err
	}

	if c.rtpEnable {
		if err = c.variableRtpAudioMetrics(ch); err != nil {
			return err
		}
	}

	return nil
}

func (c *Collector) variableRtpAudioMetrics(ch chan<- prometheus.Metric) error {
	return nil
}

func (c *Collector) scapeUptime(ch chan<- prometheus.Metric) error {
	response, err := c.fsCommand("api uptime s")
	if err != nil {
		return err
	}

	raw := string(response)
	if raw[len(raw)-1:] == "\n" {
		raw = raw[:len(raw)-1]
	}

	value, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fmt.Errorf("cannot read uptime: %w", err)
	}

	response, err = c.fsCommand("api version short")
	if err != nil {
		return err
	}

	version := string(response)
	if version[len(version)-1:] == "\n" {
		version = version[:len(version)-1]
	}

	metric, err := prometheus.NewConstMetric(
		uptimeSeconds,
		prometheus.GaugeValue,
		value,
		version,
	)

	if err != nil {
		return err
	}

	ch <- metric
	return nil
}

func (c *Collector) scapeMetrics(ch chan<- prometheus.Metric) error {
	for _, metricDef := range metricList {
		if len(metricDef.Command) == 0 {
			// this metric will be fetched by scapeStatus
			continue
		}

		value, err := c.fetchMetric(&metricDef)

		if err != nil {
			return err
		}

		metric, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_"+metricDef.Name, metricDef.Help, nil, nil),
			metricDef.Type,
			value,
		)

		if err != nil {
			return err
		}

		ch <- metric
	}

	return nil
}

func (c *Collector) loadModuleMetrics(ch chan<- prometheus.Metric) error {
	response, err := c.fsCommand("api xml_locate configuration configuration name modules.conf")

	if err != nil {
		return err
	}
	cfgs := Configuration{}

	decode := xml.NewDecoder(bytes.NewReader(response))
	decode.CharsetReader = charset.NewReaderLabel
	err = decode.Decode(&cfgs)
	if err != nil {
		msgStr := fmt.Sprintf("Configuration decode error: %s", err)
		level.Warn(c.logger).Log("msg", msgStr)
	}
	level.Debug(c.logger).Log("[response]:", &cfgs)
	fsLoadModules := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "freeswitch_load_module",
			Help: "freeswitch load module status",
		},
		[]string{
			"module",
		},
	)
	//prometheus.MustRegister(fsLoadModules)
	for _, m := range cfgs.Modules.Load {
		status, err := c.fsCommand("api module_exists " + m.Module)

		if err != nil {
			return err
		}
		loadModule := 0

		if string(status) == "true" {
			loadModule = 1
		}
		level.Debug(c.logger).Log("module", m.Module, " load status: ", string(status))
		fsLoadModules.WithLabelValues(m.Module).Set(float64(loadModule))
	}
	fsLoadModules.MetricVec.Collect(ch)
	return nil
}

func (c *Collector) sofiaStatusMetrics(ch chan<- prometheus.Metric) error {
	response, err := c.fsCommand("api sofia xmlstatus gateway")

	if err != nil {
		return err
	}
	gw := Gateways{}
	//err = xml.Unmarshal(response, &gw)

	decode := xml.NewDecoder(bytes.NewReader(response))
	decode.CharsetReader = charset.NewReaderLabel
	err = decode.Decode(&gw)
	if err != nil {
		msgStr := fmt.Sprintf("Gateways decode error: %s", err)
		level.Warn(c.logger).Log("msg", msgStr)
	}
	level.Debug(c.logger).Log("[response]:", &gw)
	for _, gateway := range gw.Gateway {
		status := 0
		if gateway.Status == "UP" {
			status = 1
		}
		level.Debug(c.logger).Log("sofia ", gateway.Name, " status:", status)
		fsStatus, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_status", "freeswitch gateways status", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile, "context": gateway.Context, "scheme": gateway.Scheme}),
			prometheus.GaugeValue,
			float64(status),
		)

		if err != nil {
			return err
		}

		ch <- fsStatus

		callIn, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_call_in", "freeswitch gateway call-in", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.CallsIn),
		)
		if err != nil {
			return err
		}

		ch <- callIn

		callOut, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_call_out", "freeswitch gateway call-out", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.CallsOut),
		)
		if err != nil {
			return err
		}

		ch <- callOut

		failedCallIn, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_failed_call_in", "freeswitch gateway failed-call-in", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.FailedCallsIn),
		)
		if err != nil {
			return err
		}

		ch <- failedCallIn

		failedCallOut, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_failed_call_out", "freeswitch gateway failed-call-out", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.FailedCallsOut),
		)
		if err != nil {
			return err
		}

		ch <- failedCallOut

		ping, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_ping", "freeswitch gateway ping", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.Ping),
		)
		if err != nil {
			return err
		}

		ch <- ping

		pingfreq, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_pingfreq", "freeswitch gateway pingfreq", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.PingFreq),
		)
		if err != nil {
			return err
		}

		ch <- pingfreq

		pingmin, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_pingmin", "freeswitch gateway pingmin", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.PingMin),
		)
		if err != nil {
			return err
		}

		ch <- pingmin

		pingmax, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_pingmax", "freeswitch gateway pingmax", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.PingMax),
		)
		if err != nil {
			return err
		}

		ch <- pingmax

		pingcount, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_pingcount", "freeswitch gateway pingcount", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.PingCount),
		)
		if err != nil {
			return err
		}

		ch <- pingcount

		pingtime, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_sofia_gateway_pingtime", "freeswitch gateway pingtime", nil, prometheus.Labels{"name": gateway.Name, "proxy": gateway.Proxy, "profile": gateway.Profile}),
			prometheus.GaugeValue,
			float64(gateway.PingTime),
		)
		if err != nil {
			return err
		}

		ch <- pingtime
	}
	return nil
}

func (c *Collector) endpointMetrics(ch chan<- prometheus.Metric) error {
	response, err := c.fsCommand("api show endpoint as xml")

	if err != nil {
		return err
	}
	rt := Result{}
	decode := xml.NewDecoder(bytes.NewReader(response))
	decode.CharsetReader = charset.NewReaderLabel
	err = decode.Decode(&rt)
	if err != nil {
		msgStr := fmt.Sprintf("Result decode error: %s", err)
		level.Warn(c.logger).Log("msg", msgStr)
	}
	level.Debug(c.logger).Log("[response]:", &rt)
	for _, ep := range rt.Row {
		endpointLoad, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_endpoint_status", "freeswitch endpoint status", nil, prometheus.Labels{"type": ep.Type.Text, "name": ep.Name.Text, "ikey": ep.Ikey.Text}),
			prometheus.GaugeValue,
			float64(1),
		)

		if err != nil {
			return err
		}

		ch <- endpointLoad
	}
	return nil
}

func (c *Collector) codecMetrics(ch chan<- prometheus.Metric) error {
	response, err := c.fsCommand("api show codec as xml")

	if err != nil {
		return err
	}
	rt := Result{}
	decode := xml.NewDecoder(bytes.NewReader(response))
	decode.CharsetReader = charset.NewReaderLabel
	err = decode.Decode(&rt)
	if err != nil {
		msgStr := fmt.Sprintf("Result decode error: %s", err)
		level.Warn(c.logger).Log("msg", msgStr)
	}
	level.Debug(c.logger).Log("[response]:", &rt)
	for _, cc := range rt.Row {
		codecLoad, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_codec_status", "freeswitch endpoint status", nil, prometheus.Labels{"type": cc.Type.Text, "name": cc.Name.Text, "ikey": cc.Ikey.Text}),
			prometheus.GaugeValue,
			float64(1),
		)

		if err != nil {
			return err
		}

		ch <- codecLoad
	}
	return nil
}

func (c *Collector) vertoMetrics(ch chan<- prometheus.Metric) error {
	status, err := c.fsCommand("api module_exists mod_verto")
	if err != nil {
		return err
	}

	if string(status) == "false" {
		return nil
	}

	response, err := c.fsCommand("api verto xmlstatus")

	if err != nil {
		return err
	}
	vt := Verto{}
	decode := xml.NewDecoder(bytes.NewReader(response))
	decode.CharsetReader = charset.NewReaderLabel
	err = decode.Decode(&vt)
	if err != nil {
		msgStr := fmt.Sprintf("Verto decode error: %s", err)
		level.Warn(c.logger).Log("msg", msgStr)
	}
	level.Debug(c.logger).Log("[response]:", &vt)
	for _, cc := range vt.Profile {
		vertoStatus := 0
		if cc.State.Text == "RUNNING" {
			vertoStatus = 1
		}
		vertoLoad, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_verto_status", "freeswitch endpoint status", nil, prometheus.Labels{"name": cc.Name.Text, "type": cc.Type.Text, "data": cc.Data.Text}),
			prometheus.GaugeValue,
			float64(vertoStatus),
		)

		if err != nil {
			return err
		}

		ch <- vertoLoad
	}
	return nil
}

func (c *Collector) scrapeStatus(ch chan<- prometheus.Metric) error {
	response, err := c.fsCommand("api status")

	if err != nil {
		return err
	}

	matches := statusRegex.FindAllSubmatch(response, -1)

	if len(matches) != 1 {
		return errors.New("error parsing status")
	}

	for _, metricDef := range metricList {
		if len(metricDef.Command) != 0 {
			// this metric will be fetched by fetchMetric
			continue
		}

		if len(matches[0]) < metricDef.RegexIndex {
			return errors.New("error parsing status")
		}

		strValue := string(matches[0][metricDef.RegexIndex])
		value, err := strconv.ParseFloat(strValue, 64)

		if err != nil {
			return fmt.Errorf("error parsing status: %w", err)
		}

		metric, err := prometheus.NewConstMetric(
			prometheus.NewDesc(namespace+"_"+metricDef.Name, metricDef.Help, nil, nil),
			metricDef.Type,
			value,
		)

		if err != nil {
			return err
		}

		ch <- metric
	}

	return nil
}

func (c *Collector) fetchMetric(metricDef *Metric) (float64, error) {
	now := time.Now()
	response, err := c.fsCommand(metricDef.Command)

	if err != nil {
		return 0, err
	}

	switch metricDef.Name {
	//case "current_channels":
	case "current_calls":
		r := struct {
			Count float64 `json:"row_count"`
		}{}

		err = json.Unmarshal(response, &r)

		if err != nil {
			return 0, fmt.Errorf("cannot read JSON response: %w", err)
		}

		return r.Count, nil
	case "current_channels":
		r := struct {
			Count float64 `json:"row_count"`
		}{}

		err = json.Unmarshal(response, &r)

		if err != nil {
			return 0, fmt.Errorf("cannot read JSON response: %w", err)
		}

		return r.Count, nil
	case "detailed_bridged_calls":
		r := struct {
			Count float64 `json:"row_count"`
		}{}

		err = json.Unmarshal(response, &r)

		if err != nil {
			return 0, fmt.Errorf("cannot read JSON response: %w", err)
		}

		return r.Count, nil
	case "detailed_calls":
		r := struct {
			Count float64 `json:"row_count"`
		}{}

		err = json.Unmarshal(response, &r)

		if err != nil {
			return 0, fmt.Errorf("cannot read JSON response: %w", err)
		}

		return r.Count, nil
	case "registrations":
		r := struct {
			Count float64 `json:"row_count"`
		}{}

		err = json.Unmarshal(response, &r)

		if err != nil {
			return 0, fmt.Errorf("cannot read JSON response: %w", err)
		}

		return r.Count, nil
	case "bridged_calls":
		r := struct {
			Count float64 `json:"row_count"`
		}{}

		err = json.Unmarshal(response, &r)

		if err != nil {
			return 0, fmt.Errorf("cannot read JSON response: %w", err)
		}

		return r.Count, nil
	case "time_synced":
		value, err := strconv.ParseInt(string(response), 10, 64)

		if err != nil {
			return 0, fmt.Errorf("cannot read FreeSWITCH time: %w", err)
		}

		if now.Unix() == value {
			return 1, nil
		}

		msgStr := fmt.Sprintf("[warning] time not in sync between system (%v) and FreeSWITCH (%v)\n",
			now.Unix(), value)
		level.Info(c.logger).Log("msg", msgStr)

		return 0, nil
	}

	return 0, fmt.Errorf("unknown metric: %s", metricDef.Name)
}

func (c *Collector) fsCommand(command string) ([]byte, error) {
	_, err := io.WriteString(c.conn, command+"\n\n")

	if err != nil {
		return nil, fmt.Errorf("cannot write command: %w", err)
	}

	mimeReader := textproto.NewReader(c.input)
	message, err := mimeReader.ReadMIMEHeader()

	if err != nil {
		return nil, fmt.Errorf("cannot read command response: %w", err)
	}

	value := message.Get("Content-Length")
	length, _ := strconv.Atoi(value)

	body := make([]byte, length)
	_, err = io.ReadFull(c.input, body)

	if err != nil {
		return nil, err
	}

	return body, nil
}

func (c *Collector) fsAuth() error {
	mimeReader := textproto.NewReader(c.input)
	message, err := mimeReader.ReadMIMEHeader()

	if err != nil {
		return fmt.Errorf("read auth failed: %w", err)
	}

	if message.Get("Content-Type") != "auth/request" {
		return errors.New("auth failed: unknown content-type")
	}

	_, err = io.WriteString(c.conn, fmt.Sprintf("auth %s\n\n", c.Password))

	if err != nil {
		return fmt.Errorf("write auth failed: %w", err)
	}

	message, err = mimeReader.ReadMIMEHeader()

	if err != nil {
		return fmt.Errorf("read auth failed: %w", err)
	}

	if message.Get("Content-Type") != "command/reply" {
		return errors.New("auth failed: unknown reply")
	}

	if message.Get("Reply-Text") != "+OK accepted" {
		return fmt.Errorf("auth failed: %s", message.Get("Reply-Text"))
	}

	return nil
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(c, ch)
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if err := c.scrape(ch); err != nil {
		level.Error(c.logger).Log("msg", "Error scraping freeswitch", "err", err)
		c.failedScrapes.Inc()
		c.failedScrapes.Collect(ch)
		c.up.Set(0)
	} else {
		c.up.Set(1)
	}

	ch <- c.up
	ch <- c.totalScrapes
}
