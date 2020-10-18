package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetOutput(os.Stdout)
}

var (
	adguardhomeAddr = flag.String("addr", "http://192.168.2.1:3100", "addguardhome addr")
	adguardhomeUser = flag.String("user", "admin", "adguardhome user")
	adguardhomePass = flag.String("pass", "admin", "adguardhome password")
	chinaDNS        = flag.String("chinaDNS", "https://rubyfish.cn/dns-query", "china dns")
	extDNS          = flag.String("extdns", "https://dns.google/dns-query", "ext dns config")
	chinaDomainURL  = flag.String("chinaDomain", "https://cdn.jsdelivr.net/gh/lostz/china-rules@release/direct.txt", "chinaDomainList")
	target          = flag.String("target", "/etc/china_domain.txt", "china domain file")
)

//DNSConfig ...
type DNSConfig struct {
	Upstreams         []string `json:"upstream_dns"`
	UpstreamsFile     string   `json:"upstream_dns_file"`
	Bootstraps        []string `json:"bootstrap_dns"`
	ProtectionEnabled bool     `json:"protection_enabled"`
	RateLimit         uint32   `json:"ratelimit"`
	BlockingMode      string   `json:"blocking_mode"`
	BlockingIPv4      string   `json:"blocking_ipv4"`
	BlockingIPv6      string   `json:"blocking_ipv6"`
	EDNSCSEnabled     bool     `json:"edns_cs_enabled"`
	DNSSECEnabled     bool     `json:"dnssec_enabled"`
	DisableIPv6       bool     `json:"disable_ipv6"`
	UpstreamMode      string   `json:"upstream_mode"`
	CacheSize         uint32   `json:"cache_size"`
	CacheMinTTL       uint32   `json:"cache_ttl_min"`
	CacheMaxTTL       uint32   `json:"cache_ttl_max"`
}

//DownloadDomainList ...
func DownloadDomainList(urls []string, dns string, target *os.File) error {
	defer target.Close()
	w := bufio.NewWriter(target)
	for _, url := range urls {
		resp, err := http.Get(url)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(bytes.NewBuffer(data))
		for scanner.Scan() {
			domain := scanner.Text()
			if strings.HasPrefix(domain, "#") {
				continue
			}
			line := fmt.Sprintf("[/%s/]%s", domain, dns)
			w.WriteString(line + "\n")
		}

	}
	w.Flush()
	return nil
}

//GetAdguardHomeDNSConfig ...
func GetAdguardHomeDNSConfig(addr, user, pass string) (*DNSConfig, error) {
	req, err := http.NewRequest("GET", addr+"/control/dns_info", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(user, pass)
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	config := DNSConfig{}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, err

}

//UpdateAdguardHomeDNSConfig ...
func UpdateAdguardHomeDNSConfig(addr, user, pass string, config *DNSConfig) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", addr+"/control/dns_config", bytes.NewBuffer(data))
	req.Header.Set("Content-Type", "application/json")
	if err != nil {
		return err
	}
	req.SetBasicAuth(user, pass)
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Info(string(body))
	log.Info("update adguardhome ", resp.Status)
	return nil

}

//HashFile ...
func HashFile(target string) (string, error) {
	input, err := os.Open(target)
	if err != nil {
		return "", err
	}
	defer input.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, input); err != nil {
		return "", err
	}
	sum := hash.Sum(nil)
	return string(sum), nil
}

//CopyFile ...
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

//GetChinaDomainDNS ...
func GetChinaDomainDNS(dst string) ([]string, error) {
	domains := make([]string, 0)
	file, err := os.Open(dst)
	if err != nil {
		return nil, err

	}
	defer file.Close()
	reader := bufio.NewReader(file)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		domains = append(domains, string(line))

	}
	return domains, nil

}

func main() {
	flag.Parse()
	path := filepath.Dir(*target)
	extDNSs := strings.Split(*extDNS, ",")
	chinaDomainURLs := strings.Split(*chinaDomainURL, ",")
	file, err := ioutil.TempFile(path, "china_domain")
	if err != nil {
		log.Fatal("failed to create tmpfile", err)
		return
	}
	defer os.Remove(file.Name())
	err = DownloadDomainList(chinaDomainURLs, *chinaDNS, file)
	if err != nil {
		log.Error("fail to download china domain list", err)
		return
	}
	sumNew, err := HashFile(file.Name())
	if err != nil {
		log.Error("can not hash tmp file", err)
		return
	}
	sumOld, err := HashFile(*target)
	if err != nil {
		log.Error("can not hash target file", err)
		return
	}
	if sumNew == sumOld {
		log.Info("no need to update AdguardHome")
		return
	}
	err = os.Remove(*target)
	if err != nil {
		log.Fatal("can not remove old target file", err)
		return
	}
	err = CopyFile(file.Name(), *target)
	if err != nil {
		log.Fatal("can not mv tmp file to target ", err)
		return
	}
	config, err := GetAdguardHomeDNSConfig(*adguardhomeAddr, *adguardhomeUser, *adguardhomePass)
	if err != nil {
		log.Error("faild to get adguardhome dnsconfig", err)
		return
	}
	domains, err := GetChinaDomainDNS(*target)
	if err != nil {
		log.Error("failed to get china domainlit ", err)
		return
	}
	domains = append(domains, extDNSs...)
	config.Upstreams = domains
	err = UpdateAdguardHomeDNSConfig(*adguardhomeAddr, *adguardhomeUser, *adguardhomePass, config)
	if err != nil {
		log.Error("failed to update adguardhome config ", err)
	}
}
