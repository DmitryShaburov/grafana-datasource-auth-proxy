package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Configuration
type Config struct {
	Acl map[string][]string `yaml:"acl"`
}

func LoadConfig(configFile string) (*Config, error) {
	yamlReader, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()

	conf := &Config{}
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)
	if err = decoder.Decode(conf); err != nil {
		return nil, fmt.Errorf("error parsing config file: %s", err)
	}

	return conf, nil
}

// Grafana
type GrafanaDB struct {
	db     *sql.DB
	secret *string
}

func NewGrafanaDB(secret, database, user, pass, host *string) (*GrafanaDB, error) {
	db, err := sql.Open("mysql", fmt.Sprintf("%v:%v@tcp(%v)/%v", *user, *pass, *host, *database))
	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return &GrafanaDB{
		db:     db,
		secret: secret,
	}, nil
}

func (g *GrafanaDB) GetUserTeams(session string) ([]string, error) {
	var team string
	var teams []string

	query := `SELECT name
			  FROM team
			  INNER JOIN team_member
			 	ON team_member.team_id = team.id
			  INNER JOIN user_auth_token
				ON user_auth_token.user_id = team_member.user_id
			  WHERE user_auth_token.auth_token = ?;`
	rows, err := g.db.Query(query, g.HashToken(session))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		if err = rows.Scan(&team); err != nil {
			return nil, err
		}
		teams = append(teams, team)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	return teams, nil
}

func (g *GrafanaDB) GetDatasourceByID(id int) (string, error) {
	var name string

	query := `SELECT name FROM data_source WHERE id = ?`
	row := g.db.QueryRow(query, id)
	if err := row.Scan(&name); err != nil {
		return "", err
	}
	return name, nil
}

func (g *GrafanaDB) HashToken(token string) string {
	hashBytes := sha256.Sum256([]byte(token + *g.secret))
	return hex.EncodeToString(hashBytes[:])
}

func (g *GrafanaDB) Close() {
	g.db.Close()
}

// Helper functions
func LookupEnvOrString(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func GetDatasourceID(path string) (int, error) {
	s := strings.Split(path, "/")
	for i := 0; i < len(s); i++ {
		if s[i] == "proxy" && s[i-1] == "datasources" {
			return strconv.Atoi(s[i+1])
		}
	}
	return 0, errors.New("path does not contains datasource id")
}

func IsAuthenticated(r *http.Request, g *GrafanaDB, c *Config) bool {
	if !strings.Contains(r.URL.Path, "api/datasources/proxy") {
		log.WithFields(log.Fields{"path": r.URL.Path, "remote_addr": r.RemoteAddr}).
			Warn("non-proxy request")
		return false
	}

	cookie, err := r.Cookie("grafana_session")
	if err != nil {
		log.WithFields(log.Fields{"path": r.URL.Path, "remote_addr": r.RemoteAddr, "err": err}).
			Warn("request without authentication cookie")
		return false
	}

	teams, err := g.GetUserTeams(cookie.Value)
	if err != nil {
		log.WithFields(log.Fields{"path": r.URL.Path, "remote_addr": r.RemoteAddr, "err": err}).
			Warn("cannot get user teams")
		return false
	}

	id, err := GetDatasourceID(r.URL.Path)
	if err != nil {
		log.WithFields(log.Fields{"path": r.URL.Path, "remote_addr": r.RemoteAddr, "err": err}).
			Warn("cannot get datasource ID")
		return false
	}

	datasource, err := g.GetDatasourceByID(id)
	if err != nil {
		log.WithFields(log.Fields{"path": r.URL.Path, "remote_addr": r.RemoteAddr, "err": err}).
			Warn("cannot get datasource name")
		return false
	}

	if acl, ok := c.Acl[datasource]; ok {
		for _, a := range acl {
			for _, t := range teams {
				if a == t {
					return true
				}
			}
		}
	}

	return false
}

// Main
func main() {
	var (
		configFile        = flag.String("config", LookupEnvOrString("CONFIG_FILE", "/etc/grafana-datasource-auth-proxy/config.yaml"), "Path to configuration file")
		listenAddress     = flag.String("listen-address", LookupEnvOrString("LISTEN_ADDRESS", ":3000"), "The address to listen on for HTTP requests")
		grafanaOriginHost = flag.String("grafana-url", LookupEnvOrString("GF_SERVER_DOMAIN", "grafana"), "Grafana remote origin host")
		grafanaSecret     = flag.String("grafana-secret", LookupEnvOrString("GF_SECURITY_SECRET_KEY", "SW2YcwTIb9zpOOhoPsMm"), "Grafana encryption secret")
		dbDatabase        = flag.String("db-database", LookupEnvOrString("GF_DATABASE_NAME", "grafana"), "Grafana database name")
		dbHost            = flag.String("db-host", LookupEnvOrString("GF_DATABASE_HOST", "127.0.0.1:3306"), "Grafana database host and port")
		dbUser            = flag.String("db-user", LookupEnvOrString("GF_DATABASE_USER", ""), "Grafana database user")
		dbPass            = flag.String("db-pass", LookupEnvOrString("GF_DATABASE_PASSWORD", ""), "Grafana database password")
		logFormat         = flag.String("log-format", LookupEnvOrString("LOG_FORMAT", "txt"), "Log format, valid options are txt and json")
		logLevel          = flag.String("log-level", LookupEnvOrString("LOG_LEVEL", "info"), "Log level, valid options are trace, debug, info, warn, error, fatal and panic")
	)
	flag.Parse()

	switch *logFormat {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	default:
		log.SetFormatter(&log.TextFormatter{})
	}

	level, err := log.ParseLevel(*logLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(level)

	log.Info("loading configuration")
	config, err := LoadConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}

	proxy := &httputil.ReverseProxy{Director: func(req *http.Request) {
		originHost := *grafanaOriginHost

		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Origin-Host", originHost)
		req.Host = originHost
		req.URL.Scheme = "http"
		req.URL.Host = originHost
	}}

	log.Info("building Grafana DB connection")
	gf, err := NewGrafanaDB(grafanaSecret, dbDatabase, dbUser, dbPass, dbHost)
	if err != nil {
		log.Fatal(err)
	}
	defer gf.Close()

	http.HandleFunc("/", handler(proxy, gf, config))
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`OK`))
	})

	log.Info("listening on address " + *listenAddress)
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func handler(p *httputil.ReverseProxy, g *GrafanaDB, c *Config) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if IsAuthenticated(r, g, c) {
			log.WithFields(log.Fields{"path": r.URL.Path, "remote_addr": r.RemoteAddr}).
				Debug("OK")
			p.ServeHTTP(w, r)
		} else {
			log.WithFields(log.Fields{"path": r.URL.Path, "remote_addr": r.RemoteAddr}).
				Debug("Unauthorized")
			http.Error(w, "Not authorized", http.StatusUnauthorized)
		}
	}
}
