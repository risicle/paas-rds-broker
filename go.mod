module github.com/alphagov/paas-rds-broker

go 1.18

require (
	code.cloudfoundry.org/lager v2.0.0+incompatible
	github.com/Masterminds/semver v1.5.0
	github.com/aws/aws-sdk-go v1.42.50
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-sql-driver/mysql v1.6.0
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/lib/pq v1.10.4
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.19.0
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/phayes/freeport v0.0.0-20220201140144-74d24b5ae9f5
	github.com/pkg/errors v0.9.1 // indirect
	github.com/robfig/cron v1.2.0
	github.com/satori/go.uuid v1.2.0
	golang.org/x/net v0.0.0-20220225172249-27dd8689420f // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20220315194320-039c03cc5b86 // indirect
	golang.org/x/text v0.3.7 // indirect
)

require github.com/pivotal-cf/brokerapi/v8 v8.2.2

require (
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/rogpeppe/go-internal v1.8.1 // indirect
	google.golang.org/protobuf v1.27.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)
