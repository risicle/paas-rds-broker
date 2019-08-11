package sqlengine

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"text/template"
	"time"
	"unicode"

	"github.com/lib/pq" // PostgreSQL Driver

	"code.cloudfoundry.org/lager"
)

const (
	pqErrUniqueViolation  = "23505"
	pqErrDuplicateContent = "42710"
	pqErrInternalError    = "XX000"
	pqErrInvalidPassword  = "28P01"
)

type PostgresqlPrivilege struct {
	TargetType   string    `json:"target_type"`
	TargetSchema *string   `json:"target_schema"`
	TargetName   *string   `json:"target_name"`
	Privilege    string    `json:"privilege"`
	ColumnNames  *[]string `json:"column_names"`
}

func (pp *PostgresqlPrivilege) Validate() error {
	switch strings.ToUpper(pp.TargetType) {
		case "TABLE":
			if pp.TargetName == nil || *pp.TargetName == "" {
				return fmt.Errorf("Must provide a non-empty target_name for 'TABLE' postgresql privilege target_type (%+v)", *pp)
			}

			if err := ValidatePostgresqlName(*pp.TargetName); err != nil {
				return err
			}

			if pp.TargetSchema != nil && *pp.TargetSchema != "" {
				if err := ValidatePostgresqlName(*pp.TargetSchema); err != nil {
					return err
				}
			}

			if pp.ColumnNames != nil && len(*pp.ColumnNames) != 0 {
				for _, columnName := range *pp.ColumnNames {
					if err := ValidatePostgresqlName(columnName); err != nil {
						return err
					}
				}

				switch strings.ToUpper(pp.Privilege) {
					case "SELECT":
					case "INSERT":
					case "UPDATE":
					case "REFERENCES":
					case "ALL":
					default:
						return fmt.Errorf("Unknown postgresql column privilege: %s", pp.Privilege)
				}
			} else {
				switch strings.ToUpper(pp.Privilege) {
					case "SELECT":
					case "INSERT":
					case "UPDATE":
					case "DELETE":
					case "TRUNCATE":
					case "REFERENCES":
					case "TRIGGER":
					case "ALL":
					default:
						return fmt.Errorf("Unknown postgresql table privilege: %s", pp.Privilege)
				}
			}
		case "SEQUENCE":
			if pp.TargetName == nil || *pp.TargetName == "" {
				return fmt.Errorf("Must provide a non-empty target_name for 'SEQUENCE' postgresql privilege target_type (%+v)", *pp)
			}

			if err := ValidatePostgresqlName(*pp.TargetName); err != nil {
				return err
			}

			if pp.TargetSchema != nil && *pp.TargetSchema != "" {
				if err := ValidatePostgresqlName(*pp.TargetSchema); err != nil {
					return err
				}
			}

			if pp.ColumnNames != nil {
				return fmt.Errorf("column_names makes no sense for 'SEQUENCE' postgresql privilege target_type (%+v)", *pp)
			}

			switch strings.ToUpper(pp.Privilege) {
				case "USAGE":
				case "SELECT":
				case "UPDATE":
				case "ALL":
				default:
					return fmt.Errorf("Unknown postgresql sequence privilege: %s", pp.Privilege)
			}
		case "DATABASE":
			if pp.TargetName != nil {
				return fmt.Errorf("target_name makes no sense for 'DATABASE' postgresql privilege target_type (%+v)", *pp)
			}

			if pp.TargetSchema != nil {
				return fmt.Errorf("target_schema makes no sense for 'DATABASE' postgresql privilege target_type (%+v)", *pp)
			}

			if pp.ColumnNames != nil {
				return fmt.Errorf("column_names makes no sense for 'DATABASE' postgresql privilege target_type (%+v)", *pp)
			}

			switch strings.ToUpper(pp.Privilege) {
				case "CREATE":
				case "TEMPORARY":
				case "TEMP":
				case "ALL":
				default:
					return fmt.Errorf("Unknown postgresql database privilege: %s", pp.Privilege)
			}
		case "SCHEMA":
			if pp.TargetName == nil || *pp.TargetName == "" {
				return fmt.Errorf("Must provide a non-empty target_name for 'SCHEMA' postgresql privilege target_type (%+v)", *pp)
			}

			if err := ValidatePostgresqlName(*pp.TargetName); err != nil {
				return err
			}

			if pp.TargetSchema != nil {
				return fmt.Errorf("target_schema makes no sense for 'SCHEMA' postgresql privilege target_type (try target_name instead) (%+v)", *pp)
			}

			if pp.ColumnNames != nil {
				return fmt.Errorf("column_names makes no sense for 'SCHEMA' postgresql privilege target_type (%+v)", *pp)
			}

			switch strings.ToUpper(pp.Privilege) {
				case "CREATE":
				case "USAGE":
				case "ALL":
				default:
					return fmt.Errorf("Unknown postgresql schema privilege: %s", pp.Privilege)
			}
		default:
			return fmt.Errorf("Unknown postgresql privilege target_type: %s", pp.TargetType)
	}

	return nil
}

func getQuotedIdents(schema *string, name string) (text string, parameters string[]) {
	if schema == nil || *schema == "" {
		return "quote_ident(?)", []string{name}
	}

	return "quote_ident(?) || '.' || quote_ident(?)", []string{*schema, name}
}

const privilegeStatementWrapper = `
	BEGIN
		%s
	EXCEPTION
		WHEN undefined_column OR undefined_table OR invalid_schema_name THEN
			NULL;
	END;`

func (pp *PostgresqlPrivilege) GetPlPgSQL(action string, user string) (text string, parameters []string, error) {
	switch action {
		case "GRANT":
		case "REVOKE":
		default:
			return "", []string{}, fmt.Errorf("Expected 'action' to be one of GRANT or REVOKE, not '%s'", action)
	}

	if strings.ToUpper(pp.TargetType) == "TABLE" && pp.ColumnNames != nil && len(*pp.ColumnNames) != 0 {
		columnQuoteIdents := make(string[], len(*pp.ColumnNames))
		for i := range columnQuoteIdents {
			columnQuoteIdents[i] = "quote_ident(?)"
		}

		return Sprintf(
			"EXECUTE '%s %s (' || %s || ') ON TABLE ' || %s || ' TO ' || quote_ident(?);",
			action,
			pp.Privilege,
			strings.Join(columnQuoteIdents, ", "),
			getQuotedIdents(pp.TargetSchema, pp.TargetName),
		), 
	}
}

func ValidatePostgresqlName(name string) error {
	if len(name) == 0 {
		return fmt.Errorf("Empty name")
	}

	for i := 0; i < len(name); i++ {
		if name[i] > unicode.MaxASCII {
			return fmt.Errorf("Non-ASCII characters in postgresql object names not (yet) supported: %s", name)
		}
	}

	return nil
}

type PostgresUserBindParameters struct {
	IsOwner                *bool                  `json:"is_owner"`
	DefaultPrivilegePolicy string                 `json:"default_privilege_policy"`
	RevokePrivileges       *[]PostgresqlPrivilege `json:"revoke_privileges"`
	GrantPrivileges        *[]PostgresqlPrivilege `json:"grant_privileges"`
}

func (bp *PostgresUserBindParameters) Validate() error {
	if bp.IsOwner != nil && !*bp.IsOwner {
		switch strings.ToLower(bp.DefaultPrivilegePolicy) {
			case "revoke":
				if bp.RevokePrivileges != nil {
					return fmt.Errorf("revoke_privileges makes no sense with default_privilege_policy 'revoke' (%+v)", *bp)
				}
				if bp.GrantPrivileges != nil {
					for _, privilege := range *bp.GrantPrivileges {
						if err := privilege.Validate(); err != nil {
							return err
						}
					}
				}
			case "grant":
				if bp.GrantPrivileges != nil {
					return fmt.Errorf("grant_privileges makes no sense with default_privilege_policy 'grant' (%+v)", *bp)
				}
				if bp.RevokePrivileges != nil {
					for _, privilege := range *bp.RevokePrivileges {
						if err := privilege.Validate(); err != nil {
							return err
						}
					}
				}
			default:
				return fmt.Errorf("default_privilege_policy must be one of 'grant' or 'revoke' (%+v)", *bp)
		}
	} else {
		if bp.DefaultPrivilegePolicy != "" {
			return fmt.Errorf("postgresql_user.default_privilege_policy makes no sense for owner (%+v)", *bp)
		}
		if bp.RevokePrivileges != nil {
			return fmt.Errorf("postgresql_user.revoke_privileges makes no sense for owner (%+v)", *bp)
		}
		if bp.GrantPrivileges != nil {
			return fmt.Errorf("postgresql_user.grant_privileges makes no sense for owner (%+v)", *bp)
		}
	}
	return nil
}

type PostgresEngine struct {
	logger            lager.Logger
	db                *sql.DB
	requireSSL        bool
	UsernameGenerator func(string) string
}

func NewPostgresEngine(logger lager.Logger) *PostgresEngine {
	return &PostgresEngine{
		logger:            logger.Session("postgres-engine"),
		requireSSL:        true,
		UsernameGenerator: generateUsername,
	}
}

func (d *PostgresEngine) Open(address string, port int64, dbname string, username string, password string) error {
	connectionString := d.URI(address, port, dbname, username, password)
	sanitizedConnectionString := d.URI(address, port, dbname, username, "REDACTED")
	d.logger.Debug("sql-open", lager.Data{"connection-string": sanitizedConnectionString})

	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return err
	}

	d.db = db

	// Open() may not actually open the connection so we ping to validate it
	err = d.db.Ping()
	if err != nil {
		// We specifically look for invalid password error and map it to a
		// generic error that can be the same across other engines
		// See: https://www.postgresql.org/docs/9.3/static/errcodes-appendix.html
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == pqErrInvalidPassword {
			// return &LoginFailedError{username}
			return LoginFailedError
		}
		return err
	}

	return nil
}

func (d *PostgresEngine) Close() {
	if d.db != nil {
		d.db.Close()
	}
}

const grantAllPrivilegesPattern = `
	DO
	$body$
	BEGIN
		FOR schema_name IN SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') LOOP
			EXECUTE 'GRANT ALL ON ALL TABLES IN SCHEMA ' || quote_ident(schema_name) || ' TO "{{.user}}"';
			EXECUTE 'GRANT ALL ON ALL SEQUENCES IN SCHEMA ' || quote_ident(schema_name) || ' TO "{{.user}}"';
			EXECUTE 'GRANT ALL ON ALL FUNCTIONS IN SCHEMA ' || quote_ident(schema_name) || ' TO "{{.user}}"';
			EXECUTE 'GRANT ALL ON SCHEMA ' || quote_ident(schema_name) || ' TO "{{.user}}"';
		END LOOP;

		GRANT ALL ON DATABASE "{{,dbname}}" TO "{{.user}}";

		ALTER DEFAULT PRIVILEGES GRANT ALL ON TABLES TO "{{.user}}";
		ALTER DEFAULT PRIVILEGES GRANT ALL ON SEQUENCES TO "{{.user}}";
		ALTER DEFAULT PRIVILEGES GRANT ALL ON FUNCTIONS TO "{{.user}}";
		ALTER DEFAULT PRIVILEGES GRANT ALL ON SCHEMAS TO "{{.user}}";
	END
	$body$;`

var grantAllPrivilegesTemplate = template.Must(template.New("grantAllPrivileges").Parse(grantAllPrivilegesPattern))

const grantUnhandledPrivilegesPattern = `
	DO
	$body$
	BEGIN
		FOR schema_name IN SELECT schema_name FROM information_schema.schemata WHERE schema_name NOT IN ('pg_catalog','information_schema') LOOP
			EXECUTE 'GRANT ALL ON ALL FUNCTIONS IN SCHEMA ' || quote_ident(schema_name) || ' TO "{{.user}}"';
		END LOOP;

		FOR type_schema, type_name IN SELECT user_defined_type_schema, user_defined_type_name FROM information_schema.user_defined_types LOOP
			EXECUTE 'GRANT ALL ON TYPE ' || quote_ident(type_schema) || '.' || quote_ident(type_name) || ' TO "{{.user}}';
		END LOOP;

		FOR domain_schema, domain_name IN SELECT domain_schema, domain_name FROM information_schema.domains LOOP
			EXECUTE 'GRANT ALL ON DOMAIN ' || quote_ident(domain_schema) || '.' || quote_ident(domain_name) || ' TO "{{.user}}';
		END LOOP;

		FOR lang_name IN SELECT lanname FROM pg_catalog.pg_language WHERE lanpltrusted LOOP
			EXECUTE 'GRANT ALL ON LANGUAGE ' || quote_ident(lang_name) || ' TO "{{.user}}"';
		END LOOP;

		ALTER DEFAULT PRIVILEGES GRANT ALL ON FUNCTIONS TO "{{.user}}";
		ALTER DEFAULT PRIVILEGES GRANT ALL ON TYPES TO "{{.user}}";
	END
	$body$;`

var grantUnhandledPrivilegesTemplate = template.Must(template.New("grantUnhandledPrivileges").Parse(grantUnhandledPrivilegesPattern))

func (d *PostgresEngine) execCreateUser(tx *sql.Tx, bindingID, dbname string, userBindParameters PostgresUserBindParameters) (username, password string, err error) {
	groupname := d.generatePostgresGroup(dbname)

	if err = d.ensureGroup(tx, dbname, groupname); err != nil {
		return "", "", err
	}

	if err = d.ensureTrigger(tx, groupname); err != nil {
		return "", "", err
	}

	username = d.UsernameGenerator(bindingID)
	password = generatePassword()

	if err = d.ensureUser(tx, dbname, username, password); err != nil {
		return "", "", err
	}

	if userBindParameters.IsOwner == nil || *userBindParameters.IsOwner {
		grantMembershipStatement := fmt.Sprintf(`grant "%s" to "%s"`, groupname, username)
		d.logger.Debug("grant-privileges", lager.Data{"statement": grantMembershipStatement})

		if _, err := tx.Exec(grantMembershipStatement); err != nil {
			d.logger.Error("Grant sql-error", err)
			return "", "", err
		}
	} else {
		if strings.ToLower(userBindParameters.DefaultPrivilegePolicy) != "deny" {
			// grant priviliges to all objects which can then be revoked individually
			var grantAllPrivilegesStatement bytes.Buffer
			grantAllPrivilegesTemplate.Execute(&grantAllPrivilegesStatement, map[string]string{
				"dbname": dbname,
				"user": username,
			})

			if _, err := tx.Exec(grantAllPrivilegesStatement); err != nil {
				d.logger.Error("Grant sql-error", err)
				return "", "", err
			}
		}

		// we don't implement a way to further control some types of privilege, so for these features to be at all
		// usable by a non-owner user, we need to allow all of them
		var grantUnhandledPrivilegesStatement bytes.Buffer
		grantUnhandledPrivilegesTemplate.Execute(&grantUnhandledPrivilegesStatement, map[string]string{
			"user": username,
		})

		if _, err := tx.Exec(grantUnhandledPrivilegesStatement); err != nil {
			d.logger.Error("Grant sql-error", err)
			return "", "", err
		}
	}

	grantAllOnDatabaseStatement := fmt.Sprintf(`grant all privileges on database "%s" to "%s"`, dbname, groupname)
	d.logger.Debug("grant-privileges", lager.Data{"statement": grantAllOnDatabaseStatement})

	if _, err := tx.Exec(grantAllOnDatabaseStatement); err != nil {
		d.logger.Error("Grant sql-error", err)
		return "", "", err
	}

	return username, password, nil
}

func (d *PostgresEngine) createUser(bindingID, dbname string, userBindParameters PostgresUserBindParameters) (username, password string, err error) {
	tx, err := d.db.Begin()
	if err != nil {
		d.logger.Error("sql-error", err)
		return "", "", err
	}
	username, password, err = d.execCreateUser(tx, bindingID, dbname, userBindParameters)
	if err != nil {
		_ = tx.Rollback()
		return "", "", err
	}
	return username, password, tx.Commit()
}

func (d *PostgresEngine) CreateUser(bindingID, dbname string, userBindParametersRaw *json.RawMessage) (username, password string, err error) {
	bindParameters := PostgresUserBindParameters{}
	if userBindParametersRaw != nil && len(*userBindParametersRaw) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(*userBindParametersRaw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&bindParameters); err != nil {
			return "", "", err
		}
		if err := bindParameters.Validate(); err != nil {
			return "", "", err
		}
	}

	var pqErr *pq.Error
	tries := 0
	for tries < 10 {
		tries++
		username, password, err := d.createUser(bindingID, dbname, bindParameters)
		if err != nil {
			var ok bool
			pqErr, ok = err.(*pq.Error)
			if ok && (pqErr.Code == pqErrInternalError || pqErr.Code == pqErrDuplicateContent || pqErr.Code == pqErrUniqueViolation) {
				time.Sleep(time.Duration(rand.Intn(1500)) * time.Millisecond)
				continue
			}
			return "", "", err
		}
		return username, password, nil
	}
	return "", "", pqErr

}

func (d *PostgresEngine) DropUser(bindingID string) error {
	username := d.UsernameGenerator(bindingID)
	dropUserStatement := fmt.Sprintf(`drop role "%s"`, username)

	_, err := d.db.Exec(dropUserStatement)
	if err == nil {
		return nil
	}

	// When handling unbinds for bindings created before the switch to
	// event-triggers based permissions the `username` won't exist.
	// Also we changed how we generate usernames so we have to try to drop the username generated
	// the old way. If none of the usernames exist then we swallow the error
	if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "42704" {
		d.logger.Info("warning", lager.Data{"warning": "User " + username + " does not exist"})

		username = generateUsernameOld(bindingID)
		dropUserStatement = fmt.Sprintf(`drop role "%s"`, username)
		if _, err = d.db.Exec(dropUserStatement); err != nil {
			if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "42704" {
				d.logger.Info("warning", lager.Data{"warning": "User " + username + " does not exist"})
				return nil
			}
			d.logger.Error("sql-error", err)
			return err
		}

		return nil
	}

	d.logger.Error("sql-error", err)

	return err
}

func (d *PostgresEngine) ResetState() error {
	d.logger.Debug("reset-state.start")

	tx, err := d.db.Begin()
	if err != nil {
		d.logger.Error("sql-error", err)
		return err
	}
	commitCalled := false
	defer func() {
		if !commitCalled {
			tx.Rollback()
		}
	}()

	users, err := d.listNonSuperUsers()
	if err != nil {
		return err
	}

	for _, username := range users {
		dropUserStatement := fmt.Sprintf(`drop role "%s"`, username)
		d.logger.Debug("reset-state", lager.Data{"statement": dropUserStatement})
		if _, err = tx.Exec(dropUserStatement); err != nil {
			d.logger.Error("sql-error", err)
			return err
		}
	}

	err = tx.Commit()
	if err != nil {
		d.logger.Error("commit.sql-error", err)
		return err
	}
	commitCalled = true // Prevent Rollback being called in deferred function

	d.logger.Debug("reset-state.finish")

	return nil
}

func (d *PostgresEngine) listNonSuperUsers() ([]string, error) {
	users := []string{}

	rows, err := d.db.Query("select usename from pg_user where usesuper != true and usename != current_user")
	if err != nil {
		d.logger.Error("sql-error", err)
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var username string
		err = rows.Scan(&username)
		if err != nil {
			d.logger.Error("sql-error", err)
			return nil, err
		}
		users = append(users, username)
	}
	return users, nil
}

func (d *PostgresEngine) URI(address string, port int64, dbname string, username string, password string) string {
	uri := fmt.Sprintf("postgres://%s:%s@%s:%d/%s", username, password, address, port, dbname)
	if !d.requireSSL {
		uri = uri + "?sslmode=disable"
	}
	return uri
}

func (d *PostgresEngine) JDBCURI(address string, port int64, dbname string, username string, password string) string {
	params := &url.Values{}
	params.Set("user", username)
	params.Set("password", password)

	if d.requireSSL {
		params.Set("ssl", "true")
	}
	return fmt.Sprintf("jdbc:postgresql://%s:%d/%s?%s", address, port, dbname, params.Encode())
}

const createExtensionPattern = `CREATE EXTENSION IF NOT EXISTS "{{.extension}}"`
const dropExtensionPattern = `DROP EXTENSION IF EXISTS "{{.extension}}"`

func (d *PostgresEngine) CreateExtensions(extensions []string) error {
	for _, extension := range extensions {
		createExtensionTemplate := template.Must(template.New(extension + "Extension").Parse(createExtensionPattern))
		var createExtensionStatement bytes.Buffer
		if err := createExtensionTemplate.Execute(&createExtensionStatement, map[string]string{"extension": extension}); err != nil {
			return err
		}
		if _, err := d.db.Exec(createExtensionStatement.String()); err != nil {
			return err
		}
	}
	return nil
}

func (d *PostgresEngine) DropExtensions(extensions []string) error {
	for _, extension := range extensions {
		dropExtensionTemplate := template.Must(template.New(extension + "Extension").Parse(dropExtensionPattern))
		var dropExtensionStatement bytes.Buffer
		if err := dropExtensionTemplate.Execute(&dropExtensionStatement, map[string]string{"extension": extension}); err != nil {
			return err
		}
		if _, err := d.db.Exec(dropExtensionStatement.String()); err != nil {
			return err
		}
	}
	return nil
}

// generatePostgresGroup produces a deterministic group name. This is because the role
// will be persisted across all application bindings
func (d *PostgresEngine) generatePostgresGroup(dbname string) string {
	return dbname + "_manager"
}

const ensureGroupPattern = `
	do
	$body$
	begin
		IF NOT EXISTS (select 1 from pg_catalog.pg_roles where rolname = '{{.role}}') THEN
			CREATE ROLE "{{.role}}";
		END IF;
	end
	$body$
	`

var ensureGroupTemplate = template.Must(template.New("ensureGroup").Parse(ensureGroupPattern))

func (d *PostgresEngine) ensureGroup(tx *sql.Tx, dbname, groupname string) error {
	var ensureGroupStatement bytes.Buffer
	if err := ensureGroupTemplate.Execute(&ensureGroupStatement, map[string]string{
		"role": groupname,
	}); err != nil {
		return err
	}
	d.logger.Debug("ensure-group", lager.Data{"statement": ensureGroupStatement.String()})

	if _, err := tx.Exec(ensureGroupStatement.String()); err != nil {
		d.logger.Error("sql-error", err)
		return err
	}

	return nil
}

const ensureTriggerPattern = `
	create or replace function reassign_owned() returns event_trigger language plpgsql as $$
	begin
		-- do not execute if member of rds_superuser
		IF EXISTS (select 1 from pg_catalog.pg_roles where rolname = 'rds_superuser')
		AND pg_has_role(current_user, 'rds_superuser', 'member') THEN
			RETURN;
		END IF;

		-- do not execute if not member of manager role
		IF NOT pg_has_role(current_user, '{{.role}}', 'member') THEN
			RETURN;
		END IF;

		-- do not execute if superuser
		IF EXISTS (SELECT 1 FROM pg_user WHERE usename = current_user and usesuper = true) THEN
			RETURN;
		END IF;

		EXECUTE 'reassign owned by "' || current_user || '" to "{{.role}}"';
	end
	$$;
	`

var ensureTriggerTemplate = template.Must(template.New("ensureTrigger").Parse(ensureTriggerPattern))

func (d *PostgresEngine) ensureTrigger(tx *sql.Tx, groupname string) error {
	var ensureTriggerStatement bytes.Buffer
	if err := ensureTriggerTemplate.Execute(&ensureTriggerStatement, map[string]string{
		"role": groupname,
	}); err != nil {
		return err
	}

	cmds := []string{
		ensureTriggerStatement.String(),
		`drop event trigger if exists reassign_owned;`,
		`create event trigger reassign_owned on ddl_command_end execute procedure reassign_owned();`,
	}

	for _, cmd := range cmds {
		d.logger.Debug("ensure-trigger", lager.Data{"statement": cmd})
		_, err := tx.Exec(cmd)
		if err != nil {
			d.logger.Error("sql-error", err)
			return err
		}
	}

	return nil
}

const ensureCreateUserPattern = `
	DO
	$body$
	BEGIN
	   IF NOT EXISTS (
		  SELECT *
		  FROM   pg_catalog.pg_user
		  WHERE  usename = '{{.user}}') THEN

		  CREATE USER {{.user}} WITH PASSWORD '{{.password}}';
	   END IF;
	END
	$body$;`

var ensureCreateUserTemplate = template.Must(template.New("ensureUser").Parse(ensureCreateUserPattern))

func (d *PostgresEngine) ensureUser(tx *sql.Tx, dbname string, username string, password string) error {
	var ensureUserStatement bytes.Buffer
	if err := ensureCreateUserTemplate.Execute(&ensureUserStatement, map[string]string{
		"password": password,
		"user":     username,
	}); err != nil {
		return err
	}
	var ensureUserStatementSanitized bytes.Buffer
	if err := ensureCreateUserTemplate.Execute(&ensureUserStatementSanitized, map[string]string{
		"password": "REDACTED",
		"user":     username,
	}); err != nil {
		return err
	}
	d.logger.Debug("ensure-user", lager.Data{"statement": ensureUserStatementSanitized.String()})

	if _, err := tx.Exec(ensureUserStatement.String()); err != nil {
		d.logger.Error("sql-error", err)
		return err
	}

	return nil
}
